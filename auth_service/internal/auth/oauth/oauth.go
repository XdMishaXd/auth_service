package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/auth"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"
	"auth_service/internal/storage"
)

var (
	ErrOAuthStateInvalid     = errors.New("invalid or expired oauth state")
	ErrOAuthEmailNotVerified = errors.New("email not verified by provider")
	ErrOAuthProviderNotFound = errors.New("unknown oauth provider")
	ErrOAuthAccountConflict  = errors.New("account with this email already exists, log in and link instead")
	ErrOAuthLastAuthMethod   = errors.New("cannot unlink last authentication method")
)

// OAuthProvider — внешний клиент конкретного провайдера (Google/GitHub).
type OAuthProvider interface {
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*OAuthToken, error)
	FetchUser(ctx context.Context, token *OAuthToken) (*OAuthUser, error)
}

type OAuthToken struct {
	AccessToken string
}

type OAuthUser struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

type OAuthAccountRepo interface {
	SaveOAuthAccount(ctx context.Context, userID int64, provider, providerUserID, email string) error
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error)
	OAuthAccountsByUserID(ctx context.Context, userID int64) ([]*models.OAuthAccount, error)
	UnlinkOAuthAccount(ctx context.Context, userID int64, provider string) error
	SaveOAuthUser(ctx context.Context, email, username, provider, providerUserID string) (int64, error)
}

// OAuthStateStore — доступ к state-токенам в Redis.
type OAuthStateStore interface {
	SaveOAuthState(ctx context.Context, state string, payload OAuthStatePayload, ttl time.Duration) error
	GetAndDeleteOAuthState(ctx context.Context, state string) (*OAuthStatePayload, error)
}

type OAuthStatePayload struct {
	RedirectURI string `json:"redirect_uri"`
	UserID      int64  `json:"user_id,omitempty"`
	AppID       int32  `json:"app_id"`
}

type OAuthService struct {
	auth *auth.Auth

	log *slog.Logger

	accountRepo OAuthAccountRepo
	stateStore  OAuthStateStore
	providers   map[string]OAuthProvider

	stateTTL time.Duration
}

func New(
	base *auth.Auth,
	log *slog.Logger,
	accountRepo OAuthAccountRepo,
	stateStore OAuthStateStore,
	providers map[string]OAuthProvider,
	stateTTL time.Duration,
) *OAuthService {
	return &OAuthService{
		auth:        base,
		log:         log,
		accountRepo: accountRepo,
		stateStore:  stateStore,
		providers:   providers,
		stateTTL:    stateTTL,
	}
}

// StartLogin генерирует state и возвращает URL для редиректа юзера на provider.
// userID = 0 для обычного login/register, != 0 для linking-флоу.
func (s *OAuthService) StartLogin(
	ctx context.Context,
	providerName string,
	appID int32,
	redirectURI string,
	userID int64,
) (string, error) {
	const op = "OAuthService.StartLogin"

	p, err := s.provider(providerName)
	if err != nil {
		return "", err
	}

	state, err := generateState()
	if err != nil {
		return "", fmt.Errorf("%s: generate state: %w", op, err)
	}

	payload := OAuthStatePayload{
		RedirectURI: redirectURI,
		UserID:      userID,
		AppID:       appID,
	}

	if err := s.stateStore.SaveOAuthState(ctx, state, payload, s.stateTTL); err != nil {
		return "", fmt.Errorf("%s: save state: %w", op, err)
	}

	return p.AuthURL(state), nil
}

// Callback обрабатывает возврат от provider: логин существующего юзера,
// создание нового, либо привязку к текущему (если payload.UserID != 0).
func (s *OAuthService) Callback(
	ctx context.Context,
	providerName string,
	code string,
	state string,
) (accessToken, refreshToken string, err error) {
	const op = "OAuthService.Callback"

	log := s.log.With(slog.String("op", op))

	p, err := s.provider(providerName)
	if err != nil {
		return "", "", err
	}

	// GETDEL — до любых внешних вызовов. Защищает от replay и двойного клика
	// независимо от того, что случится дальше в этой функции.
	payload, err := s.stateStore.GetAndDeleteOAuthState(ctx, state)
	if err != nil {
		if errors.Is(err, storage.ErrOAuthStateNotFound) {
			return "", "", ErrOAuthStateInvalid
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	exCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	token, err := p.Exchange(exCtx, code)
	if err != nil {
		log.Error("provider exchange failed", sl.Err(err))
		return "", "", fmt.Errorf("%s: exchange: %w", op, err)
	}

	oauthUser, err := p.FetchUser(exCtx, token)
	if err != nil {
		log.Error("provider fetch user failed", sl.Err(err))
		return "", "", fmt.Errorf("%s: fetch user: %w", op, err)
	}

	if !oauthUser.EmailVerified {
		return "", "", ErrOAuthEmailNotVerified
	}

	app, err := s.auth.AppProvider.App(ctx, payload.AppID)
	if err != nil {
		return "", "", auth.ErrInvalidAppID
	}

	// Linking flow: юзер уже залогинен, привязываем provider к его аккаунту.
	if payload.UserID != 0 {
		if err := s.accountRepo.SaveOAuthAccount(ctx, payload.UserID, providerName, oauthUser.ProviderUserID, oauthUser.Email); err != nil {
			return "", "", fmt.Errorf("%s: link account: %w", op, err)
		}

		user, err := s.auth.UsrProvider.UserByID(ctx, payload.UserID)
		if err != nil {
			return "", "", fmt.Errorf("%s: load linked user: %w", op, err)
		}

		return s.auth.IssueTokens(ctx, user, app)
	}

	// Обычный login/register.
	existing, err := s.accountRepo.OAuthAccountByProviderUserID(ctx, providerName, oauthUser.ProviderUserID)
	switch {
	case err == nil:
		user, err := s.auth.UsrProvider.UserByID(ctx, existing.UserID)
		if err != nil {
			return "", "", fmt.Errorf("%s: load user: %w", op, err)
		}
		return s.auth.IssueTokens(ctx, user, app)

	case errors.Is(err, storage.ErrOAuthAccountNotFound):
		// Провайдерского аккаунта нет — проверяем, не занят ли email локально
		// или другим провайдером, прежде чем создавать нового юзера.
		if _, err := s.auth.UsrProvider.User(ctx, oauthUser.Email); err == nil {
			return "", "", ErrOAuthAccountConflict
		} else if !errors.Is(err, storage.ErrUserNotFound) {
			return "", "", fmt.Errorf("%s: check existing user: %w", op, err)
		}

		username := deriveUsername(oauthUser.Email)

		userID, err := s.accountRepo.SaveOAuthUser(ctx, oauthUser.Email, username, providerName, oauthUser.ProviderUserID)
		if err != nil {
			return "", "", fmt.Errorf("%s: create oauth user: %w", op, err)
		}

		user, err := s.auth.UsrProvider.UserByID(ctx, userID)
		if err != nil {
			return "", "", fmt.Errorf("%s: load new user: %w", op, err)
		}

		return s.auth.IssueTokens(ctx, user, app)

	default:
		return "", "", fmt.Errorf("%s: lookup oauth account: %w", op, err)
	}
}

// * Unlink отвязывает provider от юзера.
func (s *OAuthService) Unlink(ctx context.Context, userID int64, providerName string) error {
	const op = "OAuthService.Unlink"

	if err := s.accountRepo.UnlinkOAuthAccount(ctx, userID, providerName); err != nil {
		if errors.Is(err, storage.ErrOAuthLastAuthMethod) {
			return ErrOAuthLastAuthMethod
		}
		if errors.Is(err, storage.ErrOAuthAccountNotFound) {
			return err
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// ListAccounts — привязанные провайдеры юзера, для профиля/настроек.
func (s *OAuthService) ListAccounts(ctx context.Context, userID int64) ([]*models.OAuthAccount, error) {
	return s.accountRepo.OAuthAccountsByUserID(ctx, userID)
}

func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *OAuthService) provider(name string) (OAuthProvider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, ErrOAuthProviderNotFound
	}
	return p, nil
}

// deriveUsername — временный username из email-локали.
func deriveUsername(email string) string {
	for i, c := range email {
		if c == '@' {
			return email[:i]
		}
	}
	return email
}
