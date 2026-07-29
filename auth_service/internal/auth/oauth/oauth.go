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
	"auth_service/internal/lib/sl"
	"auth_service/internal/models"
	"auth_service/internal/storage"
)

var (
	ErrOAuthStateInvalid      = errors.New("invalid or expired oauth state")
	ErrOAuthEmailNotVerified  = errors.New("email not verified by provider")
	ErrOAuthProviderNotFound  = errors.New("unknown oauth provider")
	ErrOAuthAccountConflict   = errors.New("account with this email already exists, log in and link instead")
	ErrOAuthLastAuthMethod    = errors.New("cannot unlink last authentication method")
	ErrAccountPendingDeletion = errors.New("account with this email is pending deletion")
)

// Provider — внешний клиент конкретного провайдера (Google/GitHub).
type Provider interface {
	AuthURL(state string) string
	Exchange(ctx context.Context, code string) (*Token, error)
	FetchUser(ctx context.Context, token *Token) (*User, error)
}

type Token struct {
	AccessToken string
}

type User struct {
	ProviderUserID string
	Email          string
	EmailVerified  bool
}

type AccountRepo interface {
	SaveOAuthAccount(ctx context.Context, userID int64, provider, providerUserID, email string) error
	OAuthAccountByProviderUserID(ctx context.Context, provider, providerUserID string) (*models.OAuthAccount, error)
	OAuthAccountsByUserID(ctx context.Context, userID int64) ([]*models.OAuthAccount, error)
	UnlinkOAuthAccount(ctx context.Context, userID int64, provider string) error
	SaveOAuthUser(ctx context.Context, email, username, provider, providerUserID string) (int64, error)
}

// StateStore — доступ к state-токенам в Redis.
type StateStore interface {
	SaveOAuthState(ctx context.Context, state string, payload StatePayload, ttl time.Duration) error
	GetAndDeleteOAuthState(ctx context.Context, state string) (*StatePayload, error)
}

type StatePayload struct {
	RedirectURI string `json:"redirect_uri"`
	UserID      int64  `json:"user_id,omitempty"`
	AppID       int32  `json:"app_id"`
}

type OAuthService struct {
	auth *auth.Auth

	log *slog.Logger

	accountRepo AccountRepo
	stateStore  StateStore
	providers   map[string]Provider

	stateTTL time.Duration
}

func New(
	base *auth.Auth,
	log *slog.Logger,
	accountRepo AccountRepo,
	stateStore StateStore,
	providers map[string]Provider,
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

	payload := StatePayload{
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

	// GETDEL — до любых внешних вызовов. Защищает от replay и двойного клика.
	payload, err := s.stateStore.GetAndDeleteOAuthState(ctx, state)
	if err != nil {
		if errors.Is(err, storage.ErrOAuthStateNotFound) {
			return "", "", ErrOAuthStateInvalid
		}
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	oauthUser, err := exchangeAndFetch(ctx, p, code, log, op)
	if err != nil {
		return "", "", err
	}
	if !oauthUser.EmailVerified {
		return "", "", ErrOAuthEmailNotVerified
	}

	app, err := s.auth.AppProvider.App(ctx, payload.AppID)
	if err != nil {
		return "", "", fmt.Errorf("%s: load app: %w", op, err)
	}

	if payload.UserID != 0 {
		return s.linkOAuthAccount(ctx, payload.UserID, providerName, oauthUser, app, op)
	}
	return s.loginOrRegisterOAuthUser(ctx, providerName, oauthUser, app, op)
}

// * Unlink отвязывает provider от юзера.
func (s *OAuthService) Unlink(ctx context.Context, userID int64, providerName string) error {
	const op = "OAuthService.Unlink"

	if err := s.accountRepo.UnlinkOAuthAccount(ctx, userID, providerName); err != nil {
		if errors.Is(err, storage.ErrOAuthLastAuthMethod) {
			return fmt.Errorf("%s: %w", op, storage.ErrOAuthLastAuthMethod)
		}
		if errors.Is(err, storage.ErrOAuthAccountNotFound) {
			return fmt.Errorf("%s: %w", op, storage.ErrOAuthAccountNotFound)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// ListAccounts — привязанные провайдеры юзера, для профиля/настроек.
func (s *OAuthService) ListAccounts(ctx context.Context, userID int64) ([]*models.OAuthAccount, error) {
	const op = "OAuthService.ListAccounts"

	account, err := s.accountRepo.OAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return account, nil
}

// Linking flow: юзер уже залогинен, привязываем provider к его аккаунту.
func (s *OAuthService) linkOAuthAccount(
	ctx context.Context, userID int64, providerName string, oauthUser User, app *models.App, op string,
) (accessToken, refreshToken string, err error) {
	if err = s.accountRepo.SaveOAuthAccount(ctx, userID, providerName, oauthUser.ProviderUserID, oauthUser.Email); err != nil {
		return "", "", fmt.Errorf("%s: link account: %w", op, err)
	}

	user, err := s.auth.UsrProvider.UserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: load linked user: %w", op, err)
	}
	if user.DeletedAt != nil {
		return "", "", ErrAccountPendingDeletion
	}

	accessToken, refreshToken, err = s.auth.IssueTokens(ctx, user, app)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

func (s *OAuthService) loginOrRegisterOAuthUser(
	ctx context.Context, providerName string, oauthUser User, app *models.App, op string,
) (accessToken, refreshToken string, err error) {
	existing, err := s.accountRepo.OAuthAccountByProviderUserID(ctx, providerName, oauthUser.ProviderUserID)
	switch {
	case err == nil:
		return s.issueForExistingUser(ctx, existing.UserID, app, op)

	case errors.Is(err, storage.ErrOAuthAccountNotFound):
		return s.resolveByEmailOrCreate(ctx, providerName, oauthUser, app, op)

	default:
		return "", "", fmt.Errorf("%s: lookup oauth account: %w", op, err)
	}
}

func (s *OAuthService) issueForExistingUser(
	ctx context.Context, userID int64, app *models.App, op string,
) (accessToken, refreshToken string, err error) {
	user, err := s.auth.UsrProvider.UserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: load user: %w", op, err)
	}

	if user.DeletedAt != nil {
		return "", "", ErrAccountPendingDeletion
	}

	accessToken, refreshToken, err = s.auth.IssueTokens(ctx, user, app)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

// Нет oauth-связки по этому provider'у. Проверяем, не занят ли email локальным аккаунтом —
// если да, это конфликт (нужен явный linking flow, а не тихая привязка).
func (s *OAuthService) resolveByEmailOrCreate(
	ctx context.Context, providerName string, oauthUser User, app *models.App, op string,
) (accessToken, refreshToken string, err error) {
	existingUser, err := s.auth.UsrProvider.UserByEmail(ctx, oauthUser.Email)
	switch {
	case err == nil:
		if existingUser.DeletedAt != nil {
			return "", "", ErrAccountPendingDeletion
		}
		return "", "", ErrOAuthAccountConflict

	case errors.Is(err, storage.ErrUserNotFound):
		return s.createOAuthUser(ctx, providerName, oauthUser, app, op)

	default:
		return "", "", fmt.Errorf("%s: check existing user: %w", op, err)
	}
}

func (s *OAuthService) createOAuthUser(
	ctx context.Context, providerName string, oauthUser User, app *models.App, op string,
) (accessToken, refreshToken string, err error) {
	username := deriveUsername(oauthUser.Email)

	userID, err := s.accountRepo.SaveOAuthUser(ctx, oauthUser.Email, username, providerName, oauthUser.ProviderUserID)
	if err != nil {
		return "", "", fmt.Errorf("%s: create oauth user: %w", op, err)
	}

	user, err := s.auth.UsrProvider.UserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: load new user: %w", op, err)
	}

	accessToken, refreshToken, err = s.auth.IssueTokens(ctx, user, app)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return accessToken, refreshToken, nil
}

func exchangeAndFetch(
	ctx context.Context, p Provider, code string, log *slog.Logger, op string,
) (User, error) {
	exCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	token, err := p.Exchange(exCtx, code)
	if err != nil {
		log.Error("provider exchange failed", sl.Err(err))
		return User{}, fmt.Errorf("%s: exchange: %w", op, err)
	}

	oauthUser, err := p.FetchUser(exCtx, token)
	if err != nil {
		log.Error("provider fetch user failed", sl.Err(err))
		return User{}, fmt.Errorf("%s: fetch user: %w", op, err)
	}

	return *oauthUser, nil
}

func generateState() (string, error) {
	const op = "OAuthService.generateState"

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *OAuthService) provider(name string) (Provider, error) {
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
