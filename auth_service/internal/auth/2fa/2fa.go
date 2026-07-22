package twoFactorAuth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/config"
	"auth_service/internal/models"
	"auth_service/internal/storage"
)

var (
	ErrMagicLinkVerificationFailed = errors.New("lagic link verification failed")
	ErrActionMismatch              = errors.New("action mismatch")
)

type Publisher interface {
	SendMessage(ctx context.Context, msg models.Message) error
}

type PostgresRepo interface {
	UserByID(ctx context.Context, id int64) (*models.User, error)

	SaveMagicLink(ctx context.Context, link *models.MagicLink) error
	ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*models.MagicLink, error)
	InvalidateMagicLinksByUserID(ctx context.Context, userID int64) (int64, error)
	CleanupExpiredMagicLinks(ctx context.Context) (int, error)
}

type RedisRepo interface {
	SetPendingSession(ctx context.Context, sessionID string, session models.PendingSession, ttl time.Duration) error
	GetPendingSession(ctx context.Context, sessionID string) (*models.PendingSession, error)
	DeletePendingSession(ctx context.Context, sessionID string) error
}

type TwoFactorAuthentificator struct {
	pg          PostgresRepo
	redis       RedisRepo
	publisher   Publisher
	log         *slog.Logger
	tokenTTL    time.Duration
	redirectURL string
}

func New(
	pg PostgresRepo,
	redis RedisRepo,
	publisher Publisher,
	log *slog.Logger,
	cfg *config.Config,
) *TwoFactorAuthentificator {
	return &TwoFactorAuthentificator{
		pg:          pg,
		redis:       redis,
		publisher:   publisher,
		log:         log,
		tokenTTL:    cfg.TwoFactorAuth.TokenTTL,
		redirectURL: cfg.TwoFactorAuth.RedirectURL,
	}
}

// * SendMagicLink генерирует токен и ставит письмо в очередь на отправку.
func (s *TwoFactorAuthentificator) SendMagicLink(ctx context.Context, req *models.SendMagicLinkRequest, sessionID string) error {
	const op = "twoFactorAuth.Service.SendMagicLink"

	selector, verifier, err := generateSelectorVerifier()
	if err != nil {
		return fmt.Errorf("%s: generate token: %w", op, err)
	}

	verifierHash := hashVerifier(verifier)
	expiresAt := time.Now().Add(s.tokenTTL)

	magicLink := &models.MagicLink{
		UserID:    req.UserID,
		AppID:     req.AppID,
		TokenHash: verifierHash,
		SessionID: sessionID,
		ExpiresAt: expiresAt,
	}

	if err := s.pg.SaveMagicLink(ctx, magicLink); err != nil {
		return fmt.Errorf("%s: save: %w", op, err)
	}

	rawToken := selector + "." + verifier
	magicLinkURL := fmt.Sprintf("/auth/2fa/magic-link/verify#token=%s", rawToken)

	msg := models.Message{
		Email:   req.Email,
		Link:    magicLinkURL,
		Purpose: "2fa",
	}

	if err := s.publisher.SendMessage(ctx, msg); err != nil {
		return fmt.Errorf("%s: enqueue message: %w", op, err)
	}

	s.log.Info("magic link issued",
		slog.Int64("user_id", req.UserID),
		slog.Int("app_id", int(req.AppID)),
		slog.String("session_id", sessionID),
	)

	return nil
}

// * VerifyLogin проверяет токен в рамках логина и завершает pending-сессию.
func (s *TwoFactorAuthentificator) VerifyLogin(
	ctx context.Context,
	sessionID, rawToken string,
) (userID int64, appID int32, err error) {
	const op = "twoFactorAuth.Service.VerifyLogin"

	link, err := s.verifyToken(ctx, sessionID, rawToken, models.ActionLogin2FA)
	if err != nil {
		if errors.Is(err, ErrMagicLinkVerificationFailed) || errors.Is(err, storage.ErrMagicLinkNotFound) {
			return 0, 0, err
		}

		return 0, 0, fmt.Errorf("%s: %w", op, err)
	}

	if err := s.redis.DeletePendingSession(ctx, sessionID); err != nil {
		s.log.Warn("failed to delete pending session", slog.String("op", op), slog.Any("err", err))
	}

	return link.UserID, link.AppID, nil
}

// * RequestChallenge инициирует 2FA-челлендж после успешной проверки пароля на этапе логина.
func (s *TwoFactorAuthentificator) RequestChallenge(
	ctx context.Context,
	user *models.User,
	appID int32,
	pendingSessionTTL time.Duration,
) (string, error) {
	const op = "twoFactorAuth.Service.RequestChallenge"

	sessionID, err := s.issueMagicLink(ctx, user, appID, models.ActionLogin2FA, pendingSessionTTL)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return sessionID, nil
}

// * VerifyForAction проверяет действующий magic-link код как подтверждение
// чувствительного действия (например, disable 2FA для oauth-only
// пользователя без пароля).
func (s *TwoFactorAuthentificator) VerifyForAction(
	ctx context.Context,
	sessionID, rawToken string,
	expectedUserID int64,
	expectedAction models.Action,
) error {
	const op = "twoFactorAuth.Service.VerifyForAction"

	link, err := s.verifyToken(ctx, sessionID, rawToken, expectedAction)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if link.UserID != expectedUserID {
		return fmt.Errorf("%s: user mismatch", op)
	}

	if err := s.redis.DeletePendingSession(ctx, sessionID); err != nil {
		s.log.Warn("failed to delete pending session", slog.String("op", op), slog.Any("err", err))
	}

	return nil
}

func (s *TwoFactorAuthentificator) CleanupExpired(ctx context.Context) (int, error) {
	const op = "twoFactorAuth.Service.CleanupExpired"

	deleted, err := s.pg.CleanupExpiredMagicLinks(ctx)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	s.log.Info("cleanup completed", slog.Int("deleted", deleted))

	return deleted, nil
}

func generateSelectorVerifier() (selector, verifier string, err error) {
	selBytes := make([]byte, 16)
	if _, err = rand.Read(selBytes); err != nil {
		return "", "", err
	}

	verBytes := make([]byte, 32)
	if _, err = rand.Read(verBytes); err != nil {
		return "", "", err
	}

	return base64.RawURLEncoding.EncodeToString(selBytes),
		base64.RawURLEncoding.EncodeToString(verBytes),
		nil
}

// * RequestActionConfirmation отправляет magic-link код уже залогиненному
// пользователю для подтверждения чувствительного действия (например, disable
// 2FA у oauth-only пользователя без пароля).
func (s *TwoFactorAuthentificator) RequestActionConfirmation(
	ctx context.Context,
	userID int64,
	appID int32,
	action models.Action,
	pendingSessionTTL time.Duration,
) (string, error) {
	const op = "twoFactorAuth.Service.RequestActionConfirmation"

	user, err := s.pg.UserByID(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("%s: get user: %w", op, err)
	}

	sessionID, err := s.issueMagicLink(ctx, user, appID, action, pendingSessionTTL)
	if err != nil {
		s.log.Error("failed to issue action confirmation",
			slog.String("op", op),
			slog.Any("err", err),
		)

		return "", fmt.Errorf("%s: %w", op, err)
	}

	return sessionID, nil
}

// * Resend инвалидирует предыдущую активную ссылку и высылает новую в рамках той же pending-сессии.
func (s *TwoFactorAuthentificator) Resend(ctx context.Context, sessionID string) error {
	const op = "twoFactorAuth.Service.Resend"

	pending, err := s.redis.GetPendingSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("%s: pending session: %w", op, err)
	}

	if _, err := s.pg.InvalidateMagicLinksByUserID(ctx, pending.UserID); err != nil {
		return fmt.Errorf("%s: invalidate previous: %w", op, err)
	}

	user, err := s.pg.UserByID(ctx, pending.UserID)
	if err != nil {
		return fmt.Errorf("%s: get user: %w", op, err)
	}

	req := &models.SendMagicLinkRequest{
		UserID: pending.UserID,
		AppID:  pending.AppID,
		Email:  user.Email,
	}

	if err := s.SendMagicLink(ctx, req, sessionID); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * issueMagicLink — общее ядро для запроса magic-link кода.
func (s *TwoFactorAuthentificator) issueMagicLink(
	ctx context.Context,
	user *models.User,
	appID int32,
	action models.Action,
	pendingSessionTTL time.Duration,
) (sessionID string, err error) {
	sessionID, err = generateSessionID()
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}

	session := models.PendingSession{
		UserID: user.ID,
		AppID:  appID,
		Action: action,
	}

	if err := s.redis.SetPendingSession(ctx, sessionID, session, pendingSessionTTL); err != nil {
		return "", fmt.Errorf("set pending session: %w", err)
	}

	req := &models.SendMagicLinkRequest{
		UserID: user.ID,
		AppID:  appID,
		Email:  user.Email,
	}

	if err := s.SendMagicLink(ctx, req, sessionID); err != nil {
		return "", fmt.Errorf("send magic link: %w", err)
	}

	return sessionID, nil
}

// * verifyToken — общее ядро проверки magic-link токена.
func (s *TwoFactorAuthentificator) verifyToken(
	ctx context.Context,
	sessionID, rawToken string,
	expectedAction models.Action,
) (*models.MagicLink, error) {
	const op = "twoFactorAuth.Service.verifyToken"

	pending, err := s.redis.GetPendingSession(ctx, sessionID)
	if err != nil {
		if errors.Is(err, storage.ErrPendingSessionNotFound) {
			return nil, fmt.Errorf("%s: %w", op, storage.ErrPendingSessionNotFound)
		}

		return nil, fmt.Errorf("%s: pending session: %w", op, err)
	}

	if pending.Action != expectedAction {
		// Токен не трогаем — это не проблема токена, это неверный контекст запроса.
		return nil, fmt.Errorf("%s: %w", op, ErrActionMismatch)
	}

	_, verifier, ok := splitToken(rawToken)
	if !ok {
		return nil, fmt.Errorf("%s: malformed token: %w", op, ErrMagicLinkVerificationFailed)
	}

	verifierHash := hashVerifier(verifier)

	link, err := s.pg.ConsumeMagicLink(ctx, verifierHash)
	if err != nil {
		if errors.Is(err, storage.ErrMagicLinkNotFound) {
			return nil, fmt.Errorf("%s: %w", op, ErrMagicLinkVerificationFailed)
		}

		return nil, fmt.Errorf("%s: consume: %w", op, err)
	}

	if link.SessionID != sessionID {
		return nil, fmt.Errorf("%s: session mismatch: %w", op, ErrMagicLinkVerificationFailed)
	}
	if link.UserID != pending.UserID || link.AppID != pending.AppID {
		return nil, fmt.Errorf("%s: pending session mismatch: %w", op, ErrMagicLinkVerificationFailed)
	}

	return link, nil
}

func splitToken(raw string) (selector, verifier string, ok bool) {
	for i := 0; i < len(raw); i++ {
		if raw[i] == '.' {
			return raw[:i], raw[i+1:], true
		}
	}
	return "", "", false
}

func hashVerifier(verifier string) []byte {
	h := sha256.Sum256([]byte(verifier))
	return h[:]
}

// func parseIPAddress(raw string) *net.IPAddr {
// 	if raw == "" {
// 		return nil
// 	}
// 	ip := net.ParseIP(raw)
// 	if ip == nil {
// 		return nil
// 	}
// 	return &net.IPAddr{IP: ip}
// }

func generateSessionID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generateSessionID: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
