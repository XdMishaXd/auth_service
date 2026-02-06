package twoFactorAuth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"auth_service/internal/config"
	"auth_service/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

type Publisher interface {
	SendMessage(ctx context.Context, msg models.Message) error
}

type PostgresRepo interface {
	CreateMagicLink(ctx context.Context, link *models.MagicLink) error
	GetMagicLinkByTokenHash(ctx context.Context, tokenHash string) (*models.MagicLink, error)
	MarkMagicLinkAsUsed(ctx context.Context, id int64) error
	GetActiveMagicLinksByUserID(ctx context.Context, userID int64) ([]*models.MagicLink, error)
	InvalidateMagicLinksByUserID(ctx context.Context, userID int64) (int64, error)
	CleanupExpiredMagicLinks(ctx context.Context) (int, error)
}

type RedisRepo interface {
	MarkMagicLinkAsUsed(ctx context.Context, tokenHash string, ttl time.Duration) (bool, error)
	IsMagicLinkUsed(ctx context.Context, tokenHash string) (bool, error)
	SetMagicLinkPending(ctx context.Context, tokenHash string, userID int64, appID int32, ttl time.Duration) error
	DeleteMagicLinkPending(ctx context.Context, tokenHash string) error
	InvalidateMagicLinksByHashes(ctx context.Context, tokenHashes []string, ttl time.Duration) error
}

type TwoFactorAuthentificator struct {
	pg          PostgresRepo
	redis       RedisRepo
	publisher   Publisher
	log         *slog.Logger
	tokenSecret string
	tokenTTL    time.Duration
	redirectURL string
}

type tokenClaims struct {
	UserID    int64
	AppID     int32
	SessionID string
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
		tokenSecret: cfg.TwoFactorAuth.TokenSecret,
		tokenTTL:    cfg.TwoFactorAuth.TokenTTL,
		redirectURL: cfg.TwoFactorAuth.RedirectURL,
	}
}

// * SendMagicLink генерирует и отправляет magic link на email
func (s *TwoFactorAuthentificator) SendMagicLink(ctx context.Context, req *models.SendMagicLinkRequest) error {
	const op = "twoFactorAuth.Service.SendMagicLink"

	token, sessionID, err := s.generateToken(req.UserID, req.AppID)
	if err != nil {
		s.log.Error("failed to generate token", slog.String("op", op), slog.Any("err", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	tokenHash := s.hashToken(token)
	expiresAt := time.Now().Add(s.tokenTTL)

	magicLink := &models.MagicLink{
		UserID:    req.UserID,
		AppID:     req.AppID,
		TokenHash: tokenHash,
		SessionID: sessionID,
		IPAddress: req.IPAddress,
		UserAgent: req.UserAgent,
		ExpiresAt: expiresAt,
	}

	if err := s.pg.CreateMagicLink(ctx, magicLink); err != nil {
		s.log.Error("failed to save to postgres", slog.String("op", op), slog.Any("err", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.redis.SetMagicLinkPending(ctx, tokenHash, req.UserID, req.AppID, s.tokenTTL); err != nil {
		s.log.Warn("failed to save to redis", slog.String("op", op), slog.Any("err", err))
	}

	magicLinkURL := fmt.Sprintf("%s/auth/2fa/verify-link?token=%s", s.redirectURL, token)

	msg := models.Message{
		Email:   req.Email,
		Link:    magicLinkURL,
		Purpose: "2fa",
	}

	if err := s.publisher.SendMessage(ctx, msg); err != nil {
		s.log.Error("failed to send email", slog.String("op", op), slog.Any("err", err))
		return fmt.Errorf("%s: %w", op, err)
	}

	s.log.Info("magic link sent",
		slog.Int64("user_id", req.UserID),
		slog.Int("app_id", int(req.AppID)),
		slog.String("session_id", sessionID),
	)

	return nil
}

// * parseToken парсит и валидирует JWT токен
func (s *TwoFactorAuthentificator) ParseToken(tokenStr string) (*tokenClaims, error) {
	claims := jwt.MapClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.tokenSecret), nil
	})
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	purpose, ok := claims["purpose"].(string)
	if !ok || purpose != "2fa" {
		return nil, fmt.Errorf("invalid token purpose")
	}

	userID, ok := claims["sub"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing user_id")
	}

	appID, ok := claims["app_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing app_id")
	}

	sessionID, ok := claims["session_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing session_id")
	}

	return &tokenClaims{
		UserID:    int64(userID),
		AppID:     int32(appID),
		SessionID: sessionID,
	}, nil
}

// * CleanupExpired очищает истекшие magic links (вызывать через cron)
func (s *TwoFactorAuthentificator) CleanupExpired(ctx context.Context) (int, error) {
	const op = "twoFactorAuth.Service.CleanupExpired"

	deleted, err := s.pg.CleanupExpiredMagicLinks(ctx)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	s.log.Info("cleanup completed", slog.Int("deleted", deleted))

	return deleted, nil
}

// * generateToken генерирует JWT токен для magic link
func (s *TwoFactorAuthentificator) generateToken(userID int64, appID int32) (string, string, error) {
	sessionID := fmt.Sprintf("sess_%d_%d", time.Now().UnixNano(), userID)

	claims := jwt.MapClaims{
		"sub":        userID,
		"app_id":     appID,
		"session_id": sessionID,
		"purpose":    "2fa",
		"iat":        time.Now().Unix(),
		"exp":        time.Now().Add(s.tokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.tokenSecret))
	if err != nil {
		return "", "", err
	}

	return signedToken, sessionID, nil
}

// * hashToken создает SHA256 хеш токена
func (s *TwoFactorAuthentificator) hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
