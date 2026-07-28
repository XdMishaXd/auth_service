package twoFactorAuth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"auth_service/internal/models"
	"auth_service/internal/storage"
)

type mockPostgresRepo struct {
	userByIDFunc    func(ctx context.Context, id int64) (*models.User, error)
	consumeLinkFunc func(ctx context.Context, tokenHash []byte) (*models.MagicLink, error)
	saveLinkFunc    func(ctx context.Context, link *models.MagicLink) error
	invalidateFunc  func(ctx context.Context, userID int64) (int64, error)
	cleanupFunc     func(ctx context.Context) (int, error)
}

func (m *mockPostgresRepo) UserByID(ctx context.Context, id int64) (*models.User, error) {
	return m.userByIDFunc(ctx, id)
}

func (m *mockPostgresRepo) SaveMagicLink(ctx context.Context, link *models.MagicLink) error {
	return m.saveLinkFunc(ctx, link)
}

func (m *mockPostgresRepo) ConsumeMagicLink(ctx context.Context, tokenHash []byte) (*models.MagicLink, error) {
	return m.consumeLinkFunc(ctx, tokenHash)
}

func (m *mockPostgresRepo) InvalidateMagicLinksByUserID(ctx context.Context, userID int64) (int64, error) {
	return m.invalidateFunc(ctx, userID)
}

func (m *mockPostgresRepo) CleanupExpiredMagicLinks(ctx context.Context) (int, error) {
	return m.cleanupFunc(ctx)
}

type mockRedisRepo struct {
	getPendingFunc    func(ctx context.Context, sessionID string) (*models.PendingSession, error)
	setPendingFunc    func(ctx context.Context, sessionID string, session models.PendingSession, ttl time.Duration) error
	deletePendingFunc func(ctx context.Context, sessionID string) error
}

func (m *mockRedisRepo) GetPendingSession(ctx context.Context, sessionID string) (*models.PendingSession, error) {
	return m.getPendingFunc(ctx, sessionID)
}

func (m *mockRedisRepo) SetPendingSession(ctx context.Context, sessionID string, session models.PendingSession, ttl time.Duration) error {
	return m.setPendingFunc(ctx, sessionID, session, ttl)
}

func (m *mockRedisRepo) DeletePendingSession(ctx context.Context, sessionID string) error {
	return m.deletePendingFunc(ctx, sessionID)
}

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestVerifyLogin(t *testing.T) {
	const sessionID = "test-session-id"
	rawToken := "selector123.verifierABC"
	verifierHash := hashVerifier("verifierABC")

	tests := []struct {
		name       string
		pending    *models.PendingSession
		pendingErr error
		link       *models.MagicLink
		consumeErr error
		deleteErr  error
		wantErr    error
		wantUserID int64
		wantAppID  int32
	}{
		{
			name:    "успешная верификация",
			pending: &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionLogin2FA},
			link: &models.MagicLink{
				UserID:    1,
				AppID:     10,
				SessionID: sessionID,
				TokenHash: verifierHash,
			},
			wantUserID: 1,
			wantAppID:  10,
		},
		{
			name:       "pending session не найдена",
			pendingErr: storage.ErrPendingSessionNotFound,
			wantErr:    storage.ErrPendingSessionNotFound,
		},
		{
			name:    "action mismatch — сессия не под логин",
			pending: &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionDisable2FA},
			wantErr: ErrActionMismatch,
		},
		{
			name:       "magic link не найден / уже использован",
			pending:    &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionLogin2FA},
			consumeErr: storage.ErrMagicLinkNotFound,
			wantErr:    ErrMagicLinkVerificationFailed,
		},
		{
			name:    "session mismatch — токен от другой сессии",
			pending: &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionLogin2FA},
			link: &models.MagicLink{
				UserID:    1,
				AppID:     10,
				SessionID: "другая-сессия",
				TokenHash: verifierHash,
			},
			wantErr: ErrMagicLinkVerificationFailed,
		},
		{
			name:    "user/app mismatch",
			pending: &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionLogin2FA},
			link: &models.MagicLink{
				UserID:    999, // другой пользователь
				AppID:     10,
				SessionID: sessionID,
				TokenHash: verifierHash,
			},
			wantErr: ErrMagicLinkVerificationFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pg := &mockPostgresRepo{
				consumeLinkFunc: func(ctx context.Context, tokenHash []byte) (*models.MagicLink, error) {
					if tt.consumeErr != nil {
						return nil, tt.consumeErr
					}
					return tt.link, nil
				},
			}
			redis := &mockRedisRepo{
				getPendingFunc: func(ctx context.Context, sessionID string) (*models.PendingSession, error) {
					if tt.pendingErr != nil {
						return nil, tt.pendingErr
					}
					return tt.pending, nil
				},
				deletePendingFunc: func(ctx context.Context, sessionID string) error {
					return tt.deleteErr
				},
			}

			s := &TwoFactorAuthentificator{
				pg:    pg,
				redis: redis,
				log:   noopLogger(),
			}

			userID, appID, err := s.VerifyLogin(context.Background(), sessionID, rawToken)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("хочу ошибку %v, получил %v", tt.wantErr, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			if userID != tt.wantUserID {
				t.Errorf("userID: хочу %d, получил %d", tt.wantUserID, userID)
			}
			if appID != tt.wantAppID {
				t.Errorf("appID: хочу %d, получил %d", tt.wantAppID, appID)
			}
		})
	}
}

func TestVerifyLogin_MalformedToken(t *testing.T) {
	pg := &mockPostgresRepo{}
	redis := &mockRedisRepo{
		getPendingFunc: func(ctx context.Context, sessionID string) (*models.PendingSession, error) {
			return &models.PendingSession{UserID: 1, AppID: 10, Action: models.ActionLogin2FA}, nil
		},
	}

	s := &TwoFactorAuthentificator{pg: pg, redis: redis, log: noopLogger()}

	_, _, err := s.VerifyLogin(context.Background(), "session", "token-без-точки")
	if !errors.Is(err, ErrMagicLinkVerificationFailed) {
		t.Fatalf("хочу ErrMagicLinkVerificationFailed, получил %v", err)
	}
}
