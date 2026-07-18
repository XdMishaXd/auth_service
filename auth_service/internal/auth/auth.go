package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"auth_service/internal/lib/jwt"
	"auth_service/internal/lib/tokens"
	"auth_service/internal/lib/verification"
	"auth_service/internal/models"
	"auth_service/internal/storage"

	sl "auth_service/internal/lib/logger"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	_ "auth_service/docs"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidAppID       = errors.New("invalid app id")

	ErrEmailNotVerified = errors.New("email not verified")

	ErrResetTokenExpired = errors.New("reset token expired")
	ErrResetTokenUsed    = errors.New("reset token already used")

	ErrSamePassword = errors.New("new password is the same as the old one")

	ErrNoAuthFactorAvailable = errors.New("no password or linked oauth account to enable 2fa")
	ErrTwoFAAlreadyEnabled   = errors.New("2fa already enabled")
	ErrTwoFANotEnabled       = errors.New("2fa is not enabled")
	ErrDisableConfirmation   = errors.New("invalid confirmation")
)

type Auth struct {
	Log         *slog.Logger
	UsrSaver    UserSaver
	UsrProvider UserProvider
	AppProvider AppProvider
	TwoFA       TwoFAService

	tokenTTL   time.Duration
	refreshTTL time.Duration
	resetTTL   time.Duration
}

type LoginResult struct {
	AccessToken      string
	RefreshToken     string
	TwoFactorPending bool
	SessionID        string
}

type UserSaver interface {
	SaveUser(ctx context.Context, email string, username string, passHash []byte) (uid int64, err error)

	SaveRefreshToken(ctx context.Context, id string, userID int64, appID int32, tokenHash []byte, expiresAt time.Time) error
	UpdateRefreshToken(ctx context.Context, id uuid.UUID, newTokenHash []byte, oldTokenHash []byte, expiresAt time.Time) error
	DeleteRefreshToken(ctx context.Context, id uuid.UUID) error

	SaveResetToken(ctx context.Context, tokenID uuid.UUID, userID int64, tokenHash []byte, expiresAt time.Time) error
	DeleteAllResetTokens(ctx context.Context, uid int64) error
}

type UserProvider interface {
	User(ctx context.Context, email string) (*models.User, error)
	UserByID(ctx context.Context, id int64) (*models.User, error)
	UserByEmail(ctx context.Context, email string) (int64, error)

	RefreshTokenByID(ctx context.Context, id uuid.UUID) (*models.RefreshToken, error)

	ResetTokenByID(ctx context.Context, tokenID uuid.UUID) (*models.ResetToken, error)
	ResetPassword(ctx context.Context, userID int64, tokenID uuid.UUID, newPasswordHash []byte) error

	SetEmailVerified(ctx context.Context, uid int64) error
	CheckIfUserVerified(ctx context.Context, email string) (int64, bool, error)

	TwoFAStatus(ctx context.Context, userID int64) (*models.TwoFAStatus, error)
	EnableMagicLink2FA(ctx context.Context, userID int64) error
	DisableMagicLink2FA(ctx context.Context, userID int64) error

	HasOAuthAccounts(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int32) (*models.App, error)
}

type TwoFAService interface {
	RequestChallenge(ctx context.Context, user *models.User, appID int32, pendingSessionTTL time.Duration) (sessionID string, err error)
	RequestActionConfirmation(
		ctx context.Context,
		userID int64,
		appID int32,
		pendingSessionTTL time.Duration,
	) (string, error)

	Resend(ctx context.Context, sessionID string) error

	VerifyLogin(ctx context.Context, sessionID, rawToken string) (userID int64, appID int32, err error)
	VerifyForAction(ctx context.Context, sessionID, rawToken string, expectedUserID int64) error
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	twoFAService TwoFAService,
	jwtTTL, refreshTTL, resetTTL time.Duration,
) *Auth {
	return &Auth{
		UsrSaver:    userSaver,
		UsrProvider: userProvider,
		AppProvider: appProvider,
		TwoFA:       twoFAService,
		Log:         log,
		tokenTTL:    jwtTTL,
		refreshTTL:  refreshTTL,
		resetTTL:    resetTTL,
	}
}

// * Login проверяет учетные данные и возвращает JWT и refresh token
func (a *Auth) Login(
	ctx context.Context,
	email, password string,
	appID int32,
	pendingSessionTTL time.Duration,
) (*LoginResult, error) {
	const op = "Auth.Login"

	log := a.Log.With(slog.String("op", op))

	user, err := a.UsrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found")
			return nil, storage.ErrUserNotFound
		}

		log.Error("failed to get user", sl.Err(err))
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))
		return nil, ErrInvalidCredentials
	}

	if !user.IsVerified {
		return nil, ErrEmailNotVerified
	}

	app, err := a.AppProvider.App(ctx, appID)
	if err != nil {
		return nil, ErrInvalidAppID
	}

	status, err := a.UsrProvider.TwoFAStatus(ctx, user.ID)
	if err != nil {
		log.Error("failed to get 2fa status", sl.Err(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	if status.IsEnabled {
		sessionID, err := a.TwoFA.RequestChallenge(ctx, user, app.ID, pendingSessionTTL)
		if err != nil {
			log.Error("failed to request 2fa challenge", sl.Err(err))
			return nil, fmt.Errorf("%s: %w", op, err)
		}

		return &LoginResult{TwoFactorPending: true, SessionID: sessionID}, nil
	}

	accessToken, refreshToken, err := a.IssueTokens(ctx, user, app)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	return &LoginResult{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	username string,
	pass string,
) (int64, error) {
	const op = "auth.registerNewUser"

	log := a.Log.With(
		slog.String("op", op),
	)

	log.Info("Registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.UsrSaver.SaveUser(ctx, email, username, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("User already exists")

			return 0, storage.ErrUserAlreadyExists
		}

		log.Error("Failed to save user", sl.Err(err))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	return id, nil
}

func (a *Auth) CheckUserVerification(
	ctx context.Context,
	email string,
) (int64, bool, error) {
	const op = "auth.CheckUserVerification"

	log := a.Log.With(
		slog.String("op", op),
	)

	userID, isVerified, err := a.UsrProvider.CheckIfUserVerified(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return 0, false, storage.ErrUserNotFound
		}

		log.Info("failed to check user", sl.Err(err))

		return 0, false, err
	}

	return userID, isVerified, nil
}

func (a *Auth) Refresh(
	ctx context.Context,
	refreshToken string,
) (string, string, error) {
	const op = "auth.refresh"

	log := a.Log.With(
		slog.String("op", op),
	)

	parts := strings.Split(refreshToken, ".")
	if len(parts) != 2 {
		log.Warn("invalid refresh token format")
		return "", "", ErrInvalidCredentials
	}

	tokenID := parts[0]
	secret := parts[1]

	uid, err := uuid.Parse(tokenID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	rt, err := a.UsrProvider.RefreshTokenByID(ctx, uid)
	if err != nil {
		log.Warn("refresh token not found", sl.Err(err))
		return "", "", ErrInvalidCredentials
	}

	if time.Now().After(rt.ExpiresAt) {
		log.Warn("refresh token expired")
		return "", "", ErrInvalidCredentials
	}
	if !tokens.VerifyOpaqueToken(secret, rt.TokenHash) {
		log.Warn("invalid refresh token")
		return "", "", ErrInvalidCredentials
	}

	user, err := a.UsrProvider.UserByID(ctx, rt.UserID)
	if err != nil {
		log.Error("failed to load user", sl.Err(err))
		return "", "", ErrInvalidCredentials
	}

	app, err := a.AppProvider.App(ctx, rt.AppID)
	if err != nil {
		return "", "", ErrInvalidAppID
	}

	accessToken, err := jwt.NewToken(*user, *app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate access token", sl.Err(err))
		return "", "", err
	}

	_, newRefreshToken, newHash, err := tokens.NewRefreshToken(tokenID)
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", err
	}

	err = a.UsrSaver.UpdateRefreshToken(
		ctx,
		rt.ID,
		newHash,
		rt.TokenHash,
		time.Now().Add(a.refreshTTL),
	)
	if err != nil {
		log.Error("failed to update refresh token", sl.Err(err))
		return "", "", err
	}

	return accessToken, newRefreshToken, nil
}

func (a *Auth) VerifyUser(
	ctx context.Context,
	verificationToken string,
	verificationTokenSecret string,
) error {
	const op = "auth.VerifyUser"

	log := a.Log.With(
		slog.String("op", op),
	)

	user_id, err := verification.ParseVerificationToken(verificationToken, verificationTokenSecret)
	if err != nil {
		log.Error("failed to update parse verification token", sl.Err(err))

		return err
	}

	if err = a.UsrProvider.SetEmailVerified(ctx, user_id); err != nil {
		log.Error("failed to update update status in database", sl.Err(err))

		return err
	}

	return nil
}

func (a *Auth) Logout(
	ctx context.Context,
	rawRefreshToken string,
) error {
	const op = "auth.logout"

	parts := strings.Split(rawRefreshToken, ".")
	if len(parts) != 2 {
		return ErrInvalidCredentials
	}

	tokenID := parts[0]
	secret := parts[1]

	uid, err := uuid.Parse(tokenID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	rt, err := a.UsrProvider.RefreshTokenByID(ctx, uid)
	if err != nil {
		return ErrInvalidCredentials
	}

	if !tokens.VerifyOpaqueToken(secret, rt.TokenHash) {
		return ErrInvalidCredentials
	}

	err = a.UsrSaver.DeleteRefreshToken(ctx, rt.ID)
	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) Forgot(ctx context.Context, email string) (string, error) {
	const op = "auth.ForgotPass"

	log := a.Log.With(
		slog.String("op", op),
	)

	uid, err := a.UsrProvider.UserByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	err = a.UsrSaver.DeleteAllResetTokens(ctx, uid)
	if err != nil {
		log.Error("Failed to delete reset tokens", sl.Err(err))

		return "", err
	}

	tokenID, resetToken, hash, err := tokens.NewResetToken("")
	if err != nil {
		log.Error("Failed to generate reset token", sl.Err(err))

		return "", err
	}

	err = a.UsrSaver.SaveResetToken(
		ctx,
		uuid.MustParse(tokenID),
		uid,
		hash,
		time.Now().Add(a.resetTTL),
	)
	if err != nil {
		log.Error("Failed to save reset token", sl.Err(err))
		return "", err
	}

	return resetToken, nil
}

func (a *Auth) ResetPassword(ctx context.Context, tokenID, verifier, newPass string) error {
	const op = "auth.ResetPassword"

	uid, err := uuid.Parse(tokenID)
	if err != nil {
		return fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	rt, err := a.UsrProvider.ResetTokenByID(ctx, uid)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if time.Now().After(rt.ExpiresAt) {
		return ErrResetTokenExpired
	}
	if rt.UsedAt != nil {
		return ErrResetTokenUsed
	}
	if !tokens.VerifyOpaqueToken(verifier, rt.TokenHash) {
		return ErrInvalidCredentials
	}

	user, err := a.UsrProvider.UserByID(ctx, rt.UserID)
	if err != nil {
		return fmt.Errorf("%s: get user: %w", op, err)
	}

	if bcrypt.CompareHashAndPassword(user.PassHash, []byte(newPass)) == nil {
		return ErrSamePassword
	}

	passHash, err := bcrypt.GenerateFromPassword([]byte(newPass), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := a.UsrProvider.ResetPassword(ctx, rt.UserID, rt.ID, passHash); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// * VerifyMagicLink подтверждает второй фактор и выдаёт токены.
func (a *Auth) VerifyMagicLink(ctx context.Context, sessionID, rawToken string) (accessToken, refreshToken string, err error) {
	const op = "Auth.VerifyMagicLink"

	userID, appID, err := a.TwoFA.VerifyLogin(ctx, sessionID, rawToken)
	if err != nil {
		return "", "", err
	}

	user, err := a.UsrProvider.UserByID(ctx, userID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	app, err := a.AppProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", op, err)
	}

	return a.IssueTokens(ctx, user, app)
}

// * Enable2FA включает magic-link 2FA пользователю. Требует, чтобы у него уже
// был рабочий фактор для будущего disable (пароль или хотя бы один
// oauth-аккаунт) — иначе включение необратимо заблокирует доступ к аккаунту.
func (a *Auth) Enable2FA(ctx context.Context, userID int64) error {
	const op = "Auth.Enable2FA"

	log := a.Log.With(slog.String("op", op))

	status, err := a.UsrProvider.TwoFAStatus(ctx, userID)
	if err != nil {
		log.Error("failed to get 2fa status", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if status.IsEnabled {
		return ErrTwoFAAlreadyEnabled
	}

	if !status.HasPassword {
		hasOAuth, err := a.UsrProvider.HasOAuthAccounts(ctx, userID)
		if err != nil {
			log.Error("failed to check oauth accounts", sl.Err(err))
			return fmt.Errorf("%s: %w", op, err)
		}

		if !hasOAuth {
			return ErrNoAuthFactorAvailable
		}
	}

	if err := a.UsrProvider.EnableMagicLink2FA(ctx, userID); err != nil {
		log.Error("failed to enable 2fa", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("2fa enabled", slog.Int64("user_id", userID))

	return nil
}

func (a *Auth) Disable2FA(
	ctx context.Context,
	userID int64,
	password string,
	sessionID, rawToken string,
) error {
	const op = "Auth.Disable2FA"

	log := a.Log.With(slog.String("op", op))

	status, err := a.UsrProvider.TwoFAStatus(ctx, userID)
	if err != nil {
		log.Error("failed to get 2fa status", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if !status.IsEnabled {
		return ErrTwoFANotEnabled
	}

	switch {
	case status.HasPassword:
		user, err := a.UsrProvider.UserByID(ctx, userID)
		if err != nil {
			log.Error("failed to get user", sl.Err(err))
			return fmt.Errorf("%s: %w", op, err)
		}

		if bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)) != nil {
			log.Warn("disable 2fa: invalid password")
			return ErrDisableConfirmation
		}

	default:
		if sessionID == "" || rawToken == "" {
			return ErrDisableConfirmation
		}

		if err := a.TwoFA.VerifyForAction(ctx, sessionID, rawToken, userID); err != nil {
			log.Warn("disable 2fa: invalid magic link confirmation", sl.Err(err))
			return ErrDisableConfirmation
		}
	}

	if err := a.UsrProvider.DisableMagicLink2FA(ctx, userID); err != nil {
		log.Error("failed to disable 2fa", sl.Err(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("2fa disabled", slog.Int64("user_id", userID))

	return nil
}

// * IssueTokens генерирует access и refresh токены и сохраняет refresh в БД.
func (a *Auth) IssueTokens(ctx context.Context, user *models.User, app *models.App) (accessToken, refreshToken string, err error) {
	accessToken, err = jwt.NewToken(*user, *app, a.tokenTTL)
	if err != nil {
		a.Log.Error("failed to generate access token", sl.Err(err))
		return "", "", err
	}

	tokenID, refreshToken, hash, err := tokens.NewRefreshToken("")
	if err != nil {
		a.Log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", err
	}

	if err := a.UsrSaver.SaveRefreshToken(ctx, tokenID, user.ID, app.ID, hash, time.Now().Add(a.refreshTTL)); err != nil {
		a.Log.Error("failed to save refresh token", sl.Err(err))
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
