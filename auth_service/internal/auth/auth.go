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
	ErrEmailNotVerified   = errors.New("email not verified")
	ErrResetTokenExpired  = errors.New("reset token expired")
	ErrResetTokenUsed     = errors.New("reset token already used")
	ErrSamePassword       = errors.New("new password is the same as the old one")
)

type Auth struct {
	log         *slog.Logger
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL    time.Duration
	refreshTTL  time.Duration
	resetTTL    time.Duration
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
}

type AppProvider interface {
	App(ctx context.Context, appID int32) (*models.App, error)
}

func New(
	log *slog.Logger,
	userSaver UserSaver,
	userProvider UserProvider,
	appProvider AppProvider,
	jwtTTL, refreshTTL, resetTTL time.Duration,
) *Auth {
	return &Auth{
		usrSaver:    userSaver,
		usrProvider: userProvider,
		appProvider: appProvider,
		log:         log,
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
) (accessToken string, refreshToken string, err error) {
	const op = "Auth.Login"

	log := a.log.With(slog.String("op", op))

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			log.Warn("user not found")
			return "", "", storage.ErrUserNotFound
		}

		log.Error("failed to get user", sl.Err(err))
		return "", "", err
	}

	if !user.IsVerified {
		return "", "", ErrEmailNotVerified
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		log.Info("invalid credentials", sl.Err(err))
		return "", "", ErrInvalidCredentials
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", ErrInvalidAppID
	}

	accessToken, err = jwt.NewToken(*user, *app, a.tokenTTL)
	if err != nil {
		log.Error("failed to generate access token", sl.Err(err))
		return "", "", err
	}

	tokenID, refreshToken, hash, err := tokens.NewRefreshToken("")
	if err != nil {
		log.Error("failed to generate refresh token", sl.Err(err))
		return "", "", err
	}

	err = a.usrSaver.SaveRefreshToken(
		ctx,
		tokenID,
		user.ID,
		appID,
		hash,
		time.Now().Add(a.refreshTTL),
	)
	if err != nil {
		log.Error("failed to save refresh token", sl.Err(err))
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (a *Auth) RegisterNewUser(
	ctx context.Context,
	email string,
	username string,
	pass string,
) (int64, error) {
	const op = "auth.registerNewUser"

	log := a.log.With(
		slog.String("op", op),
	)

	log.Info("Registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, username, passHash)
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

	log := a.log.With(
		slog.String("op", op),
	)

	userID, isVerified, err := a.usrProvider.CheckIfUserVerified(ctx, email)
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

	log := a.log.With(
		slog.String("op", op),
	)

	parts := strings.Split(refreshToken, ".")
	if len(parts) != 2 {
		log.Warn("invalid refresh token format")
		return "", "", ErrInvalidCredentials
	}

	tokenID := parts[0]
	secret := parts[1]

	rt, err := a.usrProvider.RefreshTokenByID(ctx, uuid.MustParse(tokenID))
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

	user, err := a.usrProvider.UserByID(ctx, rt.UserID)
	if err != nil {
		log.Error("failed to load user", sl.Err(err))
		return "", "", ErrInvalidCredentials
	}

	app, err := a.appProvider.App(ctx, rt.AppID)
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

	err = a.usrSaver.UpdateRefreshToken(
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

	log := a.log.With(
		slog.String("op", op),
	)

	user_id, err := verification.ParseVerificationToken(verificationToken, verificationTokenSecret)
	if err != nil {
		log.Error("failed to update parse verification token", sl.Err(err))

		return err
	}

	if err = a.usrProvider.SetEmailVerified(ctx, user_id); err != nil {
		log.Error("failed to update update status in database", sl.Err(err))

		return err
	}

	return nil
}

func (a *Auth) Logout(
	ctx context.Context,
	rawRefreshToken string,
) error {
	parts := strings.Split(rawRefreshToken, ".")
	if len(parts) != 2 {
		return ErrInvalidCredentials
	}

	tokenID := parts[0]
	secret := parts[1]

	rt, err := a.usrProvider.RefreshTokenByID(ctx, uuid.MustParse(tokenID))
	if err != nil {
		return ErrInvalidCredentials
	}

	if !tokens.VerifyOpaqueToken(secret, rt.TokenHash) {
		return ErrInvalidCredentials
	}

	err = a.usrSaver.DeleteRefreshToken(ctx, rt.ID)
	if err != nil {
		return err
	}

	return nil
}

func (a *Auth) Forgot(ctx context.Context, email string) (string, error) {
	const op = "auth.ForgotPass"

	log := a.log.With(
		slog.String("op", op),
	)

	uid, err := a.usrProvider.UserByEmail(ctx, email)
	if err != nil {
		return "", err
	}

	err = a.usrSaver.DeleteAllResetTokens(ctx, uid)
	if err != nil {
		log.Error("Failed to delete reset tokens", sl.Err(err))

		return "", err
	}

	tokenID, resetToken, hash, err := tokens.NewResetToken("")
	if err != nil {
		log.Error("Failed to generate reset token", sl.Err(err))

		return "", err
	}

	err = a.usrSaver.SaveResetToken(
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

	rt, err := a.usrProvider.ResetTokenByID(ctx, uid)
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

	user, err := a.usrProvider.UserByID(ctx, rt.UserID)
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

	if err := a.usrProvider.ResetPassword(ctx, rt.UserID, rt.ID, passHash); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}
