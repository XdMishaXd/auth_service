package jwt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"auth_service/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrTokenExpired = errors.New("token expired")
	ErrAppNotFound  = errors.New("app not found")
)

type AppSecretProvider interface {
	AppSecret(ctx context.Context, appID int32) (string, error)
}

type Claims struct {
	UserID   int64
	Username string
	Email    string
	AppID    int32
}

func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["username"] = user.Username
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ParseAndVerify достаёт app_id из непроверенного токена, получает секрет
// приложения и валидирует подпись этим секретом.
func ParseAndVerify(ctx context.Context, tokenString string, apps AppSecretProvider) (*Claims, error) {
	appID, err := unverifiedAppID(tokenString)
	if err != nil {
		return nil, err
	}

	secret, err := apps.AppSecret(ctx, appID)
	if err != nil {
		return nil, ErrAppNotFound
	}

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	return extractClaims(claims)
}

func unverifiedAppID(tokenString string) (int32, error) {
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return 0, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return 0, ErrInvalidToken
	}

	appIDFloat, ok := claims["app_id"].(float64)
	if !ok {
		return 0, ErrInvalidToken
	}

	return int32(appIDFloat), nil
}

func extractClaims(claims jwt.MapClaims) (*Claims, error) {
	uidFloat, ok := claims["uid"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}

	username, _ := claims["username"].(string)
	email, _ := claims["email"].(string)

	appIDFloat, ok := claims["app_id"].(float64)
	if !ok {
		return nil, ErrInvalidToken
	}

	return &Claims{
		UserID:   int64(uidFloat),
		Username: username,
		Email:    email,
		AppID:    int32(appIDFloat),
	}, nil
}
