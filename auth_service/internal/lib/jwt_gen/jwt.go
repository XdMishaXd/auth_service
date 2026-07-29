package jwtgen

import (
	"context"
	"errors"
	"fmt"
	"strconv"
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

// NewToken генерирует jwt
func NewToken(user models.User, app models.App, duration time.Duration) (string, error) {
	claims := jwt.MapClaims{
		"uid":      user.ID,
		"username": user.Username,
		"email":    user.Email,
		"exp":      time.Now().Add(duration).Unix(),
		"app_id":   app.ID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to generate jwt: %w", err)
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

	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
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
	var uidInt int64
	switch v := claims["uid"].(type) {
	case float64:
		uidInt = int64(v)
	case int64:
		uidInt = v
	case string:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, ErrInvalidToken
		}
		uidInt = n
	default:
		return nil, ErrInvalidToken
	}

	username, ok := claims["username"].(string)
	if !ok {
		username = ""
	}

	email, ok := claims["email"].(string)
	if !ok {
		email = ""
	}

	var appIDInt int32
	switch v := claims["app_id"].(type) {
	case float64:
		appIDInt = int32(v)
	case int64:
		if v < -(1<<31) || v > (1<<31)-1 {
			return nil, ErrInvalidToken
		}
		appIDInt = int32(v)
	case string:
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, ErrInvalidToken
		}
		appIDInt = int32(n)
	default:
		return nil, ErrInvalidToken
	}

	return &Claims{
		UserID:   uidInt,
		Username: username,
		Email:    email,
		AppID:    appIDInt,
	}, nil
}
