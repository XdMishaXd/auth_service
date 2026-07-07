package jwt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"auth_service/internal/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

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

func NewRefreshToken(id string) (string, string, []byte, error) {
	if id == "" {
		id = uuid.NewString()
	}

	b := make([]byte, 32)

	_, err := rand.Read(b)
	if err != nil {
		return "", "", nil, err
	}

	token := base64.RawURLEncoding.EncodeToString(b)

	fullToken := id + "." + token

	sum := sha256.Sum256([]byte(token))
	hash := sum[:]

	return id, fullToken, hash, nil
}
