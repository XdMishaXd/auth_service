package tokens

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

// generateOpaque — общая механика: id + random verifier + hash.
// Не экспортируется — используется только внутри конструкторов конкретных токенов.
func generateOpaque(id string) (string, string, []byte, error) {
	if id == "" {
		id = uuid.NewString()
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, fmt.Errorf("generate random bytes: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(b)
	fullToken := id + "." + verifier

	sum := sha256.Sum256([]byte(verifier))
	hash := sum[:]

	return id, fullToken, hash, nil
}

// RefreshToken — multi-use до истечения/logout, ротируется.
func NewRefreshToken(id string) (string, string, []byte, error) {
	return generateOpaque(id)
}

// ResetToken — строго one-time, короткий TTL, задаётся в вызывающем коде
func NewResetToken(id string) (string, string, []byte, error) {
	return generateOpaque(id)
}

func VerifyOpaqueToken(verifier string, storedHash []byte) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare(storedHash, sum[:]) == 1
}
