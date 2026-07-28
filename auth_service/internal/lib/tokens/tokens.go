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
func generateOpaque(id string) (tokenID, fullToken string, hash []byte, err error) {
	if id == "" {
		newID, err := uuid.NewV7()
		if err != nil {
			return "", "", nil, err
		}

		id = newID.String()
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", nil, fmt.Errorf("generate random bytes: %w", err)
	}

	verifier := base64.RawURLEncoding.EncodeToString(b)
	fullToken = id + "." + verifier

	sum := sha256.Sum256([]byte(verifier))
	hash = sum[:]

	return id, fullToken, hash, nil
}

// NewRefreshToken — multi-use до истечения/logout, ротируется.
func NewRefreshToken(id string) (tokenID, fullToken string, hash []byte, err error) {
	return generateOpaque(id)
}

// NewResetToken — строго one-time, короткий TTL, задаётся в вызывающем коде
func NewResetToken(id string) (tokenID, fullToken string, hash []byte, err error) {
	return generateOpaque(id)
}

func VerifyOpaqueToken(verifier string, storedHash []byte) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare(storedHash, sum[:]) == 1
}
