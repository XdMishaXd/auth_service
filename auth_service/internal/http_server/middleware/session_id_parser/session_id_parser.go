package sessionIDParser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

type contextKey struct{}

var sessionIDContextKey = contextKey{}

type bodyPeek struct {
	SessionID string `json:"session_id"`
}

// New читает session_id из JSON-тела запроса, кладёт в контекст и
// восстанавливает r.Body, чтобы дальнейший декодинг в хэндлере отработал
// как обычно — аналог emailParser для случая, когда ключ лимитирования не
// в URL/claims, а в теле запроса.
func New(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		var peek bodyPeek
		_ = json.Unmarshal(body, &peek) // намеренно игнорируем ошибку — если json битый, хэндлер сам вернёт 400 при decode

		ctx := context.WithValue(r.Context(), sessionIDContextKey, peek.SessionID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func FromContext(ctx context.Context) string {
	sessionID, _ := ctx.Value(sessionIDContextKey).(string)
	return sessionID
}
