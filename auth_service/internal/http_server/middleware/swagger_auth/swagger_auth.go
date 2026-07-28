package swaggerAuth

import (
	"crypto/subtle"
	"log/slog"
	"net/http"

	sl "auth_service/internal/lib/logger"
)

// New - middleware для защиты Swagger
func New(log *slog.Logger, username, password string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Если credentials пустые, Swagger недоступен
			if username == "" || password == "" {
				http.Error(w, "Not Found", http.StatusNotFound)
				return
			}

			user, pass, ok := r.BasicAuth()

			usernameMatch := subtle.ConstantTimeCompare([]byte(user), []byte(username)) == 1
			passwordMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1

			if !ok || !usernameMatch || !passwordMatch {
				w.Header().Set("WWW-Authenticate", `Basic realm="Swagger Documentation"`)
				w.WriteHeader(http.StatusUnauthorized)

				if _, err := w.Write([]byte("Unauthorized")); err != nil {
					log.Warn("failed to write header", sl.Err(err))
				}

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
