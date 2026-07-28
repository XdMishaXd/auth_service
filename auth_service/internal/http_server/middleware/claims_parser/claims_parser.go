package claimsParser

import (
	"context"
	"net/http"
	"strings"

	jwtGen "auth_service/internal/lib/jwt"

	"github.com/go-chi/render"
)

type contextKey string

const claimsContextKey contextKey = "claims"

func RequireAuth(apps jwtGen.AppSecretProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			const prefix = "Bearer "

			if !strings.HasPrefix(header, prefix) {
				unauthorized(w, r)
				return
			}

			tokenString := strings.TrimPrefix(header, prefix)

			claims, err := jwtGen.ParseAndVerify(r.Context(), tokenString, apps)
			if err != nil {
				unauthorized(w, r)
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	render.Status(r, http.StatusUnauthorized)
	render.JSON(w, r, map[string]string{"error": "invalid or expired access token"})
}

func ClaimsFromContext(ctx context.Context) (*jwtGen.Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*jwtGen.Claims)
	return claims, ok
}
