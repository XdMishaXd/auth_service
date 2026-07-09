package rateLimit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	httprate "github.com/go-chi/httprate"
)

var ErrLimitExeeded = errors.New("limit exeeded")

func Login() func(http.Handler) http.Handler {
	return chain(
		limitByIP(10, 5*time.Minute),
		limitByEmail(5, 15*time.Minute),
	)
}

func Register() func(http.Handler) http.Handler {
	return chain(
		limitByIP(5, time.Hour),
		limitByEmail(3, time.Hour),
	)
}

func Refresh() func(http.Handler) http.Handler {
	return limitByIP(30, 10*time.Minute)
}

func Logout() func(http.Handler) http.Handler {
	return limitByIP(20, 10*time.Minute)
}

func Verify() func(http.Handler) http.Handler {
	return limitByIP(10, 10*time.Minute)
}

func ResendVerificationEmail() func(http.Handler) http.Handler {
	return chain(
		limitByIP(3, time.Hour),
		limitByEmail(3, time.Hour),
	)
}

func ForgotPassword() func(http.Handler) http.Handler {
	return chain(
		limitByIP(3, time.Hour),
		limitByEmail(3, time.Hour),
	)
}

func ResetPassword() func(http.Handler) http.Handler {
	return limitByIP(10, 10*time.Minute)
}

func limitByIP(limit int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.Limit(limit, window, httprate.WithKeyFuncs(httprate.KeyByIP))
}

func emailFromBody(r *http.Request) (string, error) {
	if r.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<16)) // защита от body-bomb
	if err != nil {
		return "", err
	}
	r.Body = io.NopCloser(bytes.NewReader(body)) // восстанавливаем для handler'а

	var payload struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", nil // не критично — просто не лимитируем по email
	}
	return payload.Email, nil
}

// chain объединяет несколько middleware — request должен пройти оба лимита.
func chain(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			next = mws[i](next)
		}
		return next
	}
}

func limitByEmail(limit int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.Limit(limit, window, httprate.WithKeyFuncs(
		func(r *http.Request) (string, error) {
			email, err := emailFromBody(r)
			if err != nil {
				return "", err
			}
			if email == "" {
				return "", ErrLimitExeeded
			}
			return "email:" + email, nil
		},
	))
}
