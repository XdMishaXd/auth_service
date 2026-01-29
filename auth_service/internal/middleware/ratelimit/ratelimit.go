package rateLimit

import (
	"net/http"
	"time"

	httprate "github.com/go-chi/httprate"
)

func Login() func(http.Handler) http.Handler {
	return limitByIP(10, 5*time.Minute)
}

func Register() func(http.Handler) http.Handler {
	return limitByIP(5, time.Hour)
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
	return limitByIP(3, time.Hour)
}

func limitByIP(limit int, window time.Duration) func(http.Handler) http.Handler {
	return httprate.Limit(limit, window)
}
