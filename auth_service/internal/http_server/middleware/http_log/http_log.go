package httplog

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"auth_service/internal/lib/sl/sanitizer"
	"auth_service/internal/metrics"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func New(logger *slog.Logger, m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				dur := time.Since(start)
				status := ww.Status()
				pattern := chi.RouteContext(r.Context()).RoutePattern()

				logger.LogAttrs(r.Context(), levelFor(status),
					"http request",
					slog.String("method", r.Method),
					slog.String("uri", sanitizer.SanitizedURI(r)),
					slog.Int("status", status),
					slog.Int("bytes", ww.BytesWritten()),
					slog.Int64("duration_ms", dur.Milliseconds()),
					slog.String("request_id", middleware.GetReqID(r.Context())),
					slog.String("remote_addr", r.RemoteAddr),
				)

				m.HTTPRequestsTotal.WithLabelValues(pattern, r.Method, strconv.Itoa(status)).Inc()
				m.HTTPRequestDuration.WithLabelValues(pattern, r.Method).Observe(dur.Seconds())
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func levelFor(status int) slog.Level {
	switch {
	case status >= 500:
		return slog.LevelError
	case status >= 400:
		return slog.LevelWarn
	default:
		return slog.LevelInfo
	}
}
