package metricsCollector

import (
	"net/http"
	"strconv"
	"time"

	"auth_service/internal/metrics"

	"github.com/go-chi/chi"
)

// New возвращает middleware, пишущий http_requests_total и
// http_request_duration_seconds для каждого запроса, прошедшего через роутер.
func New(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rec, r)

			duration := time.Since(start).Seconds()

			pattern := routePattern(r)
			status := strconv.Itoa(rec.status)

			m.HTTPRequestsTotal.WithLabelValues(pattern, r.Method, status).Inc()
			m.HTTPRequestDuration.WithLabelValues(pattern, r.Method).Observe(duration)
		})
	}
}

// routePattern возвращает pattern, под который замэтчился роут в chi
// (например "/auth/oauth/{provider}/callback").
// RouteContext заполняется chi по ходу матчинга и доступен ПОСЛЕ ServeHTTP,
// когда middleware стоит на верхнем уровне роутера (что и требуется).
func routePattern(r *http.Request) string {
	rctx := chi.RouteContext(r.Context())
	if rctx == nil {
		return "unmatched"
	}
	pattern := rctx.RoutePattern()
	if pattern == "" {
		// 404, метод не разрешён и т.п. — без нормализации сырой r.URL.Path
		// даст explosion лейблов на ботовом трафике (/wp-admin, /.env, ...)
		return "unmatched"
	}
	return pattern
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.status = code
	r.wroteHeader = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK) // фиксируем implicit 200 явно, через нашу же логику
	}
	return r.ResponseWriter.Write(b)
}
