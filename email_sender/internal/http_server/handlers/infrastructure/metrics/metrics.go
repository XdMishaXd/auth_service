package metricsHandler

import (
	"net/http"

	"email_sender/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func New(m *metrics.Metrics) http.HandlerFunc {
	handler := promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	})
	return handler.ServeHTTP
}
