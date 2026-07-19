package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics держит явный Registry и все коллекторы сервиса.
type Metrics struct {
	Registry *prometheus.Registry

	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	EmailPublishFailuresTotal *prometheus.CounterVec
}

func New() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,

		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "http_requests_total",
				Help: "Total HTTP requests, labeled by chi route pattern, method and status",
			},
			// pattern — это chi RoutePattern (напр. "/auth/oauth/{provider}/callback"),
			[]string{"pattern", "method", "status"},
		),

		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "http_request_duration_seconds",
				Help: "HTTP request duration in seconds, labeled by route pattern and method",
				// DefBuckets: .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10 сек.
				// Для auth-эндпоинтов (bcrypt cost=12 в /register/login) достаточно —
				// bcrypt(cost 12) укладывается в 200-400мс, попадёт в 0.5 bucket.
				Buckets: prometheus.DefBuckets,
			},
			[]string{"pattern", "method"},
		),

		EmailPublishFailuresTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "email_publish_failures_total",
				Help: "Count of failed RabbitMQ publishes for outgoing emails",
			},
			// reason будет заполняться из internal/rabbitmq после того как
			// увидим реальные типы ошибок publisher'а (connection/channel/confirm timeout)
			[]string{"reason"},
		),
	}

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.EmailPublishFailuresTotal,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}
