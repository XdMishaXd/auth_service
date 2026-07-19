package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

type Metrics struct {
	Registry *prometheus.Registry

	// HTTP-метрики (health/metrics эндпоинты)
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// Consumer-метрики (RabbitMQ)
	MessagesConsumedTotal     prometheus.Counter
	MessagesFailedTotal       *prometheus.CounterVec
	MessageProcessingDuration prometheus.Histogram
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
			[]string{"pattern", "method", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "http_request_duration_seconds",
				Help:    "HTTP request duration in seconds, labeled by route pattern and method",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"pattern", "method"},
		),

		MessagesConsumedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "messages_consumed_total",
			Help: "Total successfully processed and acked messages",
		}),
		MessagesFailedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "messages_failed_total",
			Help: "Total messages that failed processing and were nacked",
		}, []string{"reason"}),
		MessageProcessingDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "message_processing_duration_seconds",
			Help:    "Duration of message handler execution",
			Buckets: prometheus.DefBuckets,
		}),
	}

	reg.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.MessagesConsumedTotal,
		m.MessagesFailedTotal,
		m.MessageProcessingDuration,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}
