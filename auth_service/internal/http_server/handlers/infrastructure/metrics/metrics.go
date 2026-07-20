package metricsHandler

import (
	"net/http"

	"auth_service/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// New godoc
// @Summary      Prometheus метрики
// @Description  Отдаёт метрики сервиса в формате Prometheus exposition format.
// @Description  Не предназначен для вызова из браузера/фронтенда — эндпоинт
// @Description  для scrape'а Prometheus-сервером.
// @Tags         System
// @Produce      plain
// @Success      200  {string}  string  "Метрики в текстовом формате Prometheus"
// @Router       /metrics [get]
func New(m *metrics.Metrics) http.HandlerFunc {
	handler := promhttp.HandlerFor(m.Registry, promhttp.HandlerOpts{
		// не роняем весь scrape при ошибке одного коллектора —
		// пишем остальные метрики + строку ошибки в конец вывода
		ErrorHandling: promhttp.ContinueOnError,
	})

	return handler.ServeHTTP
}
