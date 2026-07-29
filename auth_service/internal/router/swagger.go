package router

import (
	docsHandler "auth_service/internal/http_server/handlers/infrastructure/docs"
	scalarHandler "auth_service/internal/http_server/handlers/infrastructure/scalar"
	swaggerAuth "auth_service/internal/http_server/middleware/swagger_auth"

	"github.com/go-chi/chi/v5"
)

func (rt *Router) registerSwagger(r chi.Router) {
	d := rt.d
	if !d.Cfg.Swagger.Enabled { //nolint:staticcheck // QF1008: селектор через встроенное поле оставлен явно для читаемости
		return
	}
	r.Group(func(r chi.Router) {
		r.Use(swaggerAuth.New(d.Log, d.Cfg.Swagger.Username, d.Cfg.Swagger.Password)) //nolint:staticcheck // QF1008: селектор через встроенное поле оставлен явно для читаемости
		r.Get("/swagger/doc.json", docsHandler.New(d.Log))
		r.Get("/docs", scalarHandler.New(d.Log, "/swagger/doc.json"))
	})
}
