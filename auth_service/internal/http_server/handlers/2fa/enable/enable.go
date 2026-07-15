package enable

import (
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"

	resp "auth_service/internal/lib/api/response"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.login.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		// claims, ok := claimsParser.ClaimsFromContext(r.Context())
		// if !ok {
		// 	render.Status(r, http.StatusUnauthorized)
		// 	render.JSON(w, r, resp.Error("invalid or expired access token"))
		// 	return
		// }
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
