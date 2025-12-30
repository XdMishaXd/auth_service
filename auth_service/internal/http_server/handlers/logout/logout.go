package logout

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

type Response struct {
	resp.Response
}

func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.logout.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request

		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		log.Info("Request body decoded")

		if err := validate.Struct(req); err != nil {
			validateErr := err.(validator.ValidationErrors)

			log.Error("Invalid request", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.ValidationError(validateErr))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := authMiddleware.Logout(ctx, req.RefreshToken); err != nil {
			log.Error("failed to logout user", sl.Err(err))

			if errors.Is(err, auth.ErrInvalidCredentials) {
				render.JSON(w, r, resp.Error("invalid credentials"))

				return
			}

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("user logged out successfully")

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
