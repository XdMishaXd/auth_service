package login

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Email string `json:"email" validate:"required,email"`
	Pass  string `json:"password" validate:"required"`
	AppID int32  `json:"app_id" validate:"required"`
}

type Response struct {
	resp.Response
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func New(
	log *slog.Logger,
	validate *validator.Validate,
	authMiddleware *auth.Auth,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.login.New"

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

		accessToken, refreshToken, err := authMiddleware.Login(ctx, req.Email, req.Pass, req.AppID)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrUserNotFound):
				render.JSON(w, r, resp.Error("User not found"))
				return
			case errors.Is(err, auth.ErrInvalidCredentials):
				render.JSON(w, r, resp.Error("Invalid credentials"))
				return
			case errors.Is(err, auth.ErrInvalidAppID):
				render.JSON(w, r, resp.Error("Invalid app id"))
				return
			case errors.Is(err, auth.ErrEmailNotVerified):
				render.JSON(w, r, resp.Error("email is not verified"))
				return
			}

			log.Error("failed to login user", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		log.Info("User logged in successfully")

		ResponseOK(w, r, accessToken, refreshToken)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, accessToken, refreshToken string) {
	render.JSON(w, r, Response{
		Response:     resp.OK(),
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
