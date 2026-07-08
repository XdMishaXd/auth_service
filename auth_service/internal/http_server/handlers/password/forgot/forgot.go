package forgot

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/lib/mailer"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Email string `json:"email" validate:"required,email"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Request password reset
// @Description  Initiates a password reset flow for the given email. Always returns 200 OK
// @Description  regardless of whether the email exists, to avoid user enumeration.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body forgot.Request true "User email"
// @Success      200 {object} forgot.Response "Reset email sent if account exists"
// @Failure      400 {object} response.Response "Invalid request body or validation error"
// @Failure      500 {object} response.Response "Internal server error"
// @Router       /auth/password/forgot [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	msgSender mailer.Publisher,
	authMiddleware *auth.Auth,
	address string,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.password.forgot.New"

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

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		resetToken, err := authMiddleware.Forgot(ctx, req.Email)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				ResponseOK(w, r)

				return
			}

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		if err := mailer.SendResetPassEmail(ctx, msgSender, resetToken, address, req.Email); err != nil {
			log.Error("Failed to send message", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
