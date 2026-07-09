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
// @Description  Initiates a password reset flow for the given email address.
// @Description  Always returns 200 OK regardless of whether the account exists,
// @Description  to prevent user enumeration. If the account exists, a reset link
// @Description  is sent to the provided email; delivery failures are logged
// @Description  server-side and do not affect the response.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        request body forgot.Request true "User email"
// @Success      200 {object} forgot.Response "Request accepted (does not confirm account existence)"
// @Failure      400 {object} response.Response "Invalid request body or validation error"
// @Failure      429 {object} response.Response "Rate limit exceeded"
// @Failure      500 {object} response.Response "Internal server error (token generation failure, not related to email existence)"
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

		var validateErr validator.ValidationErrors

		if errors.As(err, &validateErr) {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.ValidationError(validateErr))
		} else {
			log.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		resetToken, err := authMiddleware.Forgot(ctx, req.Email)
		if err != nil {
			if errors.Is(err, storage.ErrUserNotFound) {
				log.Info("forgot password requested for non-existent email")
				ResponseOK(w, r)
				return
			}

			log.Error("failed to generate reset token", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		if err := mailer.SendResetPassEmail(ctx, msgSender, resetToken, address, req.Email); err != nil {
			log.Error("failed to send reset email, user will not receive it", sl.Err(err))
			ResponseOK(w, r)
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
