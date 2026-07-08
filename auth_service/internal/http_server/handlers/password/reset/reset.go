package reset

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/google/uuid"
)

type Request struct {
	NewPass string `json:"password" validate:"required"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Reset password
// @Description  Resets user password using a reset token received via email.
// @Description  Token must be provided as a query parameter in "selector.verifier" format.
// @Tags         auth
// @Accept       json
// @Produce      json
// @Param        token query string true "Reset token in format uuid.verifier"
// @Param        request body reset.Request true "New password"
// @Success      200 {object} reset.Response "Password successfully reset"
// @Failure      400 {object} response.Response "Missing/invalid token format or invalid request body"
// @Failure      401 {object} response.Response "Invalid or expired token"
// @Failure      500 {object} response.Response "Internal server error"
// @Router       /auth/password/reset [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.password.reset.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		token := r.URL.Query().Get("token")
		if token == "" {
			log.Warn("missing verification token")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("missing token"))

			return
		}

		parts := strings.Split(token, ".")

		if len(parts) != 2 {
			log.Warn("invalid reset token format")

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid token"))
			return
		}

		if _, err := uuid.Parse(parts[0]); err != nil {
			log.Warn("invalid token id", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid token"))
			return
		}

		var req Request

		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		log.Info("Request body decoded")

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err = authMiddleware.ResetPassword(ctx, parts[0], parts[1], req.NewPass)
		if err != nil {
			switch {
			case errors.Is(err, storage.ErrResetTokenNotFound):
				log.Warn("invalid or expired token")

				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("Token not found"))
			case errors.Is(err, storage.ErrUserNotFound):
				log.Warn("invalid or expired token")

				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("User not found"))
			default:
				log.Error("failed to reset password", sl.Err(err))

				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("internal error"))
			}

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
