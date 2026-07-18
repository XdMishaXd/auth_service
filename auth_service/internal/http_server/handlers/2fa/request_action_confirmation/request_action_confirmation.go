package requestAction

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
	SessionID string `json:"session_id"`
}

// New godoc
// @Summary      Запросить подтверждение действия через magic link
// @Description  Отправляет magic-link код на email текущего пользователя для
// @Description  подтверждения чувствительного действия (например, отключения
// @Description  2FA у oauth-only пользователя без пароля). Возвращает
// @Description  session_id, который затем передаётся вместе с кодом из письма
// @Description  в соответствующий эндпоинт действия (например, /disable).
// @Tags         2fa
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  object{status=string,session_id=string}  "Код отправлен на email"  example({"status": "ok", "session_id": "abcDEF123..."})
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"  example({"status": "error", "error": "invalid or expired access token"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "Internal error"})
// @Router       /auth/2fa/magic-link/request-action-confirmation [post]
func New(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.requestaction.New"

		log = log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		claims, ok := claimsParser.ClaimsFromContext(r.Context())
		if !ok {
			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired access token"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		sessionID, err := authMiddleware.TwoFA.RequestActionConfirmation(
			ctx,
			claims.UserID, claims.AppID,
			pendingSessionTTL,
		)
		if err != nil {
			log.Error("failed to request action confirmation", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))
			return
		}

		log.Info("action confirmation requested", slog.Int64("user_id", claims.UserID))

		// ? redirect

		ResponseOK(w, r, sessionID)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, sessionID string) {
	render.JSON(w, r, Response{
		Response:  resp.OK(),
		SessionID: sessionID,
	})
}
