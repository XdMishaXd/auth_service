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
	"auth_service/internal/models"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
	SessionID string `json:"session_id" example:"abcDEF123..."`
}

// NewDisable2FA godoc
// @Summary      Запросить подтверждение отключения 2FA через magic link
// @Description  Отправляет magic-link код на email текущего пользователя для
// @Description  подтверждения отключения 2FA. Требуется только для
// @Description  oauth-only пользователей без пароля — у них нет иного
// @Description  способа подтвердить чувствительное действие. Возвращает
// @Description  session_id, который затем передаётся вместе с кодом из письма
// @Description  в /auth/2fa/disable.
// @Tags         2fa
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  object{status=string,session_id=string}  "Код отправлен на email"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/2fa/disable/request-confirmation [post]
func NewDisable2FA(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return newActionConfirmationHandler(log, authMiddleware, models.ActionDisable2FA, handlerTimeout, pendingSessionTTL)
}

// NewDeleteAccount godoc
// @Summary      Запросить подтверждение удаления аккаунта через magic link
// @Description  Отправляет magic-link код на email текущего пользователя для
// @Description  подтверждения удаления аккаунта. Требуется только для
// @Description  oauth-only пользователей без пароля — у них нет иного
// @Description  способа подтвердить чувствительное действие. Возвращает
// @Description  session_id, который затем передаётся вместе с кодом из письма
// @Description  в /account/delete.
// @Tags         account
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  object{status=string,session_id=string}  "Код отправлен на email"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /account/delete/request-confirmation [post]
func NewDeleteAccount(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return newActionConfirmationHandler(log, authMiddleware, models.ActionDeleteAccount, handlerTimeout, pendingSessionTTL)
}

// newActionConfirmationHandler — общее ядро для всех chувствительных действий,
// подтверждаемых magic-link кодом. action фиксируется на этапе регистрации
// роута (сервером), а не клиентом в теле запроса — иначе клиент мог бы
// запросить confirmation для одного действия и подтвердить им другое.
func newActionConfirmationHandler(
	log *slog.Logger,
	authMiddleware *auth.Auth,
	action models.Action,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.twofa.requestaction.newActionConfirmationHandler"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
			slog.String("action", string(action)),
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
			action,
			pendingSessionTTL,
		)
		if err != nil {
			log.Error("failed to request action confirmation", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("Internal error"))
			return
		}

		log.Info("action confirmation requested", slog.Int64("user_id", claims.UserID))

		responseOK(w, r, sessionID)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, sessionID string) {
	render.JSON(w, r, Response{
		Response:  resp.OK(),
		SessionID: sessionID,
	})
}
