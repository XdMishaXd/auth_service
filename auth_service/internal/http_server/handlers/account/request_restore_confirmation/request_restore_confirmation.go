package requestRestoreConfirmation

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Email string `json:"email" validate:"required,email" example:"example@domain.com"`
	AppID int32  `json:"app_id" validate:"required,gt=0" example:"1"`
}

type Response struct {
	resp.Response
	SessionID string `json:"session_id" example:"abcDEF123..."`
}

// NewRequestConfirmation godoc
// @Summary      Запросить подтверждение восстановления аккаунта через magic link
// @Description  Отправляет magic-link код на email указанного (soft-deleted)
// @Description  аккаунта для подтверждения восстановления. Неаутентифицированный
// @Description  эндпоинт — юзер не может залогиниться, пока аккаунт удалён.
// @Description  Возвращает session_id для последующего запроса в /account/restore.
// @Tags         account
// @Accept       json
// @Produce      json
// @Param        request  body  Request  true  "Email и app_id"
// @Success      200  {object}  object{status=string,session_id=string}  "Код отправлен на email"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный запрос"
// @Failure      429  {object}  object{status=string,error=string}  "Превышен лимит запросов"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /account/restore/request-confirmation [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authService *auth.Auth,
	handlerTimeout time.Duration,
	pendingSessionTTL time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.account.restore.NewRequestConfirmation"

		log := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req Request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}
		if err := validate.Struct(req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		sessionID, err := authService.RequestRestoreConfirmation(ctx, req.Email, req.AppID, pendingSessionTTL)
		if err != nil {
			// Nameренно не различаем "не найден"/"не удалён" на HTTP-уровне —
			// см. обсуждение enumeration risk. Один и тот же ответ клиенту
			// независимо от реальной причины, ошибка логируется полностью.
			log.Info("restore confirmation request completed", sl.Err(err))
			responseOK(w, r, "")
			return
		}

		log.Info("restore confirmation requested")

		responseOK(w, r, sessionID)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, sessionID string) {
	render.JSON(w, r, Response{
		Response:  resp.OK(),
		SessionID: sessionID,
	})
}
