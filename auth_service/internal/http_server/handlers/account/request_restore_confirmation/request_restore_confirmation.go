package requestrestoreconfirmation

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"
	"auth_service/internal/storage"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type request struct {
	Email string `json:"email" validate:"required,email" example:"example@domain.com"`
	AppID int32  `json:"app_id" validate:"required,gt=0" example:"1"`
}

type response struct {
	resp.Response
	SessionID string `json:"session_id" example:"abcDEF123..."`
}

// New godoc
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

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		var req request
		if err := render.DecodeJSON(r.Body, &req); err != nil {
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid request"))
			return
		}
		if err := validate.Struct(req); err != nil {
			var validateErr validator.ValidationErrors

			if errors.As(err, &validateErr) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.ValidationError(validateErr))

				return
			}

			reqLog.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		sessionID, err := authService.RequestRestoreConfirmation(ctx, req.Email, req.AppID, pendingSessionTTL)
		if err != nil {
			// Клиенту всегда один и тот же ответ (anti-enumeration).
			switch {
			case errors.Is(err, storage.ErrUserNotFound), errors.Is(err, storage.ErrNothingToRestore):
				reqLog.Info("restore confirmation request completed: no matching account")
			default:
				reqLog.Error("failed to send restore confirmation", sl.Err(err))
			}

			responseOK(w, r, "")
			return
		}

		reqLog.Info("restore confirmation requested")

		responseOK(w, r, sessionID)
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, sessionID string) {
	render.JSON(w, r, response{
		Response:  resp.OK(),
		SessionID: sessionID,
	})
}
