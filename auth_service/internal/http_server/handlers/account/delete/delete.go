package deleteAccount

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
	"github.com/go-playground/validator/v10"
)

type Request struct {
	Password  string `json:"password,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Token     string `json:"token,omitempty"`
}

type Response struct {
	resp.Response
}

// New godoc
// @Summary      Удалить аккаунт
// @Description  Помечает аккаунт как удалённый (soft delete, grace period 7
// @Description  дней). Требует подтверждения: паролем (если он установлен)
// @Description  либо magic-link кодом, полученным через
// @Description  /account/delete/request-confirmation (для oauth-only
// @Description  пользователей без пароля). Все refresh-токены и активные
// @Description  сессии немедленно отзываются. Идемпотентно — повторный вызов
// @Description  на уже удалённый аккаунт не является ошибкой.
// @Tags         account
// @Security     BearerAuth
// @Accept       json
// @Produce      json
// @Param        request  body      Request  true  "Пароль ИЛИ session_id+code"
// @Success      204  "Аккаунт удалён"
// @Failure      400  {object}  object{status=string,error=string}  "Невалидный запрос"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует/невалиден, либо неверный пароль/код подтверждения"
// @Failure      429  {object}  object{status=string,error=string}  "Превышен лимит запросов"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /account/delete [post]
func New(
	log *slog.Logger,
	validate *validator.Validate,
	authService *auth.Auth,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.account.delete.New"

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

		var req Request

		err := render.DecodeJSON(r.Body, &req)
		if err != nil {
			log.Error("Failed to decode request body", sl.Err(err))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("Failed to decode request"))

			return
		}

		log.Info("Request body decoded")

		if err = validate.Struct(req); err != nil {
			var validateErr validator.ValidationErrors

			if errors.As(err, &validateErr) {
				render.Status(r, http.StatusBadRequest)
				render.JSON(w, r, resp.ValidationError(validateErr))

				return
			}

			log.Error("unexpected validation error type", sl.Err(err))
			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal error"))

			return
		}

		// Ровно один способ подтверждения — проверка на уровне хендлера,
		// а не тэгов validate (mutual exclusivity через struct tags громоздка
		// и менее читаема, чем явная проверка здесь).
		hasPassword := req.Password != ""
		hasMagicLink := req.SessionID != "" && req.Token != ""
		if hasPassword == hasMagicLink { // оба заполнены или оба пустые
			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("provide either password or session_id+code, not both or neither"))

			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		err = authService.DeleteAccount(
			ctx,
			claims.UserID,
			req.Password,
			req.SessionID,
			req.Token,
		)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrDeleteConfirmation):
				log.Warn("delete account: confirmation failed", slog.Int64("user_id", claims.UserID))

				render.Status(r, http.StatusUnauthorized)
				render.JSON(w, r, resp.Error("invalid confirmation"))

				return
			default:
				log.Error("failed to delete account", sl.Err(err), slog.Int64("user_id", claims.UserID))

				render.Status(r, http.StatusInternalServerError)
				render.JSON(w, r, resp.Error("Internal error"))

				return
			}
		}

		log.Info("account deleted", slog.Int64("user_id", claims.UserID))

		render.Status(r, http.StatusNoContent)
		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
