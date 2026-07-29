package accounts

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth/oauth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"
	"auth_service/internal/models"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

type account struct {
	Provider  string    `json:"provider" example:"google"`
	Email     string    `json:"email" example:"example@domain.com"`
	CreatedAt time.Time `json:"created_at" example:"2026-07-24T12:00:00Z"`
}

type response struct {
	resp.Response
	Accounts []account `json:"accounts"`
}

// New godoc
// @Summary      Список привязанных OAuth-аккаунтов
// @Description  Возвращает все OAuth-провайдеры, привязанные к аккаунту
// @Description  текущего аутентифицированного пользователя.
// @Tags         oauth
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  Response  "Список привязанных аккаунтов"
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/oauth/accounts [get]
func New(
	log *slog.Logger,
	authService *oauth.OAuthService,
	handlerTimeout time.Duration,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.accounts.New"

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		claims, ok := claimsParser.ClaimsFromContext(r.Context())
		if !ok {
			reqLog.Error("claims missing from context after RequireAuth")

			render.Status(r, http.StatusUnauthorized)
			render.JSON(w, r, resp.Error("invalid or expired access token"))
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), handlerTimeout)
		defer cancel()

		accounts, err := authService.ListAccounts(ctx, claims.UserID)
		if err != nil {
			reqLog.Error("failed to list oauth accounts", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal server error"))

			return
		}

		responseOK(w, r, toAccounts(accounts))
	}
}

func responseOK(w http.ResponseWriter, r *http.Request, accounts []account) {
	render.Status(r, http.StatusOK)
	render.JSON(w, r, response{
		Response: resp.OK(),
		Accounts: accounts,
	})
}

func toAccounts(accounts []*models.OAuthAccount) []account {
	result := make([]account, 0, len(accounts))

	for _, a := range accounts {
		result = append(result, account{
			Provider:  a.Provider,
			Email:     a.Email,
			CreatedAt: a.CreatedAt,
		})
	}

	return result
}
