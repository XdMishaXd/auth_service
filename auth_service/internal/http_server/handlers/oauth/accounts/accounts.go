package accounts

import (
	"log/slog"
	"net/http"
	"time"

	"auth_service/internal/auth/oauth"
	claimsParser "auth_service/internal/http_server/middleware/claims_parser"
	resp "auth_service/internal/lib/api/response"
	sl "auth_service/internal/lib/logger"
	"auth_service/internal/models"

	"github.com/go-chi/chi/middleware"
	"github.com/go-chi/render"
)

type Account struct {
	Provider  string    `json:"provider"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type Response struct {
	resp.Response
	Accounts []Account `json:"accounts"`
}

// New godoc
// @Summary      List linked OAuth accounts
// @Description  Returns all third-party OAuth providers linked to the
// @Description  currently authenticated user's account.
// @Tags         oauth
// @Security     BearerAuth
// @Produce      json
// @Success      200  {object}  Response  "Список привязанных аккаунтов"  example({"status": "ok", "accounts": [{"provider": "google", "email": "user@example.com", "created_at": "2026-01-15T10:00:00Z"}]})
// @Failure      401  {object}  object{status=string,error=string}  "Access token отсутствует, невалиден или истёк"  example({"status": "error", "error": "invalid or expired access token"})
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"  example({"status": "error", "error": "internal server error"})
// @Router       /auth/oauth/accounts [get]
func New(
	log *slog.Logger,
	authService *oauth.OAuthService,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.accounts.New"

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

		accounts, err := authService.ListAccounts(r.Context(), claims.UserID)
		if err != nil {
			log.Error("failed to list oauth accounts", sl.Err(err))

			render.Status(r, http.StatusInternalServerError)
			render.JSON(w, r, resp.Error("internal server error"))

			return
		}

		ResponseOK(w, r, toAccounts(accounts))
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request, accounts []Account) {
	render.Status(r, http.StatusOK)
	render.JSON(w, r, Response{
		Response: resp.OK(),
		Accounts: accounts,
	})
}

func toAccounts(accounts []*models.OAuthAccount) []Account {
	result := make([]Account, 0, len(accounts))

	for _, a := range accounts {
		result = append(result, Account{
			Provider:  a.Provider,
			Email:     a.Email,
			CreatedAt: a.CreatedAt,
		})
	}

	return result
}
