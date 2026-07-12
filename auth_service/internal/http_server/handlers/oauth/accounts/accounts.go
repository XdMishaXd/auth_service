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

func New(
	log *slog.Logger,
	authService *oauth.OAuthService,
	handlerTimeout time.Duration,
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

func toAccounts(models []*models.OAuthAccount) []Account {
	result := make([]Account, 0, len(models))
	for _, m := range models {
		result = append(result, Account{
			Provider:  m.Provider,
			Email:     m.Email,
			CreatedAt: m.CreatedAt,
		})
	}
	return result
}
