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

// @Summary      Callback OAuth-провайдера
// @Description  Обрабатывает перенаправление от OAuth-провайдера после завершения авторизации пользователя.
// @Description  В зависимости от параметра state завершает вход в систему или привязывает OAuth-провайдера к существующему аккаунту.
// @Tags         oauth
// @Produce      json
// @Param        provider  path   string  true  "Название OAuth-провайдера (например: google, github)"
// @Param        code      query  string  true  "Код авторизации, полученный от OAuth-провайдера"
// @Param        state     query  string  true  "Токен состояния (state), полученный при начале авторизации или привязки аккаунта"
// @Param        error     query  string  false "Код ошибки, возвращённый OAuth-провайдером, если пользователь отказал в доступе"
// @Success      200  {object}  Response  "Операция успешно выполнена"
// @Failure      400  {object}  object{status=string,error=string}  "Пользователь отказал в доступе, отсутствуют обязательные параметры code или state, state недействителен или истёк, либо указан некорректный app_id"
// @Failure      403  {object}  object{status=string,error=string}  "Email, полученный от OAuth-провайдера, не подтверждён"
// @Failure      404  {object}  object{status=string,error=string}  "OAuth-провайдер не поддерживается"
// @Failure      409  {object}  object{status=string,error=string}  "Конфликт данных: аккаунт с таким email уже существует или OAuth-провайдер уже привязан к другому аккаунту"
// @Failure      500  {object}  object{status=string,error=string}  "Внутренняя ошибка сервера"
// @Router       /auth/oauth/{provider}/callback [get]
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
