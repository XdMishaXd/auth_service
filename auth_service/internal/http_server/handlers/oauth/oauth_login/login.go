package oauthlogin

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"auth_service/internal/auth/oauth"
	resp "auth_service/internal/lib/api/response"
	"auth_service/internal/lib/sl"
	"auth_service/internal/lib/validation/oauthutil"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
)

// New godoc
// @Summary      Начало OAuth-авторизации
// @Description  Запускает процесс OAuth2-авторизации для указанного OAuth-провайдера.
// @Description  Проверяет корректность app_id и redirect_uri, а также соответствие
// @Description  redirect_uri списку разрешённых адресов.
// @Description  После успешной проверки формирует параметр state и перенаправляет
// @Description  пользователя на страницу авторизации OAuth-провайдера.
// @Tags         oauth
// @Produce      json
// @Param        provider      path   string   true  "Название OAuth-провайдера (например: google, github)"
// @Param        app_id        query  integer  true  "Идентификатор клиентского приложения"
// @Param        redirect_uri  query  string   true  "URL для перенаправления после завершения авторизации. Должен входить в список разрешённых адресов."
// @Success      302  "Перенаправление на страницу авторизации OAuth-провайдера"
// @Failure      400  {object}  object{status=string,error=string}  "Некорректный app_id или redirect_uri не прошёл проверку"
// @Failure      404  {object}  object{status=string,error=string}  "OAuth-провайдер не поддерживается"
// @Failure      500  {object}  object{status=string,error=string}  "Не удалось сформировать URL для авторизации"
// @Router       /auth/oauth/{provider}/login [get]
func New(
	log *slog.Logger,
	authMiddleware *oauth.OAuthService,
	allowedHosts map[string]bool,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		const op = "handlers.oauth.login.New"

		reqLog := log.With(
			slog.String("op", op),
			slog.String("request_id", middleware.GetReqID(r.Context())),
		)

		providerName := chi.URLParam(r, "provider")

		appIDStr := r.URL.Query().Get("app_id")
		appID64, err := strconv.ParseInt(appIDStr, 10, 32)
		if err != nil {
			reqLog.Warn("invalid app_id", slog.String("raw", appIDStr))

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error("invalid app_id"))
			return
		}

		redirectURI, err := oauthutil.ValidateRedirectURI(r.URL.Query().Get("redirect_uri"), allowedHosts)
		if err != nil {
			reqLog.Warn("redirect_uri rejected",
				slog.String("raw", r.URL.Query().Get("redirect_uri")),
				slog.Any("allowed_hosts", allowedHosts),
			)

			render.Status(r, http.StatusBadRequest)
			render.JSON(w, r, resp.Error(err.Error()))

			return
		}

		authURL, err := authMiddleware.StartLogin(r.Context(), providerName, int32(appID64), redirectURI, 0)
		if err != nil {
			switch {
			case errors.Is(err, oauth.ErrOAuthProviderNotFound):
				reqLog.Warn("oauth provider not found", slog.String("provider", providerName))
				render.Status(r, http.StatusNotFound)
			default:
				reqLog.Error("failed to start oauth login", sl.Err(err))
				render.Status(r, http.StatusInternalServerError)
			}

			render.JSON(w, r, resp.Error("Internal error"))

			return
		}

		reqLog.Info("oauth login started",
			slog.String("provider", providerName),
			slog.Int64("app_id", appID64),
		)

		// authURL строится из статического provider config
		http.Redirect(w, r, authURL, http.StatusFound) //nolint:gosec // G710: authURL is server-built, not user-controlled
	}
}
