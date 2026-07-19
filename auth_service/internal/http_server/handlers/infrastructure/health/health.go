package health

import (
	"net/http"

	resp "auth_service/internal/lib/api/response"

	"github.com/go-chi/render"
)

type Response struct {
	resp.Response
}

// New godoc
//
//	@Summary		Health check
//	@Description	Checks that the service is running and able to process requests.
//	@Tags			System
//	@Produce		json
//	@Success		200	{object}	health.Response
//	@Router			/health [get]
func New() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ResponseOK(w, r)
	}
}

func ResponseOK(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, Response{
		Response: resp.OK(),
	})
}
