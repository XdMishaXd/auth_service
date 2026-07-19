package health

import (
	"net/http"

	"github.com/go-chi/render"
)

func New() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, http.StatusOK)
	}
}
