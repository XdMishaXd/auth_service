package docsHandler

import (
	"net/http"

	"github.com/swaggo/swag"

	_ "auth_service/docs"
)

// New возвращает хендлер, отдающий сгенерированный OpenAPI-спек
// (swagger.json) для потребления Scalar UI. Эндпоинт инфраструктурный —
// не включается в саму спеку через swag-аннотации (@Router/@Summary),
// т.к. он не часть публичного API-контракта, а раздатчик самого контракта.
func New() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc, err := swag.ReadDoc()
		if err != nil {
			http.Error(w, "failed to read swagger doc", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(doc))
	}
}
