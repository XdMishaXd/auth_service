package scalarHandler

import (
	"fmt"
	"net/http"
)

// New отдаёт HTML-страницу Scalar API Reference, которая сама
// подгружает OpenAPI-спек по specURL (например "/swagger/doc.json").
func New(specURL string) http.HandlerFunc {
	page := fmt.Sprintf(`<!doctype html>
<html>
<head>
  <title>Auth Service API — Reference</title>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
</head>
<body>
  <script id="api-reference" data-url="%s"></script>
  <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
</body>
</html>`, specURL)

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(page))
	}
}
