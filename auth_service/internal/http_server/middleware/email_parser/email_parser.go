package emailParser

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// ctxKey — непубличный типизированный тип ключа контекста, чтобы исключить
// коллизии с ключами других пакетов (idiomatic Go: не используйте string
// напрямую как ключ context.WithValue).
type ctxKey int

const emailKey ctxKey = iota

// emailPayload — минимальная форма, требуется только поле email;
// остальные поля тела запроса middleware не касаются и не валидируют,
// это ответственность хендлера/своих DTO.
type emailPayload struct {
	Email string `json:"email"`
}

// Middleware читает поле "email" из JSON body запроса, кладёт его в контекст
// и восстанавливает body, чтобы хендлер мог прочитать его снова.
//
// Если body невалиден или email отсутствует — middleware НЕ блокирует запрос
// и не возвращает ошибку сама: в контекст просто попадёт пустая строка,
// а дальнейшая валидация (400 при пустом email) — ответственность самого
// хендлера/rate-limit-конфига (пустой email при этом лимитируется как
// отдельный "аноним" ключ — сознательное решение, чтобы не плодить точки
// принятия решений об ошибках в двух местах).
func New(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			// Не можем прочитать тело — оставляем как есть, хендлер сам
			// вернёт понятную ошибку при попытке чтения/декодирования.
			next.ServeHTTP(w, r)
			return
		}
		r.Body.Close()

		// Восстанавливаем body для хендлера НЕЗАВИСИМО от того,
		// распарсился JSON или нет — иначе хендлер получит пустое тело
		// даже при валидном JSON, если тут допущена ошибка.
		r.Body = io.NopCloser(bytes.NewReader(body))

		var payload emailPayload
		if err := json.Unmarshal(body, &payload); err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), emailKey, payload.Email)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// FromContext достаёт email, положенный Middleware. Возвращает пустую
// строку, если middleware не отрабатывал или email отсутствовал в body.
func FromContext(ctx context.Context) string {
	email, _ := ctx.Value(emailKey).(string)
	return email
}
