package logformatter

import (
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5/middleware"
)

var sensitiveQueryParams = map[string]struct{}{
	"code":  {},
	"state": {},
	"token": {},
}

func sanitizedURI(r *http.Request) string {
	u := *r.URL
	q := u.Query()
	changed := false
	for param := range q {
		if _, sensitive := sensitiveQueryParams[param]; sensitive {
			q.Set(param, "***")
			changed = true
		}
	}
	if !changed {
		return r.RequestURI
	}
	u.RawQuery = q.Encode()
	return u.RequestURI()
}

type redactingFormatter struct {
	base *middleware.DefaultLogFormatter
}

func NewRedactingLogger() func(http.Handler) http.Handler {
	return middleware.RequestLogger(&redactingFormatter{
		base: &middleware.DefaultLogFormatter{
			Logger:  log.New(os.Stdout, "", log.LstdFlags),
			NoColor: true,
		},
	})
}

func (f *redactingFormatter) NewLogEntry(r *http.Request) middleware.LogEntry {
	clone := *r // неглубокая копия — оригинальный r в хендлере не меняется
	clone.RequestURI = sanitizedURI(r)
	if clone.URL != nil {
		u := *clone.URL
		clone.URL = &u
	}
	return f.base.NewLogEntry(&clone)
}
