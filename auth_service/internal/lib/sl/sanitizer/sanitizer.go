package sanitizer

import "net/http"

var sensitiveQueryParams = map[string]struct{}{
	"code":  {},
	"state": {},
	"token": {},
}

func SanitizedURI(r *http.Request) string {
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
