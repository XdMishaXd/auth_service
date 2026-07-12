package httpRateLimit

import (
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	emailParser "auth_service/internal/http_server/middleware/email_parser"
	rateLimit "auth_service/internal/ratelimit"
)

type FailMode int

const (
	FailClosed FailMode = iota
	FailOpen
)

type RateLimit struct {
	limiter *rateLimit.Limiter
	log     *slog.Logger
}

func New(limiter *rateLimit.Limiter, log *slog.Logger) *RateLimit {
	return &RateLimit{limiter: limiter, log: log}
}

func (rl *RateLimit) Register() func(http.Handler) http.Handler {
	return rl.byIP("register", rateLimit.Policy{Burst: 2, Rate: 5, Period: time.Hour})
}

func (rl *RateLimit) Login() func(http.Handler) http.Handler {
	ip := rl.byIP("login", rateLimit.Policy{Burst: 5, Rate: 20, Period: time.Minute})
	email := rl.byEmail("login", rateLimit.Policy{Burst: 3, Rate: 5, Period: time.Minute})
	return chain(emailParser.New, ip, email)
}

func (rl *RateLimit) Refresh() func(http.Handler) http.Handler {
	return rl.byIP("refresh", rateLimit.Policy{Burst: 10, Rate: 30, Period: time.Minute})
}

func (rl *RateLimit) Logout() func(http.Handler) http.Handler {
	return rl.byIP("logout", rateLimit.Policy{Burst: 10, Rate: 30, Period: time.Minute})
}

func (rl *RateLimit) Verify() func(http.Handler) http.Handler {
	return rl.byIP("verify", rateLimit.Policy{Burst: 10, Rate: 30, Period: time.Minute})
}

func (rl *RateLimit) ResendVerificationEmail() func(http.Handler) http.Handler {
	ip := rl.byIP("verify_resend", rateLimit.Policy{Burst: 5, Rate: 20, Period: time.Hour})
	email := rl.byEmail("verify_resend", rateLimit.Policy{Burst: 1, Rate: 3, Period: time.Hour})
	return chain(emailParser.New, ip, email)
}

func (rl *RateLimit) ForgotPassword() func(http.Handler) http.Handler {
	ip := rl.byIP("forgot_password", rateLimit.Policy{Burst: 5, Rate: 20, Period: time.Hour})
	email := rl.byEmail("forgot_password", rateLimit.Policy{Burst: 2, Rate: 3, Period: time.Hour})
	return chain(emailParser.New, ip, email)
}

func (rl *RateLimit) ResetPassword() func(http.Handler) http.Handler {
	return rl.byIP("password_reset", rateLimit.Policy{Burst: 5, Rate: 20, Period: time.Hour})
}

func (rl *RateLimit) byIP(endpoint string, policy rateLimit.Policy) func(http.Handler) http.Handler {
	return rl.build(endpoint, policy, func(r *http.Request) (string, string) {
		return "ip", stripPort(r.RemoteAddr) // RealIP уже подменил RemoteAddr выше по цепочке
	}, FailClosed)
}

func (rl *RateLimit) byEmail(endpoint string, policy rateLimit.Policy) func(http.Handler) http.Handler {
	return rl.build(endpoint, policy, func(r *http.Request) (string, string) {
		return "email", emailParser.FromContext(r.Context())
	}, FailClosed)
}

func (rl *RateLimit) build(
	endpoint string,
	policy rateLimit.Policy,
	keyFunc func(r *http.Request) (keyType, identifier string),
	onFail FailMode,
) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			keyType, identifier := keyFunc(r)
			key := rateLimit.BuildKey(endpoint, keyType, identifier)

			decision, err := rl.limiter.Allow(r.Context(), key, policy)
			if err != nil {
				if errors.Is(err, rateLimit.ErrRedisUnavailable) {
					rl.log.Error("rate limiter redis unavailable",
						slog.String("endpoint", endpoint),
						slog.String("key_type", keyType),
						slog.String("fail_mode", failModeString(onFail)),
						slog.Any("error", err),
					)
					if onFail == FailClosed {
						w.WriteHeader(http.StatusServiceUnavailable)
						_, _ = w.Write([]byte(`{"status":"error","error":"service temporarily unavailable"}`))
						return
					}
					next.ServeHTTP(w, r)
					return
				}
				rl.log.Error("rate limiter internal error", slog.Any("error", err))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			if !decision.Allowed {
				w.Header().Set("Retry-After", strconv.Itoa(int(decision.RetryAfter/time.Second)+1))
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"status":"error","error":"rate limit exceeded"}`))
				return
			}

			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
			next.ServeHTTP(w, r)
		})
	}
}

// chain объединяет несколько middleware в один — chi.With() принимает
// только один middleware на вызов в вашем стиле (r.With(rateLimit.Login())),
// поэтому композиция должна произойти здесь, а не в роутере.
func chain(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		h := final
		for i := len(mws) - 1; i >= 0; i-- {
			h = mws[i](h)
		}
		return h
	}
}

func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func failModeString(m FailMode) string {
	if m == FailClosed {
		return "fail_closed"
	}
	return "fail_open"
}
