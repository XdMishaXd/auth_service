package mailer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"gopkg.in/gomail.v2"
)

var (
	ErrUnknownPurpose = errors.New("unknown purpose")
	ErrDial           = errors.New("dial failed")
	ErrSend           = errors.New("send failed")
	ErrTimeout        = errors.New("send timed out")
)

type Mailer struct {
	dialer   *gomail.Dialer
	Username string

	pool     chan gomail.SendCloser
	poolSize int

	closed bool
	mu     sync.Mutex // защищает closed

	log *slog.Logger
}

func NewMailer(host string, port, poolSize int, username, password string, log *slog.Logger) *Mailer {
	return &Mailer{
		dialer:   gomail.NewDialer(host, port, username, password),
		Username: username,
		pool:     make(chan gomail.SendCloser, poolSize),
		poolSize: poolSize,
		log:      log,
	}
}

func (m *Mailer) Send(ctx context.Context, to, body, purpose string) error {
	const op = "mailer.Send"

	msg, err := buildMessage(to, body, purpose, m.Username)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- m.sendWithRetry(msg)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("%s: %w", op, err)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("%s: %w: %w", op, ErrTimeout, ctx.Err())
	}
}

func (m *Mailer) Close() error {
	const op = "mailer.Close"

	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()

	close(m.pool)

	var errs []error
	for c := range m.pool {
		if err := c.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func buildMessage(to, body, purpose, username string) (*gomail.Message, error) {
	const op = "mailer.buildMessage"

	msg := gomail.NewMessage()
	msg.SetHeader("To", to)
	msg.SetHeader("From", username)

	switch purpose {
	case "reset_password":
		msg.SetHeader("Subject", "Сброс пароля")
	case "email_verification":
		msg.SetHeader("Subject", "Подтверждение почты")
	case "2fa":
		msg.SetHeader("Subject", "Подтверждение действия")
	default:
		return nil, fmt.Errorf("%s: %w: %q", op, ErrUnknownPurpose, purpose)
	}

	msg.SetBody("text/plain", body)
	return msg, nil
}

func (m *Mailer) getConn() (gomail.SendCloser, error) {
	const op = "mailer.getConn"

	select {
	case c := <-m.pool:
		return c, nil
	default:
		c, err := m.dialer.Dial()
		if err != nil {
			return nil, fmt.Errorf("%s: %w: %w", op, ErrDial, err)
		}
		return c, nil
	}
}

func (m *Mailer) putConn(c gomail.SendCloser) {
	const op = "mailer.putConn"

	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()

	if closed {
		if err := c.Close(); err != nil {
			m.log.Error("close conn on shutdown", "op", op, "error", err)
		}
		return
	}

	select {
	case m.pool <- c:
	default:
		if err := c.Close(); err != nil {
			m.log.Error("close conn on shutdown", "op", op, "error", err)
		}
	}
}

// sendWithRetry — одна повторная попытка на свежем соединении, если первое
// оказалось "тухлым" (SMTP-сервер закрывает простаивающие соединения).
func (m *Mailer) sendWithRetry(msg *gomail.Message) error {
	const op = "mailer.sendWithRetry"

	conn, err := m.getConn()
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := sendOnce(conn, msg); err != nil {
		closeErr := conn.Close()

		freshConn, dialErr := m.dialer.Dial()
		if dialErr != nil {
			return fmt.Errorf("%s: first attempt: %w; close: %w; retry dial: %w: %w",
				op, err, closeErr, ErrDial, dialErr)
		}

		if err := sendOnce(freshConn, msg); err != nil {
			freshCloseErr := freshConn.Close()
			return fmt.Errorf("%s: retry: %w; close: %w", op, err, freshCloseErr)
		}

		m.putConn(freshConn)
		return errWrapIfNotNil(op, "close stale conn", closeErr)
	}

	m.putConn(conn)
	return nil
}

// sendOnce — одна попытка отправки на переданном соединении.
func sendOnce(conn gomail.SendCloser, msg *gomail.Message) error {
	const op = "mailer.sendOnce"

	if err := gomail.Send(conn, msg); err != nil {
		return fmt.Errorf("%s: %w: %w", op, ErrSend, err)
	}
	return nil
}

// errWrapIfNotNil — успешная отправка не должна маскироваться ошибкой close
// от предыдущего (уже нерелевантного) соединения, но и терять её молча нельзя.
func errWrapIfNotNil(op, msg string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %s: %w", op, msg, err)
}
