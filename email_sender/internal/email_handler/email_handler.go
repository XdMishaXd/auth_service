package emailhandler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"email_sender/internal/config"
	"email_sender/internal/lib/sl"
	"email_sender/internal/mailer"
	"email_sender/internal/models"
)

type Handler struct {
	log        *slog.Logger
	mailSender *mailer.Mailer
	cfg        *config.Config
}

func New(log *slog.Logger, mailSender *mailer.Mailer, cfg *config.Config) *Handler {
	return &Handler{
		log:        log,
		mailSender: mailSender,
		cfg:        cfg,
	}
}

// Handle реализует сигнатуру func(context.Context, []byte) error,
// ожидаемую rabbitmq.StartReading.
func (h *Handler) Handle(ctx context.Context, msg []byte) error {
	const op = "emailhandler.Handle"

	var emailMsg models.EmailMessage
	if err := json.Unmarshal(msg, &emailMsg); err != nil {
		h.log.Error("failed to unmarshal message", sl.Err(err))
		return fmt.Errorf("%s: unmarshal: %w", op, err)
	}

	link := h.cfg.BaseURL + emailMsg.MessageText

	if err := h.mailSender.Send(
		ctx,
		emailMsg.Email,
		link,
		emailMsg.Purpose,
	); err != nil {
		h.log.Error("failed to send message",
			sl.Err(err),
			slog.String("email", emailMsg.Email),
			slog.String("purpose", emailMsg.Purpose),
		)
		return fmt.Errorf("%s: send: %w", op, err)
	}

	h.log.Info("message sent successfully",
		slog.String("email", emailMsg.Email),
		slog.String("purpose", emailMsg.Purpose),
	)
	return nil
}
