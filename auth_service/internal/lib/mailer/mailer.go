package mailer

import (
	"context"
	"fmt"

	"auth_service/internal/models"
)

type Publisher interface {
	SendMessage(ctx context.Context, msg models.Message) error
}

func SendResetPassEmail(ctx context.Context, pub Publisher, resetToken, url, email string) error {
	resetLink := fmt.Sprintf("%s/auth/password/reset?token=%s", url, resetToken)

	msg := models.Message{
		Email:   email,
		Link:    resetLink,
		Purpose: "reset_password",
	}

	if err := pub.SendMessage(ctx, msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

func SendVerificationEmail(ctx context.Context, pub Publisher, msg models.Message) error {
	if err := pub.SendMessage(ctx, msg); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}
