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

	err := pub.SendMessage(ctx, msg)

	return err
}

func SendVerificationEmail(ctx context.Context, pub Publisher, msg models.Message) error {
	err := pub.SendMessage(ctx, msg)

	return err
}
