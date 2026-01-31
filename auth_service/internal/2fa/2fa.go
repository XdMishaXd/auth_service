package twoFactorAuth

import (
	"context"

	"auth_service/internal/models"
)

type Publisher interface {
	SendMessage(ctx context.Context, msg models.Message) error
}
