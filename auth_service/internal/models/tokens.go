package models

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID        uuid.UUID
	TokenHash []byte
	UserID    int64
	AppID     int32
	ExpiresAt time.Time
}

type ResetToken struct {
	ID        uuid.UUID
	TokenHash []byte
	UserID    int64
	UsedAt    *time.Time
	ExpiresAt time.Time
}
