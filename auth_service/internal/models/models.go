package models

import (
	"net"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID         int64
	Email      string
	Username   string
	PassHash   []byte
	IsVerified bool
}

type OAuthAccount struct {
	ID             int64
	UserID         int64
	Provider       string
	ProviderUserID string
	Email          string
	CreatedAt      time.Time
}

type App struct {
	ID     int32
	Name   string
	Secret string
}

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

type Message struct {
	Email   string `json:"to"`
	Link    string `json:"link"`
	Purpose string `json:"purpose"`
}

type SendMagicLinkRequest struct {
	UserID    int64  `json:"user_id"`
	AppID     int32  `json:"app_id"`
	Email     string `json:"email"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
}

type MagicLinkVerificatonResult struct {
	UserID    int64  `json:"user_id"`
	AppID     int32  `json:"app_id"`
	SessionID string `json:"session_id"`
}

type MagicLink struct {
	ID        int64       `json:"id"`
	UserID    int64       `json:"user_id"`
	AppID     int32       `json:"app_id"`
	TokenHash []byte      `json:"token_hash"` // ! token hash дожен быть []byte
	SessionID string      `json:"session_id"`
	IPAddress *net.IPAddr `json:"ip_address"`
	UserAgent *string     `json:"user_agent"`
	Used      bool        `json:"used"`
	UsedAt    *time.Time  `json:"used_at,omitempty"`
	ExpiresAt time.Time   `json:"expires_at"`
	CreatedAt time.Time   `json:"created_at"`
}

// * IsExpired проверяет, истек ли срок действия ссылки
func (m *MagicLink) IsExpired() bool {
	return m.ExpiresAt.Before(time.Now())
}

// * IsActive проверяет, активна ли ссылка (не использована и не истекла)
func (m *MagicLink) IsActive() bool {
	return !m.Used && !m.IsExpired()
}
