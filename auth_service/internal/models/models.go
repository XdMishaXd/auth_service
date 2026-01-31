package models

import "time"

type User struct {
	ID         int64
	Email      string
	Username   string
	PassHash   []byte
	IsVerified bool
}

type App struct {
	ID     int32
	Name   string
	Secret string
}

type RefreshToken struct {
	TokenHash []byte
	UserID    int64
	AppID     int32
	ExpiresAt time.Time
}

type Message struct {
	Email   string `json:"to"`
	Link    string `json:"link"`
	Purpose string `json:"purpose"`
}

type MagicLink struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	AppID     int        `json:"app_id"`
	TokenHash string     `json:"token_hash"`
	SessionID string     `json:"session_id"`
	IPAddress string     `json:"ip_address"`
	UserAgent string     `json:"user_agent"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// * IsExpired проверяет, истек ли срок действия ссылки
func (m *MagicLink) IsExpired() bool {
	return m.ExpiresAt.Before(time.Now())
}

// * IsActive проверяет, активна ли ссылка (не использована и не истекла)
func (m *MagicLink) IsActive() bool {
	return !m.Used && !m.IsExpired()
}
