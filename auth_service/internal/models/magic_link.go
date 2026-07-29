package models

import "time"

type Message struct {
	Email   string `json:"to"`
	Link    string `json:"link"`
	Purpose string `json:"purpose"`
}

type SendMagicLinkRequest struct {
	UserID int64  `json:"user_id"`
	AppID  int32  `json:"app_id"`
	Email  string `json:"email"`
}

type MagicLinkVerificationResult struct {
	UserID    int64  `json:"user_id"`
	AppID     int32  `json:"app_id"`
	SessionID string `json:"session_id"`
}

type MagicLink struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	AppID     int32      `json:"app_id"`
	TokenHash []byte     `json:"token_hash"`
	SessionID string     `json:"session_id"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// IsExpired проверяет, истек ли срок действия ссылки
func (m *MagicLink) IsExpired() bool {
	return m.ExpiresAt.Before(time.Now())
}

// IsActive проверяет, активна ли ссылка (не использована и не истекла)
func (m *MagicLink) IsActive() bool {
	return !m.Used && !m.IsExpired()
}
