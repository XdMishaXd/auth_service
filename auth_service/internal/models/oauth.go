package models

import "time"

type OAuthAccount struct {
	ID             int64
	UserID         int64
	Provider       string
	ProviderUserID string
	Email          string
	CreatedAt      time.Time
}
