package models

import "time"

type User struct {
	ID         int64
	Email      string
	Username   string
	PassHash   []byte
	IsVerified bool
	DeletedAt  *time.Time
}
