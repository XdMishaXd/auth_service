package storage

import "errors"

var (
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrUserNotFound         = errors.New("user not found")
	ErrAppNotFound          = errors.New("app not found")
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	ErrRefreshTokenConflict = errors.New("refresh token has already been rotated")
)
