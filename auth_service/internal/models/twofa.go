package models

type Action string

const (
	ActionLogin2FA       Action = "login_2fa"
	ActionDisable2FA     Action = "disable_2fa"
	ActionDeleteAccount  Action = "delete_account"
	ActionRestoreAccount Action = "restore_account"
)

// TwoFAStatus состояние 2FA пользователя — используется сервисным слоем,
// чтобы решить, требовать пароль или magic-link код при disable/login-flow.
type TwoFAStatus struct {
	IsEnabled   bool
	Method      *string
	HasPassword bool
}

// PendingSession — состояние логина между успешной проверкой пароля и
// подтверждением второго фактора (magic link).
type PendingSession struct {
	UserID int64
	AppID  int32
	Action Action
}
