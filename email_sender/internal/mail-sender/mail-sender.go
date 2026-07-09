package mailSender

import "gopkg.in/gomail.v2"

type Mailer struct {
	Host     string
	Port     int
	Username string
	Password string
}

func (m *Mailer) Send(to, from, body, purpose string) error {
	msg := gomail.NewMessage()
	msg.SetHeader("To", to)
	msg.SetHeader("From", m.Username)

	switch {
	case purpose == "reset_password":
		msg.SetHeader("Subject", "Сброс пароля")
	case purpose == "email_verification":
		msg.SetHeader("Subject", "Подтверждение почты")
	}

	msg.SetBody("text/plain", body)

	dialer := gomail.NewDialer(m.Host, m.Port, m.Username, m.Password)
	return dialer.DialAndSend(msg)
}
