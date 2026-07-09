package models

type EmailMessage struct {
	Email       string `json:"to"`
	MessageText string `json:"link"`
	Purpose     string `json:"purpose"`
}
