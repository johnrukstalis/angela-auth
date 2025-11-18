package models

type CreateRealmRequest struct {
	Realm        string `json:"realm"`
	Email        string `json:"email"`
	SmtpEmail    string `json:"stmpEmail"`
	SmtpPassword string `json:"stmpPassword"`
}
