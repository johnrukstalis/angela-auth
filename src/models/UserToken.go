package models

type UserToken struct {
	AccessToken string
	ExpiresIn   int64
	TokenType   string
	User        User
}

type User struct {
	Username     string
	Email        string
	RealmAccess  []string
	ClientAccess []string
}
