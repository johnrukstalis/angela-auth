package models

type KeycloakConfig struct {
	URL          string
	RedirectURL  string
	Realm        string
	ClientID     string
	ClientSecret string
}
