package models

import "golang.org/x/oauth2"

type OauthSession struct {
	OauthConfig *oauth2.Config
	Tokens      KeycloakTokens
	Claims      KeycloakClaims
	UserInfo    KeycloakUserInfo
	Realm       string
}
