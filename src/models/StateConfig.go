package models

import "golang.org/x/oauth2"

type StateConfig struct {
	OauthConfig *oauth2.Config
	Realm       string
}
