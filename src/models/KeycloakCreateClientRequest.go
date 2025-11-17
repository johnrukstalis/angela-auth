package models

type KeycloakCreateClientRequest struct {
	ClientID                  string   `json:"clientId"`
	Secret                    string   `json:"secret"`
	Protocol                  string   `json:"protocol"`
	PublicClient              bool     `json:"publicClient"`
	RedirectURIs              []string `json:"redirectUris"`
	StandardFlowEnabled       bool     `json:"standardFlowEnabled"`
	DirectAccessGrantsEnabled bool     `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool     `json:"serviceAccountsEnabled"`
	RootURL                   string   `json:"rootUrl"`
}
