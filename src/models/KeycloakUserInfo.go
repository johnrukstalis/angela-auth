package models

type KeycloakUserInfo struct {
	Email             string                    `json:"email"`
	EmailVerified     bool                      `json:"email_verified"`
	FamilyName        string                    `json:"family_name"`
	GivenName         string                    `json:"given_name"`
	Name              string                    `json:"name"`
	PreferredUsername string                    `json:"preferred_username"`
	RealmAccess       RealmAccess               `json:"realm_access"`
	ResourceAccess    map[string]ResourceAccess `json:"resource_access"`
	Sub               string                    `json:"sub"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
}

type ResourceAccess struct {
	Roles []string `json:"roles"`
}
