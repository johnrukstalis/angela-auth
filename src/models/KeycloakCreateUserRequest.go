package models

type KeycloakCreateUserRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Enabled  bool   `json:"enabled"`
}
