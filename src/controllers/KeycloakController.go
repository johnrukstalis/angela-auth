package controllers

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/retroruk/centralized-devops-auth/src/services"
)

type KeycloakController struct {
	keycloakService *services.KeycloakService
}

func InitKeycloakController(mux *http.ServeMux, keycloakService *services.KeycloakService) {
	c := &KeycloakController{
		keycloakService: keycloakService,
	}

	mux.HandleFunc("/auth/login", c.login)
	mux.HandleFunc("/auth/callback", c.handleCallback)
}

func (c KeycloakController) login(w http.ResponseWriter, r *http.Request) {
	log.Println("Attempting login")

	realm := r.URL.Query().Get("realm")

	oauthConfig, state, err := c.keycloakService.GetConfig(realm)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := oauthConfig.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusFound)
	log.Println("redirected login")
}

func (c KeycloakController) handleCallback(w http.ResponseWriter, r *http.Request) {
	log.Println("got callback")
	state, err := r.Cookie("oauth_state")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing keycloak code", http.StatusBadRequest)
		return
	}

	userToken, err := c.keycloakService.HandleCallback(state.Value, code)
	if err != nil {
		http.Error(w, "Failed to handle callback: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/auth/success?access_token=%s", os.Getenv("BACKEND_URL"), userToken.AccessToken), http.StatusFound)
	log.Println("redirected callback")
}
