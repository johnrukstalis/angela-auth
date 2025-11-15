package controllers

import (
	"fmt"
	"log"
	"net/http"

	"github.com/retroruk/centralized-devops-auth/src/services"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
)

type KeycloakController struct {
	keycloakService *services.KeycloakService
	backendURL      string
}

func InitKeycloakController(mux *http.ServeMux, keycloakService *services.KeycloakService) {
	c := &KeycloakController{
		keycloakService: keycloakService,
		backendURL:      utilities.GetEnv("BACKEND_ORCHESTRATOR_URL"),
	}

	mux.HandleFunc("/auth/login", c.login)
	mux.HandleFunc("/auth/callback", c.handleCallback)
	mux.HandleFunc("/auth/session", c.checkSession)
	mux.HandleFunc("/auth/refreshToken", c.refreshToken)
}

func (c KeycloakController) login(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter is required", http.StatusBadRequest)
		return
	}

	session, sessionID, err := c.keycloakService.CreateSession(realm)
	if err != nil {
		http.Error(w, "failed to create authenication session", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "sessionID",
		Value:    sessionID,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	url := session.OauthConfig.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusFound)
}

func (c KeycloakController) handleCallback(w http.ResponseWriter, r *http.Request) {
	sessionID, err := r.Cookie("sessionID")
	if err != nil {
		http.Error(w, "Missing state cookie", http.StatusBadRequest)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:   "sessionID",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	if r.URL.Query().Get("state") != sessionID.Value {
		http.Error(w, "Invalid sessionID", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing keycloak code", http.StatusBadRequest)
		return
	}

	_, err = c.keycloakService.HandleCallback(sessionID.Value, code)
	if err != nil {
		http.Error(w, "Failed to handle callback: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/auth/success?sessionID=%s", c.backendURL, sessionID.Value), http.StatusFound)
}

func (c KeycloakController) checkSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is required", http.StatusBadRequest)
		return
	}

	_, err := c.keycloakService.GetSession(sessionID)
	if err != nil {
		http.Error(w, "no session exists", http.StatusUnauthorized)
		return
	}
}

func (c KeycloakController) refreshToken(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is required", http.StatusBadRequest)
		return
	}

	if err := c.keycloakService.RefreshTokens(sessionID); err != nil {
		http.Error(w, "failed to refresh token", http.StatusInternalServerError)
		return
	}

	log.Println("refreshed token")
}
