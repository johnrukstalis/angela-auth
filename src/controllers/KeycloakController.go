package controllers

import (
	"encoding/json"
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
	mux.HandleFunc("/auth/logout", c.logout)
	mux.HandleFunc("/auth/callback/login", c.handleLoginCallback)
	mux.HandleFunc("/auth/session", c.checkSession)
	mux.HandleFunc("/auth/refreshToken", c.refreshToken)
	mux.HandleFunc("/auth/realmExists", c.realmExists)
	mux.HandleFunc("/auth/createRealm", c.createRealm)
	mux.HandleFunc("/auth/createClient", c.createClient)
	mux.HandleFunc("/auth/callback/emailActions", c.handleEmailActionsCallback)
}

func (c KeycloakController) login(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendURL), http.StatusFound)
		return
	}

	session, sessionID, err := c.keycloakService.CreateSession(realm)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendURL), http.StatusFound)
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

func (c KeycloakController) logout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is missing", http.StatusBadRequest)
		return
	}

	if err := c.keycloakService.Logout(sessionID); err != nil {
		http.Error(w, fmt.Sprintf("failed to logout: %v", err), http.StatusInternalServerError)
		return
	}
}

func (c KeycloakController) handleEmailActionsCallback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("%s/auth/callback/emailActions", c.backendURL), http.StatusFound)
}

func (c KeycloakController) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
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

	_, err = c.keycloakService.HandleLoginCallback(sessionID.Value, code)
	if err != nil {
		http.Error(w, "Failed to handle callback: "+err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/auth/callback/login?sessionID=%s", c.backendURL, sessionID.Value), http.StatusFound)
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

	expiresIn, err := c.keycloakService.RefreshTokens(sessionID)
	if err != nil {
		http.Error(w, "failed to refresh token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]int64{"expiresIn": expiresIn})
}

func (c KeycloakController) realmExists(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter is required", http.StatusBadRequest)
		return
	}

	exists, err := c.keycloakService.RealmExists(realm)
	if err != nil {
		http.Error(w, "failed to check if realm exists", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"exists": exists})
}

func (c KeycloakController) createRealm(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter required", http.StatusBadRequest)
		return
	}

	rootUserEmail := r.URL.Query().Get("rootUserEmail")
	if rootUserEmail == "" {
		http.Error(w, "rootUserEmail parameter required", http.StatusBadRequest)
		return
	}

	smtpEmail := r.URL.Query().Get("smtpEmail")
	if smtpEmail == "" {
		http.Error(w, "smtpEmail parameter required", http.StatusBadRequest)
		return
	}

	smtpPassword := r.URL.Query().Get("smtpPassword")
	if smtpPassword == "" {
		http.Error(w, "smtpPassword parameter required", http.StatusBadRequest)
		return
	}

	if err := c.keycloakService.CreateRealm(realm, rootUserEmail, smtpEmail, smtpPassword); err != nil {
		log.Println(err)
		http.Error(w, "failed to create realm", http.StatusInternalServerError)
		return
	}
}

func (c KeycloakController) createClient(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter required", http.StatusBadRequest)
		return
	}

	token, err := c.keycloakService.LoginAsAdmin()
	if err != nil {
		http.Error(w, "failed to login as admin", http.StatusUnauthorized)
		return
	}

	_, err = c.keycloakService.CreateClient(realm, token)
	if err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}
}
