package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/retroruk/centralized-devops-auth/src/services"
)

type SessionController struct {
	sessionService *services.SessionService
}

func InitSessionController(mux *http.ServeMux, sessionService *services.SessionService) {
	c := &SessionController{
		sessionService: sessionService,
	}

	mux.HandleFunc("/api/v1/auth/session/getUserInfo", c.GetUserInfo)
}

func (c SessionController) GetUserInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID param required", http.StatusBadRequest)
		return
	}

	session, err := c.sessionService.GetUserInfo(sessionID)
	if err != nil {
		http.Error(w, "failed to retrieve user info", http.StatusInternalServerError)
		return
	}

	payload := map[string]any{
		"userInfo": session.UserInfo,
		"realm":    session.Realm,
	}

	json.NewEncoder(w).Encode(payload)
}
