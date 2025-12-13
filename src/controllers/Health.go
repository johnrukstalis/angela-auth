package controllers

import (
	"encoding/json"
	"net/http"
)

type HealthController struct {
}

func InitHealthController(mux *http.ServeMux) *HealthController {
	c := &HealthController{}

	mux.HandleFunc("/health", c.health)

	return c
}

func (c *HealthController) health(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{
		"status": "OK",
	})
}
