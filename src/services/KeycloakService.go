package services

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/retroruk/centralized-devops-auth/src/models"
	"golang.org/x/oauth2"
)

var stateConfig = make(map[string]models.StateConfig)

type KeycloakClient struct {
	config   *models.KeycloakConfig
	verifier *oidc.IDTokenVerifier
}

type KeycloakService struct {
	db      *sql.DB
	baseURL string
}

func InitKeycloakService(db *sql.DB) *KeycloakService {
	return &KeycloakService{
		db:      db,
		baseURL: os.Getenv("KEYCLOAK_BASE_URL"),
	}
}

func (s KeycloakService) GenerateState() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (s KeycloakService) GetConfig(realm string) (*oauth2.Config, string, error) {
	oauthConfig := &oauth2.Config{
		RedirectURL: fmt.Sprintf("http://localhost:5001/auth/callback"),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1;", realm)

	if err := row.Scan(&oauthConfig.ClientID, &oauthConfig.ClientSecret); err != nil {
		return oauthConfig, "", err
	}

	provider, err := oidc.NewProvider(context.Background(), fmt.Sprintf("%s/realms/%s", s.baseURL, realm))
	if err != nil {
		return oauthConfig, "", err
	}

	oauthConfig.Endpoint = provider.Endpoint()

	state := s.GenerateState()
	stateConfig[state] = models.StateConfig{OauthConfig: oauthConfig, Realm: realm}

	return oauthConfig, state, nil
}

func (s KeycloakService) GetStateConfig(state string) (models.StateConfig, error) {
	config, exists := stateConfig[state]
	if exists {
		return config, nil
	} else {
		return models.StateConfig{}, fmt.Errorf("state config does not exists")
	}
}

func (s KeycloakService) HandleCallback(state string, code string) (models.UserToken, error) {
	ctx := context.Background()

	var userToken models.UserToken

	oauthConfig, err := s.GetStateConfig(state)
	if err != nil {
		return userToken, err
	}

	token, err := oauthConfig.OauthConfig.Exchange(ctx, code)
	if err != nil {
		return userToken, err
	}

	rawIdToken, ok := token.Extra("id_token").(string)
	if !ok {
		return userToken, fmt.Errorf("no raw id token found in token response: %v", err)
	}

	idToken, ok := s.ValidateIdToken(ctx, rawIdToken, oauthConfig.Realm)
	if !ok {
		return userToken, err
	}

	var claim models.KeycloakClaim
	if err := idToken.Claims(&claim); err != nil {
		return userToken, err
	}

	userInfo, err := s.GetUserInfo(token.AccessToken, oauthConfig.Realm)
	if err != nil {
		return userToken, err
	}

	userToken.AccessToken = token.AccessToken
	userToken.ExpiresIn = token.ExpiresIn
	userToken.TokenType = token.TokenType
	userToken.User.Email = userInfo.Email
	userToken.User.Username = userInfo.PreferredUsername

	if userInfo.RealmAccess.Roles == nil {
		userToken.User.RealmAccess = []string{}
	} else {
		userToken.User.RealmAccess = userInfo.RealmAccess.Roles
	}

	if userInfo.ResourceAccess[oauthConfig.Realm+"-main"].Roles == nil {
		userToken.User.ClientAccess = []string{}
	} else {
		userToken.User.ClientAccess = userInfo.ResourceAccess[oauthConfig.Realm+"-main"].Roles
	}

	return userToken, nil
}

func (s KeycloakService) GetUserInfo(accessToken string, realm string) (models.KeycloakUserInfo, error) {
	var userInfo models.KeycloakUserInfo

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", s.baseURL, realm)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return userInfo, nil
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return userInfo, nil
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Println("ERROR GETTING USER INFO", body)
		return userInfo, nil
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return userInfo, nil
	}

	return userInfo, nil
}

func (s KeycloakService) ValidateIdToken(ctx context.Context, rawIdToken string, realm string) (*oidc.IDToken, bool) {
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/realms/%s", s.baseURL, realm))
	if err != nil {
		return nil, false
	}

	row := s.db.QueryRow("SELECT client_id FROM keycloak WHERE realm = $1", realm)
	var clientID string
	if err := row.Scan(&clientID); err != nil {
		return nil, false
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:          clientID,
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
	})

	idToken, err := verifier.Verify(ctx, rawIdToken)
	if err != nil {
		return nil, false
	}

	return idToken, true
}
