package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/redis/go-redis/v9"
	"github.com/retroruk/centralized-devops-auth/src/models"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
	"golang.org/x/oauth2"
)

var stateConfig = make(map[string]models.OauthSession)

type KeycloakClient struct {
	config   *models.KeycloakConfig
	verifier *oidc.IDTokenVerifier
}

type KeycloakService struct {
	db      *sql.DB
	rdb     *redis.Client
	baseURL string
	authURL string
}

func InitKeycloakService(db *sql.DB, rdb *redis.Client) *KeycloakService {
	return &KeycloakService{
		db:      db,
		rdb:     rdb,
		baseURL: utilities.GetEnv("KEYCLOAK_BASE_URL"),
		authURL: utilities.GetEnv("AUTH_URL"),
	}
}

func (s KeycloakService) CreateSession(realm string) (models.OauthSession, string, error) {
	oauthConfig := &oauth2.Config{
		RedirectURL: fmt.Sprintf("%s/auth/callback", s.authURL),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1;", realm)

	if err := row.Scan(&oauthConfig.ClientID, &oauthConfig.ClientSecret); err != nil {
		return models.OauthSession{}, "", err
	}

	provider, err := oidc.NewProvider(context.Background(), fmt.Sprintf("%s/realms/%s", s.baseURL, realm))
	if err != nil {
		return models.OauthSession{}, "", err
	}

	oauthConfig.Endpoint = provider.Endpoint()

	sessionID := utilities.GenerateRandomEncodedByteString(32)
	session := models.OauthSession{OauthConfig: oauthConfig, Realm: realm}

	if err := s.SaveSession(sessionID, session, 5*time.Minute); err != nil {
		return models.OauthSession{}, "", err
	}
	return session, sessionID, nil
}

func (s KeycloakService) SaveSession(sessionID string, session models.OauthSession, ttl time.Duration) error {
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := s.rdb.Set(context.Background(), sessionID, sessionBytes, ttl).Err(); err != nil {
		return err
	}

	return nil
}

func (s KeycloakService) GetSession(sessionID string) (models.OauthSession, error) {
	data, err := s.rdb.Get(context.Background(), sessionID).Result()
	if err != nil {
		return models.OauthSession{}, fmt.Errorf("session not found in redis")
	}

	var session models.OauthSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return models.OauthSession{}, fmt.Errorf("failed to unmarshall session data")
	}

	return session, nil
}

func (s KeycloakService) HandleCallback(sessionID string, code string) (string, error) {
	ctx := context.Background()

	session, err := s.GetSession(sessionID)
	if err != nil {
		return sessionID, err
	}

	tokens, err := s.ExchangeCodeForTokens(ctx, sessionID, code)
	if err != nil {
		return sessionID, err
	}

	claims, err := s.GetClaims(ctx, tokens.IDToken, session.Realm)
	if err != nil {
		return sessionID, err
	}

	userInfo, err := s.GetUserInfo(session.Realm, tokens.AccessToken)
	if err != nil {
		return sessionID, err
	}

	session.Tokens = tokens
	session.Claims = claims
	session.UserInfo = userInfo
	session.OauthConfig = nil // set to nil because it's not needed after the callback

	if err := s.SaveSession(sessionID, session, time.Duration(tokens.ExpiresIn*int64(time.Second))); err != nil {
		return sessionID, err
	}

	return sessionID, nil
}

func (s KeycloakService) GetClaims(ctx context.Context, rawIdToken string, realm string) (models.KeycloakClaims, error) {
	var claims models.KeycloakClaims

	idToken, ok := s.ValidateIdToken(ctx, rawIdToken, realm)
	if !ok {
		return claims, fmt.Errorf("could not validate id token")
	}

	if err := idToken.Claims(&claims); err != nil {
		return claims, err
	}

	return claims, nil
}

func (s KeycloakService) ExchangeCodeForTokens(ctx context.Context, sessionID string, code string) (models.KeycloakTokens, error) {
	var tokens models.KeycloakTokens

	session, err := s.GetSession(sessionID)
	if err != nil {
		return tokens, err
	}

	t, err := session.OauthConfig.Exchange(ctx, code)
	if err != nil {
		return tokens, err
	}

	rawIdToken, ok := t.Extra("id_token").(string)
	if !ok {
		return tokens, fmt.Errorf("no raw id token found in token response: %v", err)
	}

	tokens.AccessToken = t.AccessToken
	tokens.ExpiresIn = t.ExpiresIn
	tokens.TokenType = t.TokenType
	tokens.IDToken = rawIdToken
	tokens.TokenType = t.TokenType
	tokens.RefreshToken = t.RefreshToken

	return tokens, nil
}

func (s KeycloakService) GetUserInfo(realm string, accessToken string) (models.KeycloakUserInfo, error) {
	var userInfo models.KeycloakUserInfo

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", s.baseURL, realm)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return userInfo, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return userInfo, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return userInfo, fmt.Errorf("failed to get user info, status: %s", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return userInfo, err
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

func (s KeycloakService) RefreshTokens(sessionID string) (int64, error) {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return -1, err
	}

	var clientID string
	var clientSecret string
	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1", session.Realm)
	if err := row.Scan(&clientID, &clientSecret); err != nil {
		return -1, err
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", session.Tokens.RefreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.baseURL, session.Realm), strings.NewReader(data.Encode()))
	if err != nil {
		return -1, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return -1, fmt.Errorf("failed to refresh token")
	}

	var tokens models.KeycloakTokens
	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		return -1, err
	}

	session.Tokens = tokens

	return session.Tokens.ExpiresIn, s.SaveSession(sessionID, session, time.Duration(session.Tokens.ExpiresIn*int64(time.Second)))
}

func (s KeycloakService) Logout(sessionID string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		return err
	}

	var clientID string
	var clientSecret string
	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1;", session.Realm)
	if err := row.Scan(&clientID, &clientSecret); err != nil {
		return err
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", session.Tokens.RefreshToken)

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", s.baseURL, session.Realm)
	req, _ := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if res.StatusCode != 204 {
		return fmt.Errorf("failed to logout")
	}

	if err := s.rdb.Del(context.Background(), sessionID).Err(); err != nil {
		return err
	}

	return nil
}
