package services

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/redis/go-redis/v9"
	"github.com/retroruk/centralized-devops-auth/src/models"
)

type SessionService struct {
	db  *sql.DB
	rdb *redis.Client
}

func InitSessionService(db *sql.DB, rdb *redis.Client) *SessionService {
	return &SessionService{
		db:  db,
		rdb: rdb,
	}
}

func (s SessionService) GetUserInfo(sessionID string) (models.OauthSession, error) {
	var session models.OauthSession

	sessionStr, err := s.rdb.Get(context.Background(), sessionID).Result()
	if err != nil {
		return session, err
	}

	if err := json.Unmarshal([]byte(sessionStr), &session); err != nil {
		return session, err
	}

	return session, nil
}
