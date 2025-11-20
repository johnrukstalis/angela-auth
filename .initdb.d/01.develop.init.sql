CREATE TABLE IF NOT EXISTS keycloak (
    id BIGSERIAL PRIMARY KEY,
    realm VARCHAR(50),
    client_id VARCHAR(50),
    client_secret VARCHAR(100)
);