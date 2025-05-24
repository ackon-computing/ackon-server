CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    login VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE clients (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    token VARCHAR(255) NOT NULL,
    pubkey TEXT DEFAULT NULL
);

ALTER TABLE users ADD COLUMN ptu_summ BIGINT NOT NULL DEFAULT 0;
CREATE TABLE users_clients_locks (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    client_id BIGINT NOT NULL,
    ptu_summ INT NOT NULL,
    runners_approvs INT NOT NULL DEFAULT 0,
    locked_at TIMESTAMP WITHOUT TIME ZONE
);

--- BEGIN;
--- UPDATE users SET ptu_summ = ptu_summ - $1 WHERE id = $2;
--- INSERT INTO users_clients_locks (user_id, client_id, ptu_summ, locked_at) VALUES ($2, $3, $1, NOW());
--- COMMIT;

CREATE TABLE coordinators_users (
    id BIGSERIAL PRIMARY KEY,
    login VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE coordinators_nodes (
    id BIGSERIAL PRIMARY KEY,
    coordinators_users_id BIGINT NOT NULL,
    token VARCHAR(255) NOT NULL,
    pubkey TEXT DEFAULT NULL
);
