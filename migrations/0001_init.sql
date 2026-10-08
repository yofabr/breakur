-- +goose Up
-- +goose StatementBegin
CREATE EXTENSION IF NOT EXISTS citext; -- case-insensitive text for username/email

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------
CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name          TEXT        NOT NULL,
    username      CITEXT      NOT NULL,
    email         CITEXT      NOT NULL,
    password_hash TEXT        NOT NULL, -- bcrypt/argon2 hash, never the plain password
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT users_username_key  UNIQUE (username),
    CONSTRAINT users_email_key     UNIQUE (email),
    CONSTRAINT users_username_fmt  CHECK (username ~ '^[a-z0-9_]{3,32}$'),
    CONSTRAINT users_email_fmt     CHECK (email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$')
);

-- ---------------------------------------------------------------------------
-- Linked socials: OAuth identities the user connected AND/OR public social
-- profile links they want shown on their page.
-- ---------------------------------------------------------------------------
CREATE TABLE user_socials (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id          BIGINT      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    provider         TEXT        NOT NULL, -- 'github', 'google', 'x', 'instagram', ...
    url              TEXT,                 -- public profile link, e.g. https://github.com/foo
    provider_user_id TEXT,                 -- subject/id returned by the provider (OAuth only)
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT user_socials_provider_key UNIQUE (user_id, provider),
    CONSTRAINT user_socials_provider_fmt CHECK (provider ~ '^[a-z0-9_]{2,32}$')
);

-- ---------------------------------------------------------------------------
-- Links: one row per short link
-- ---------------------------------------------------------------------------
CREATE TABLE links (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id       BIGINT REFERENCES users (id) ON DELETE SET NULL, -- NULL = anonymous link
    url           TEXT        NOT NULL, -- the long destination URL
    short_code    TEXT        NOT NULL, -- the short id, e.g. "abc123"
    -- Full short URL. Change the base domain here to match your deployment.
    shortened_url TEXT        GENERATED ALWAYS AS ('https://breakur.app/' || short_code) STORED,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT links_short_code_key UNIQUE (short_code),
    CONSTRAINT links_url_fmt        CHECK (url ~* '^https?://'),
    CONSTRAINT links_short_code_fmt CHECK (short_code ~ '^[A-Za-z0-9_-]{1,64}$')
);

CREATE INDEX links_user_id_idx    ON links (user_id);
CREATE INDEX links_created_at_idx ON links (created_at DESC);

-- ---------------------------------------------------------------------------
-- Keep updated_at fresh on UPDATE
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER links_updated_at BEFORE UPDATE ON links
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS links_updated_at ON links;
DROP TRIGGER IF EXISTS users_updated_at ON users;
DROP FUNCTION IF EXISTS set_updated_at();
DROP TABLE IF EXISTS links;
DROP TABLE IF EXISTS user_socials;
DROP TABLE IF EXISTS users;
