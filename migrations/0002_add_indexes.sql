-- +goose Up
-- One index instead of two: serves both FK/cascade lookups on user_id and
-- "my links, newest first" pagination.
DROP INDEX IF EXISTS links_user_id_idx;
CREATE INDEX links_user_id_created_at_idx ON links (user_id, created_at DESC);

-- OAuth login resolves a subject via (provider, provider_user_id); partial
-- because plain profile links leave provider_user_id NULL.
CREATE INDEX user_socials_provider_subject_idx
    ON user_socials (provider, provider_user_id)
    WHERE provider_user_id IS NOT NULL;

-- Admin / chronological listing of signups.
CREATE INDEX users_created_at_idx ON users (created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS users_created_at_idx;
DROP INDEX IF EXISTS user_socials_provider_subject_idx;
DROP INDEX IF EXISTS links_user_id_created_at_idx;
CREATE INDEX links_user_id_idx ON links (user_id);
