-- +goose Up

-- Accounts created through a third-party provider (OAuth) have no local
-- password. The login flow already treats a NULL hash as "no password login";
-- the hash is only ever a bcrypt digest, never a plain password.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- +goose Down

-- Restore the original constraint. This fails if any OAuth-only account
-- (password_hash IS NULL) still exists, which is the safe behaviour: it forces
-- a conscious decision before rolling back.
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
