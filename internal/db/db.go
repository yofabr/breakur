// Package db opens the Postgres connection and applies pending goose migrations.
package db

import (
	"context"
	"database/sql"

	"breakur/migrations"

	_ "github.com/jackc/pgx/v5/stdlib" // register the "pgx" database/sql driver
	"github.com/pressly/goose/v3"
)

// Open connects to Postgres using the given URL DSN and verifies it with a ping.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Migrate applies every pending migration from the embedded migrations FS.
func Migrate(conn *sql.DB) error {
	goose.SetBaseFS(migrations.FS)
	goose.SetTableName("goose_migrations")
	return goose.Up(conn, ".")
}
