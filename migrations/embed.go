// Package migrations exposes the goose SQL migrations compiled into the binary.
package migrations

import "embed"

// FS holds every versioned .sql file in this directory.
//
//go:embed *.sql
var FS embed.FS
