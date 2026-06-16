package storage

import (
	"context"

	"github.com/r0m43k/CSCP/internal/findings"
)

type FindingStore interface {
	Upsert(ctx context.Context, record findings.Record) error
}

type Transaction interface {
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}
