package remediation

import (
	"context"

	"github.com/r0m43k/CSCP/internal/findings"
)

type Request struct {
	Finding    findings.Record
	Repository string
	Branch     string
}

type Patch struct {
	Path      string
	Operation string
	Value     any
}

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Generate(ctx context.Context, request Request) ([]Patch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}
