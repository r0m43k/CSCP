package correlation

import (
	"context"

	"github.com/r0m43k/CSCP/internal/graph"
)

type Engine struct {
	MaxDepth int
}

func New(maxDepth int) *Engine {
	return &Engine{MaxDepth: maxDepth}
}

func (e *Engine) FindAttackPaths(ctx context.Context, g graph.Graph) ([]graph.Path, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}
