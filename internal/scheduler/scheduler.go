package scheduler

import (
	"context"
	"time"
)

type Job struct {
	ID        string
	ClusterID string
	RunAt     time.Time
}

type Scheduler struct{}

func New() *Scheduler {
	return &Scheduler{}
}

func (s *Scheduler) Due(ctx context.Context, now time.Time) ([]Job, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return nil, nil
}
