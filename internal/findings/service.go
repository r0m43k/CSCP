package findings

import (
	"context"
	"time"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type Repository interface {
	Upsert(ctx context.Context, record Record) error
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository) *Service {
	return &Service{
		repository: repository,
		now:        time.Now,
	}
}

func (s *Service) Record(ctx context.Context, clusterID, scanID string, finding rulekit.Finding) (Record, error) {
	now := s.now()
	record := Record{
		ClusterID:   clusterID,
		ScanID:      scanID,
		Finding:     finding,
		Status:      StatusOpen,
		Fingerprint: Fingerprint(clusterID, finding),
		FirstSeen:   now,
		LastSeen:    now,
	}

	if s.repository == nil {
		return record, nil
	}

	return record, s.repository.Upsert(ctx, record)
}
