package findings

import (
	"time"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type Status string

const (
	StatusOpen               Status = "OPEN"
	StatusAcknowledged       Status = "ACKNOWLEDGED"
	StatusSuppressed         Status = "SUPPRESSED"
	StatusRemediationPending Status = "REMEDIATION_PENDING"
	StatusResolved           Status = "RESOLVED"
	StatusReopened           Status = "REOPENED"
)

type Record struct {
	ID          string
	ClusterID   string
	ScanID      string
	Finding     rulekit.Finding
	Status      Status
	Fingerprint string
	FirstSeen   time.Time
	LastSeen    time.Time
}
