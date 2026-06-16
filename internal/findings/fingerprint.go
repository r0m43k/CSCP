package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func Fingerprint(clusterID string, finding rulekit.Finding) string {
	normalizedEvidence, _ := json.Marshal(finding.Evidence)
	sum := sha256.Sum256([]byte(clusterID + "|" + finding.Resource.Kind + "|" + finding.Resource.Namespace + "|" + finding.Resource.Name + "|" + finding.RuleID + "|" + string(normalizedEvidence)))
	return hex.EncodeToString(sum[:])
}
