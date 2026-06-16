package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type HostPIDRule struct{}

func (r HostPIDRule) ID() string {
	return "K8S-HOST-PID"
}

func (r HostPIDRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Workload uses hostPID",
		Description: "Detects workloads that share the host process namespace.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Remove hostPID or set hostPID to false.",
	}
}

func (r HostPIDRule) Supports(obj rulekit.Object) bool {
	return podSpecFromObject(obj) != nil
}

func (r HostPIDRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	hostPID, _ := boolValue(podSpecFromObject(obj)["hostPID"])
	if !hostPID {
		return nil, nil
	}

	return []rulekit.Finding{newFinding(r, obj, map[string]any{"hostPID": true})}, nil
}
