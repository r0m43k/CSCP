package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type HostNetworkRule struct{}

func (r HostNetworkRule) ID() string {
	return "K8S-HOST-NETWORK"
}

func (r HostNetworkRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Workload uses hostNetwork",
		Description: "Detects workloads that share the host network namespace.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Remove hostNetwork or set hostNetwork to false.",
	}
}

func (r HostNetworkRule) Supports(obj rulekit.Object) bool {
	return podSpecFromObject(obj) != nil
}

func (r HostNetworkRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	hostNetwork, _ := boolValue(podSpecFromObject(obj)["hostNetwork"])
	if !hostNetwork {
		return nil, nil
	}

	return []rulekit.Finding{newFinding(r, obj, map[string]any{"hostNetwork": true})}, nil
}
