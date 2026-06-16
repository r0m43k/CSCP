package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type HostIPCRule struct{}

func (r HostIPCRule) ID() string {
	return "K8S-HOST-IPC"
}

func (r HostIPCRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Workload uses hostIPC",
		Description: "Detects workloads that share the host IPC namespace.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Remove hostIPC or set hostIPC to false.",
	}
}

func (r HostIPCRule) Supports(obj rulekit.Object) bool {
	return podSpecFromObject(obj) != nil
}

func (r HostIPCRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	hostIPC, _ := boolValue(podSpecFromObject(obj)["hostIPC"])
	if !hostIPC {
		return nil, nil
	}

	return []rulekit.Finding{newFinding(r, obj, map[string]any{"hostIPC": true})}, nil
}
