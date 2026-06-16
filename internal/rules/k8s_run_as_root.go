package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type RunAsRootRule struct{}

func (r RunAsRootRule) ID() string {
	return "K8S-RUN-AS-ROOT"
}

func (r RunAsRootRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container can run as root",
		Description: "Detects containers that explicitly run as root or do not enforce non-root execution.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Set securityContext.runAsNonRoot to true and use a non-zero runAsUser.",
	}
}

func (r RunAsRootRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r RunAsRootRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}
	podSecurityContext := asMap(podSpecFromObject(obj)["securityContext"])

	for _, container := range containersFromObject(obj) {
		containerSecurityContext := asMap(container.Raw["securityContext"])
		reason, canRunAsRoot := rootReason(containerSecurityContext, podSecurityContext)
		if !canRunAsRoot {
			continue
		}

		findings = append(findings, newFinding(r, obj, map[string]any{
			"containerName": container.Name,
			"reason":        reason,
		}))
	}

	return findings, nil
}
