package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type ResourceLimitsMissingRule struct{}

func (r ResourceLimitsMissingRule) ID() string {
	return "K8S-RESOURCE-LIMITS-MISSING"
}

func (r ResourceLimitsMissingRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container is missing resource limits",
		Description: "Detects containers without CPU or memory limits.",
		Severity:    rulekit.SeverityMedium,
		Category:    "containers",
		Remediation: "Set resources.limits.cpu and resources.limits.memory for every container.",
	}
}

func (r ResourceLimitsMissingRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r ResourceLimitsMissingRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}

	for _, container := range containersFromObject(obj) {
		missing := missingResourceLimits(container)
		if len(missing) == 0 {
			continue
		}

		findings = append(findings, newFinding(r, obj, map[string]any{
			"containerName": container.Name,
			"missingLimits": missing,
		}))
	}

	return findings, nil
}
