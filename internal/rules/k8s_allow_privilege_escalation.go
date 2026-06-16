package rules

// Tests for PrivilegedContainerRule
import (
	"context"
	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type AllowPrivilegeEscalationRule struct{}

func (r AllowPrivilegeEscalationRule) ID() string {
	return "K8S-ALLOW-PRIVILEGE-ESCALATION"
}

func (r AllowPrivilegeEscalationRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container allows privilege escalation",
		Description: "Detects containers with allowPrivilegeEscalation set enabled",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Set securityContext.allowPrivilegeEscalation to false",
	}
}

func (r AllowPrivilegeEscalationRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r AllowPrivilegeEscalationRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	metadata := r.Metadata()
	findings := []rulekit.Finding{}

	for _, container := range containersFromObject(obj) {
		securityContext := asMap(container.Raw["securityContext"])

		allowPrivilegeEscalation, _ := securityContext["allowPrivilegeEscalation"].(bool)

		if !allowPrivilegeEscalation {
			continue
		}

		findings = append(findings, rulekit.Finding{
			RuleID:      r.ID(),
			Resource:    obj,
			Severity:    metadata.Severity,
			Title:       metadata.Title,
			Description: metadata.Description,
			Evidence: map[string]any{
				"containerName":            container.Name,
				"allowPrivilegeEscalation": true,
			},
			Remediation: metadata.Remediation,
		})
	}
	return findings, nil
}
