package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type DangerousCapabilitiesRule struct{}

func (r DangerousCapabilitiesRule) ID() string {
	return "K8S-DANGEROUS-CAPABILITIES"
}

func (r DangerousCapabilitiesRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container adds dangerous Linux capabilities",
		Description: "Detects containers adding SYS_ADMIN, NET_ADMIN, or SYS_PTRACE.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Remove dangerous capabilities from securityContext.capabilities.add.",
	}
}

func (r DangerousCapabilitiesRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r DangerousCapabilitiesRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}

	for _, container := range containersFromObject(obj) {
		securityContext := asMap(container.Raw["securityContext"])
		capabilities := asMap(securityContext["capabilities"])
		addedCapabilities := stringSliceFromAny(capabilities["add"])
		dangerousCapabilities := containsDangerousCapability(addedCapabilities)
		if len(dangerousCapabilities) == 0 {
			continue
		}

		findings = append(findings, newFinding(r, obj, map[string]any{
			"containerName":         container.Name,
			"dangerousCapabilities": dangerousCapabilities,
		}))
	}

	return findings, nil
}
