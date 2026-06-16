package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type RunAsNonRootMissingRule struct{}

func (r RunAsNonRootMissingRule) ID() string {
	return "K8S-RUN-AS-NON-ROOT-MISSING"
}

func (r RunAsNonRootMissingRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container does not require non-root execution",
		Description: "Detects containers without securityContext.runAsNonRoot set to true.",
		Severity:    rulekit.SeverityMedium,
		Category:    "containers",
		Remediation: "Set securityContext.runAsNonRoot to true at the pod or container level.",
	}
}

func (r RunAsNonRootMissingRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r RunAsNonRootMissingRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}
	podSecurityContext := asMap(podSpecFromObject(obj)["securityContext"])
	podRunAsNonRoot, podHasRunAsNonRoot := boolValue(podSecurityContext["runAsNonRoot"])

	for _, container := range containersFromObject(obj) {
		containerSecurityContext := asMap(container.Raw["securityContext"])
		containerRunAsNonRoot, containerHasRunAsNonRoot := boolValue(containerSecurityContext["runAsNonRoot"])

		if containerHasRunAsNonRoot && containerRunAsNonRoot {
			continue
		}

		if !containerHasRunAsNonRoot && podHasRunAsNonRoot && podRunAsNonRoot {
			continue
		}

		findings = append(findings, newFinding(r, obj, containerEvidence(container, "runAsNonRoot", false)))
	}

	return findings, nil
}
