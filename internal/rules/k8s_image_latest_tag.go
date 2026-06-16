package rules

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type ImageLatestTagRule struct{}

func (r ImageLatestTagRule) ID() string {
	return "K8S-IMAGE-LATEST-TAG"
}

func (r ImageLatestTagRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container image uses latest tag",
		Description: "Detects containers that use the latest image tag or omit an image tag.",
		Severity:    rulekit.SeverityMedium,
		Category:    "containers",
		Remediation: "Pin container images to an immutable version tag or digest.",
	}
}

func (r ImageLatestTagRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r ImageLatestTagRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}

	for _, container := range containersFromObject(obj) {
		image := asString(container.Raw["image"])
		evidence, usesLatest := latestTagEvidence(image)
		if !usesLatest {
			continue
		}

		evidence["containerName"] = container.Name
		findings = append(findings, newFinding(r, obj, evidence))
	}

	return findings, nil
}
