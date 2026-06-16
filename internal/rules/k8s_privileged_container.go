package rules
// Detects if a container is running in privileged mode
import (
	"context"
	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type PrivilegedContainerRule struct{}

func (r PrivilegedContainerRule) ID() string {
	return "K8S-PRIVILEGED-CONTAINER"
}

func (r PrivilegedContainerRule) Metadata() rulekit.RuleMetadata {
	return rulekit.RuleMetadata{
		ID:          r.ID(),
		Title:       "Container runs in privileged mode",
		Description: "Detects if a container is running in privileged mode.",
		Severity:    rulekit.SeverityHigh,
		Category:    "containers",
		Remediation: "Set securityContext.privileged to false",
	}
}

func (r PrivilegedContainerRule) Supports(obj rulekit.Object) bool {
	return len(containersFromObject(obj)) > 0
}

func (r PrivilegedContainerRule) Evaluate(ctx context.Context, obj rulekit.Object, graph rulekit.ResourceGraph) ([]rulekit.Finding, error) {
  metadata := r.Metadata()
  findings := []rulekit.Finding{}

  for _, container := range containersFromObject(obj) {
	securityContext := asMap(container.Raw["securityContext"])
	
	privileged, _ := securityContext["privileged"].(bool)
	
	if !privileged {
		continue
	}

	findings = append(findings, rulekit.Finding{
		RuleID:      r.ID(),
		Resource:    obj,
	Severity:    metadata.Severity,
		Title:       metadata.Title,
		Description: metadata.Description,
		Evidence: map[string]any{
			"containerName": container.Name,
			"privileged":    true,
		},
		Remediation: metadata.Remediation,
	}) 
	}

	return findings, nil
}
