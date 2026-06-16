package rules

import (
	"context"
	"testing"
	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func TestPrivilegedContainerRuleDetectsPrivilegedContainer(t *testing.T) {
	rule := PrivilegedContainerRule{}

	obj := rulekit.Object{
		Kind: "Pod",
		Namespace: "default",
		Name: "dangerous-pod",
		Raw: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "app",
						"securityContext": map[string]any{
							"privileged": true,
						},
					},
				},
			},
		},
	}

	findings, err := rule.Evaluate(context.Background(), obj, nil)
	if err != nil {
		t.Fatalf("Evaluate returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(findings))
	}
	
	if findings[0].RuleID != rule.ID() {
		t.Fatalf("Expected rule ID %q, got %q", rule.ID(), findings[0].RuleID)
	}
}