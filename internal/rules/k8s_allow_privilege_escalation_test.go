package rules

import (
	"context"
	"testing"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func TestAllowPrivilegeEscalationRuleDetectsEnabledSetting(t *testing.T) {
	rule := AllowPrivilegeEscalationRule{}

	obj := rulekit.Object{
		Kind:      "Pod",
		Namespace: "default",
		Name:      "dangerous-pod",
		Raw: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "app",
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": true,
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
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestAllowPrivilegeEscalationRuleIgnoresDisabledSetting(t *testing.T) {
	rule := AllowPrivilegeEscalationRule{}

	obj := rulekit.Object{
		Kind:      "Pod",
		Namespace: "default",
		Name:      "safe-pod",
		Raw: map[string]any{
			"spec": map[string]any{
				"containers": []any{
					map[string]any{
						"name": "app",
						"securityContext": map[string]any{
							"allowPrivilegeEscalation": false,
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

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}
