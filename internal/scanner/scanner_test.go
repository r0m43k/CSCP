package scanner

import (
	"context"
	"testing"

	"github.com/r0m43k/CSCP/internal/rules"
	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func TestScannerRunsRulesAgainstObjects(t *testing.T) {
	scanner := New([]rulekit.Rule{
		rules.PrivilegedContainerRule{},
	})

	objects := []rulekit.Object{
		{
			Kind:      "Pod",
			Namespace: "default",
			Name:      "dangerous-pod",
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
		},
	}

	findings, err := scanner.Scan(context.Background(), objects)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}
