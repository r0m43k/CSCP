package rules

import (
	"context"
	"testing"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func TestAdditionalContainerRules(t *testing.T) {
	tests := []struct {
		name string
		rule rulekit.Rule
		obj  rulekit.Object
		want int
	}{
		{
			name: "run as root detects missing non-root controls",
			rule: RunAsRootRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
			}),
			want: 1,
		},
		{
			name: "run as root ignores non-root container",
			rule: RunAsRootRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"runAsNonRoot": true,
				},
			}),
			want: 0,
		},
		{
			name: "run as non-root missing detects missing setting",
			rule: RunAsNonRootMissingRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
			}),
			want: 1,
		},
		{
			name: "run as non-root missing ignores pod-level setting",
			rule: RunAsNonRootMissingRule{},
			obj: podWithSpec(map[string]any{
				"securityContext": map[string]any{
					"runAsNonRoot": true,
				},
				"containers": []any{
					map[string]any{
						"name": "app",
					},
				},
			}),
			want: 0,
		},
		{
			name: "hostPID detects enabled setting",
			rule: HostPIDRule{},
			obj: podWithSpec(map[string]any{
				"hostPID": true,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 1,
		},
		{
			name: "hostPID ignores disabled setting",
			rule: HostPIDRule{},
			obj: podWithSpec(map[string]any{
				"hostPID": false,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 0,
		},
		{
			name: "hostIPC detects enabled setting",
			rule: HostIPCRule{},
			obj: podWithSpec(map[string]any{
				"hostIPC": true,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 1,
		},
		{
			name: "hostIPC ignores disabled setting",
			rule: HostIPCRule{},
			obj: podWithSpec(map[string]any{
				"hostIPC": false,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 0,
		},
		{
			name: "hostNetwork detects enabled setting",
			rule: HostNetworkRule{},
			obj: podWithSpec(map[string]any{
				"hostNetwork": true,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 1,
		},
		{
			name: "hostNetwork ignores disabled setting",
			rule: HostNetworkRule{},
			obj: podWithSpec(map[string]any{
				"hostNetwork": false,
				"containers": []any{
					map[string]any{"name": "app"},
				},
			}),
			want: 0,
		},
		{
			name: "image latest detects explicit latest tag",
			rule: ImageLatestTagRule{},
			obj: podWithContainer(map[string]any{
				"name":  "app",
				"image": "nginx:latest",
			}),
			want: 1,
		},
		{
			name: "image latest ignores pinned tag",
			rule: ImageLatestTagRule{},
			obj: podWithContainer(map[string]any{
				"name":  "app",
				"image": "nginx:1.25.3",
			}),
			want: 0,
		},
		{
			name: "dangerous capabilities detects NET_ADMIN",
			rule: DangerousCapabilitiesRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{
						"add": []any{"NET_ADMIN"},
					},
				},
			}),
			want: 1,
		},
		{
			name: "dangerous capabilities ignores safe capability",
			rule: DangerousCapabilitiesRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
				"securityContext": map[string]any{
					"capabilities": map[string]any{
						"add": []any{"CHOWN"},
					},
				},
			}),
			want: 0,
		},
		{
			name: "resource limits detects missing memory limit",
			rule: ResourceLimitsMissingRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
				"resources": map[string]any{
					"limits": map[string]any{
						"cpu": "500m",
					},
				},
			}),
			want: 1,
		},
		{
			name: "resource limits ignores complete limits",
			rule: ResourceLimitsMissingRule{},
			obj: podWithContainer(map[string]any{
				"name": "app",
				"resources": map[string]any{
					"limits": map[string]any{
						"cpu":    "500m",
						"memory": "256Mi",
					},
				},
			}),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := tt.rule.Evaluate(context.Background(), tt.obj, nil)
			if err != nil {
				t.Fatalf("Evaluate returned error: %v", err)
			}

			if len(findings) != tt.want {
				t.Fatalf("expected %d findings, got %d", tt.want, len(findings))
			}
		})
	}
}

func podWithContainer(container map[string]any) rulekit.Object {
	return podWithSpec(map[string]any{
		"containers": []any{container},
	})
}

func podWithSpec(spec map[string]any) rulekit.Object {
	return rulekit.Object{
		Kind:      "Pod",
		Namespace: "default",
		Name:      "test-pod",
		Raw: map[string]any{
			"spec": spec,
		},
	}
}
