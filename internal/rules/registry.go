package rules

import "github.com/r0m43k/CSCP/pkg/rulekit"

func DefaultRules() []rulekit.Rule {
	return []rulekit.Rule{
		PrivilegedContainerRule{},
		AllowPrivilegeEscalationRule{},
		RunAsRootRule{},
		RunAsNonRootMissingRule{},
		HostPIDRule{},
		HostIPCRule{},
		HostNetworkRule{},
		ImageLatestTagRule{},
		DangerousCapabilitiesRule{},
		ResourceLimitsMissingRule{},
	}
}
