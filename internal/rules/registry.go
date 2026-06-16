package rules
// Registry of all rules
import "github.com/r0m43k/CSCP/pkg/rulekit"


func DefaultRules() []rulekit.Rule {
	return []rulekit.Rule{
		PrivilegedContainerRule{},
		AllowPrivilegeEscalationRule{},
	}
}