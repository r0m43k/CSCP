package rulekit
import "context" // context cancellation

type Severity string
//ограничение возможными значениями константами чтобы в коде было понятнее и безопаснее
const (
	SeverityLow     Severity = "Low"
	SeverityMedium  Severity = "Medium"
	SeverityHigh    Severity = "High"
	SeverityCritical Severity = "Critical"
)

type Rule interface {
	ID() string
	Metadata() RuleMetadata
	Supports(obj Object) bool
	Evaluate(ctx context.Context, obj Object, graph ResourceGraph) ([]Finding, error)
}
// Описание security rule
type RuleMetadata struct {
	ID          string
	Title       string
	Description string
	Severity    Severity
	Category    string
	Remediation string
}
//нормализованный Kubernetes-объект, который scanner будет проверять
type Object struct {
	Kind      string
	Namespace string
	Name      string
	Raw       map[string]any
}

type ResourceGraph interface{}

type Finding struct {
	RuleID      string
	Resource    Object
	Severity    Severity
	Title       string
	Description string
	Evidence    map[string]any
	Remediation string
}

