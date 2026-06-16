package rulekit

import "context"

// Severity is the normalized risk level for a finding.
type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
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

// Object is a normalized Kubernetes resource checked by scanner rules.
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
