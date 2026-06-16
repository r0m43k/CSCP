package api

type ClusterConnectionSpec struct {
	ProjectID    string
	Mode         string
	ScanInterval string
	Namespaces   NamespaceSelector
}

type NamespaceSelector struct {
	Include []string
	Exclude []string
}

type ClusterConnection struct {
	Name string
	Spec ClusterConnectionSpec
}

type ScanJobSpec struct {
	ClusterName string
	Full        bool
}

type ScanJob struct {
	Name string
	Spec ScanJobSpec
}

type SecurityPolicySpec struct {
	EnabledRules  []string
	DisabledRules []string
}

type SecurityPolicy struct {
	Name string
	Spec SecurityPolicySpec
}

type RemediationRequestSpec struct {
	FindingID  string
	Repository string
	Branch     string
}

type RemediationRequest struct {
	Name string
	Spec RemediationRequestSpec
}
