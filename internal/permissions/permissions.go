package permissions

import "github.com/r0m43k/CSCP/internal/auth"

type Permission string

const (
	ClusterCreate      Permission = "cluster:create"
	ClusterRead        Permission = "cluster:read"
	ClusterDelete      Permission = "cluster:delete"
	ScanCreate         Permission = "scan:create"
	FindingRead        Permission = "finding:read"
	FindingAcknowledge Permission = "finding:acknowledge"
	FindingSuppress    Permission = "finding:suppress"
	RemediationCreate  Permission = "remediation:create"
	PolicyUpdate       Permission = "policy:update"
	MemberManage       Permission = "member:manage"
)

type Checker struct {
	rolePermissions map[string]map[Permission]struct{}
}

func NewChecker() Checker {
	return Checker{
		rolePermissions: map[string]map[Permission]struct{}{
			"organization-admin": allPermissions(),
			"project-admin": permissionsSet(
				ClusterCreate,
				ClusterRead,
				ClusterDelete,
				ScanCreate,
				FindingRead,
				RemediationCreate,
				PolicyUpdate,
			),
			"security-engineer": permissionsSet(
				FindingRead,
				FindingAcknowledge,
				FindingSuppress,
				RemediationCreate,
			),
			"viewer": permissionsSet(FindingRead, ClusterRead),
		},
	}
}

func (c Checker) Allowed(principal auth.Principal, permission Permission) bool {
	for _, role := range principal.Roles {
		if _, ok := c.rolePermissions[role][permission]; ok {
			return true
		}
	}

	return false
}

func allPermissions() map[Permission]struct{} {
	return permissionsSet(
		ClusterCreate,
		ClusterRead,
		ClusterDelete,
		ScanCreate,
		FindingRead,
		FindingAcknowledge,
		FindingSuppress,
		RemediationCreate,
		PolicyUpdate,
		MemberManage,
	)
}

func permissionsSet(permissions ...Permission) map[Permission]struct{} {
	result := map[Permission]struct{}{}
	for _, permission := range permissions {
		result[permission] = struct{}{}
	}

	return result
}
