package auth

import "context"

type Principal struct {
	Subject        string
	OrganizationID string
	ProjectID      string
	Roles          []string
}

type TokenVerifier interface {
	Verify(ctx context.Context, token string) (Principal, error)
}

type StaticVerifier struct {
	Principal Principal
}

func (v StaticVerifier) Verify(ctx context.Context, token string) (Principal, error) {
	if err := ctx.Err(); err != nil {
		return Principal{}, err
	}

	return v.Principal, nil
}
