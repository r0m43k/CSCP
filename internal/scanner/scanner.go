package scanner

import (
	"context"
	"fmt"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type Scanner struct {
	rules []rulekit.Rule
}

func New(rules []rulekit.Rule) *Scanner {
	return &Scanner{
		rules: rules,
	}
}

func (s *Scanner) Scan(ctx context.Context, objects []rulekit.Object) ([]rulekit.Finding, error) {
	findings := []rulekit.Finding{}

	for _, obj := range objects {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		for _, rule := range s.rules {
			if !rule.Supports(obj) {
				continue
			}

			ruleFindings, err := rule.Evaluate(ctx, obj, nil)
			if err != nil {
				return nil, fmt.Errorf("evaluate rule %s on %s/%s: %w", rule.ID(), obj.Kind, obj.Name, err)
			}

			findings = append(findings, ruleFindings...)
		}
	}

	return findings, nil
}
