package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

type JSONReport struct {
	GeneratedAt time.Time         `json:"generatedAt"`
	Findings    []rulekit.Finding `json:"findings"`
}

func WriteJSON(w io.Writer, findings []rulekit.Finding) error {
	report := JSONReport{
		GeneratedAt: time.Now().UTC(),
		Findings:    findings,
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}
