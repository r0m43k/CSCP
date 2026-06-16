package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/r0m43k/CSCP/pkg/rulekit"
)

func TestWriteJSON(t *testing.T) {
	var buffer bytes.Buffer

	err := WriteJSON(&buffer, []rulekit.Finding{
		{
			RuleID:   "TEST-RULE",
			Severity: rulekit.SeverityHigh,
		},
	})
	if err != nil {
		t.Fatalf("WriteJSON returned error: %v", err)
	}

	var decoded JSONReport
	if err := json.Unmarshal(buffer.Bytes(), &decoded); err != nil {
		t.Fatalf("json report is invalid: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
}
