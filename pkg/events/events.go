package events

import "time"

type Event struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`
	OrganizationID string         `json:"organizationId"`
	ProjectID      string         `json:"projectId"`
	ClusterID      string         `json:"clusterId"`
	CorrelationID  string         `json:"correlationId"`
	TraceID        string         `json:"traceId"`
	OccurredAt     time.Time      `json:"occurredAt"`
	Payload        map[string]any `json:"payload"`
}

func Key(event Event) string {
	return event.OrganizationID + "/" + event.ProjectID + "/" + event.ClusterID
}
