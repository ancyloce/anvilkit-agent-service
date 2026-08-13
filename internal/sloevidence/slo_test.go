package sloevidence

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEveryBindingSLOHasPinnedUnapprovedDraftEvidence(t *testing.T) {
	definitions := DraftDefinitions()
	if err := ValidateDraft(definitions); err != nil {
		t.Fatal(err)
	}
	want := []string{"availability", "create-latency", "event-visibility", "durable-recovery", "raw-plan-validity", "trace-continuity", "diagnosable-errors-dlq", "stuck-run-detection", "accepted-output-validity", "fake-tool-selection", "workspace-fairness"}
	var got []string
	for _, definition := range definitions {
		got = append(got, definition.ID)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SLO definitions=%#v", got)
	}
}

func TestDashboardAndAlertArtifactsAreCompleteDraftsWithoutPayloads(t *testing.T) {
	dashboard, err := os.ReadFile("../../../../infra/dashboards/agent-service-slo.json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Approval string `json:"approval"`
		Panels   []struct {
			ID string `json:"id"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(dashboard, &parsed); err != nil || parsed.Approval != "pending-gate-h" || len(parsed.Panels) != 11 {
		t.Fatalf("dashboard=%#v err=%v", parsed, err)
	}
	rules, err := os.ReadFile("../../../../infra/alerts/agent-service-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ruleText := strings.ToLower(string(rules))
	for _, alert := range []string{"duplicateeffect", "approvalbypass", "forbiddentool", "crosstenant", "stuckrun", "reservationexposure", "dlqbacklog", "reconciliationage"} {
		if !strings.Contains(strings.ReplaceAll(ruleText, "-", ""), alert) {
			t.Fatalf("alert %s missing", alert)
		}
	}
	for _, prohibited := range []string{"prompt_body", "response_body", "signed_url", "authorization_token"} {
		if strings.Contains(ruleText, prohibited) || strings.Contains(strings.ToLower(string(dashboard)), prohibited) {
			t.Fatalf("prohibited field %s in dashboard/alerts", prohibited)
		}
	}
}

func TestAbsoluteSafetyAlertsFireForEveryInjectionWithoutPayloadFields(t *testing.T) {
	pager := &MemoryPager{}
	monitor, _ := NewSafetyMonitor(pager)
	for _, kind := range []string{"duplicate-effect", "approval-bypass", "forbidden-tool", "cross-tenant", "stale-result", "unauthorized-disclosure"} {
		violation := Violation{Kind: kind, WorkspaceID: "workspace", ProjectID: "project", RunID: "run", TraceID: "trace"}
		if err := monitor.Observe(context.Background(), violation); err != nil {
			t.Fatal(err)
		}
	}
	if len(pager.Values) != 6 {
		t.Fatalf("pages=%#v", pager.Values)
	}
	typeShape := reflect.TypeOf(Violation{})
	for _, prohibited := range []string{"Prompt", "Response", "Content", "Payload", "URL", "Token"} {
		if _, present := typeShape.FieldByName(prohibited); present {
			t.Fatalf("prohibited payload field %s in alert", prohibited)
		}
	}
}
