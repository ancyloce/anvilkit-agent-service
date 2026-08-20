package sloevidence

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
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

// The dashboard and alert artifacts the service is accountable for are kept
// as tracked test data inside this repository, so the invariant is verifiable
// from a clean checkout of the service alone. When the whole workspace is
// present the platform copies are additionally compared byte for byte, so the
// two can never drift apart unnoticed.
func TestDashboardAndAlertArtifactsAreCompleteDraftsWithoutPayloads(t *testing.T) {
	dashboard, err := os.ReadFile("testdata/dashboard.json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Approval string `json:"approval"`
		Panels   []struct {
			ID, Objective, Query, Denominator, Exclusions, Paging string
		} `json:"panels"`
	}
	if err := json.Unmarshal(dashboard, &parsed); err != nil || parsed.Approval != "pending-gate-h" || len(parsed.Panels) != 11 {
		t.Fatalf("dashboard=%#v err=%v", parsed, err)
	}
	definitions := DraftDefinitions()
	for index, panel := range parsed.Panels {
		definition := definitions[index]
		if panel.ID != definition.ID || panel.Objective != definition.Objective || panel.Query != definition.Query || panel.Denominator != definition.Denominator || panel.Exclusions != definition.Exclusions || panel.Paging != definition.Paging {
			t.Fatalf("dashboard panel drift index=%d panel=%#v definition=%#v", index, panel, definition)
		}
	}
	rules, err := os.ReadFile("testdata/alert-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ruleText := strings.ToLower(string(rules))
	for _, alert := range []string{"duplicateeffect", "approvalbypass", "forbiddentool", "crosstenant", "staleresult", "unauthorizeddisclosure", "stuckrun", "reservationexposure", "dlqbacklog", "reconciliationage"} {
		if !strings.Contains(strings.ReplaceAll(ruleText, "-", ""), alert) {
			t.Fatalf("alert %s missing", alert)
		}
	}
	for _, prohibited := range []string{"prompt_body", "response_body", "signed_url", "authorization_token"} {
		if strings.Contains(ruleText, prohibited) || strings.Contains(strings.ToLower(string(dashboard)), prohibited) {
			t.Fatalf("prohibited field %s in dashboard/alerts", prohibited)
		}
	}
	assertPlatformCopyMatches(t, "../../../../infra/dashboards/agent-service-slo.json", dashboard)
	assertPlatformCopyMatches(t, "../../../../infra/alerts/agent-service-rules.yaml", rules)
}

// assertPlatformCopyMatches compares the tracked service artifact with the
// deployed platform copy when the surrounding workspace is checked out. A
// missing platform tree is not a failure — the service must verify from its
// own checkout — but a present, different copy is.
func assertPlatformCopyMatches(t *testing.T, path string, tracked []byte) {
	t.Helper()
	deployed, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(deployed, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(tracked, []byte("\r\n"), []byte("\n"))) {
		t.Fatalf("the deployed copy of %s has drifted from the tracked service artifact", path)
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
