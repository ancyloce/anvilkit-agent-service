package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/canonical"
)

// call issues one authenticated request to the service.
func (top *topology) call(token, method, path, key, etag string, body []byte) (*http.Response, []byte) {
	top.t.Helper()
	request, err := http.NewRequestWithContext(top.ctx, method, top.service.url+path, bytes.NewReader(body))
	if err != nil {
		top.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("traceparent", top.trace)
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	if body != nil {
		digest, err := canonical.Digest(body)
		if err != nil {
			top.t.Fatal(err)
		}
		request.Header.Set("X-AnvilKit-Request-Digest", digest)
	}
	response, err := top.client.Do(request)
	if err != nil {
		top.t.Fatal(err)
	}
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		top.t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		top.t.Fatal(err)
	}
	return response, payload
}

func (top *topology) actor(method, path, key, etag string, body []byte) (*http.Response, []byte) {
	return top.call(top.bearers.actor, method, path, key, etag, body)
}

// createRun starts one page-change run and returns its run path.
func (top *topology) createRun(idempotencyKey, userInput string) string {
	top.t.Helper()
	body := []byte(`{"kind":"CreateAgentRunRequest","definition":{"definitionId":"` + top.service.definitionID + `","definitionDigest":"` + top.service.definitionDigest +
		`"},"operation":"page-change","target":{"targetType":"page","targetId":"page-cross-001","workspaceId":"workspace","projectId":"project"},"input":{"userInput":"` + userInput + `"}}`)
	created, payload := top.actor(http.MethodPost, "/v1/workspaces/workspace/agent-runs", idempotencyKey, "", body)
	if created.StatusCode != http.StatusCreated {
		top.t.Fatalf("create status=%d body=%s", created.StatusCode, payload)
	}
	var run struct {
		RunID string `json:"runId"`
	}
	if err := json.Unmarshal(payload, &run); err != nil || run.RunID == "" {
		top.t.Fatalf("created run undecodable: %v %s", err, payload)
	}
	return "/v1/workspaces/workspace/agent-runs/" + run.RunID
}

func runIDOf(runPath string) string {
	parts := strings.Split(runPath, "/")
	return parts[len(parts)-1]
}

// currentRun returns the run's status and ETag.
func (top *topology) currentRun(runPath string) (status, etag string, payload []byte) {
	top.t.Helper()
	response, body := top.actor(http.MethodGet, runPath, "", "", nil)
	if response.StatusCode != http.StatusOK {
		top.t.Fatalf("get run status=%d body=%s", response.StatusCode, body)
	}
	var run struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &run); err != nil {
		top.t.Fatal(err)
	}
	return run.Status, response.Header.Get("ETag"), body
}

// waitForStatus polls the run until it reaches want, failing on a terminal
// state that is not want.
func (top *topology) waitForStatus(runPath, want string) string {
	top.t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		status, etag, payload := top.currentRun(runPath)
		if status == want {
			return etag
		}
		switch status {
		case "failed", "refused", "cancelled", "discarded", "conflict":
			if status == want {
				return etag
			}
			top.t.Fatalf("run settled in %q while waiting for %q: %s", status, want, payload)
		}
		if time.Now().After(deadline) {
			top.t.Fatalf("run is %q; %q was not reached in time: %s", status, want, payload)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// waitForTerminal polls the run until any terminal state and returns it.
func (top *topology) waitForTerminal(runPath string) string {
	top.t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for {
		status, _, _ := top.currentRun(runPath)
		switch status {
		case "completed", "failed", "refused", "cancelled", "discarded", "conflict":
			return status
		}
		if time.Now().After(deadline) {
			top.t.Fatalf("run %s never reached a terminal state (last %q)", runPath, status)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

// eventPayload reads the newest public event of the given type from the run's
// SSE stream.
func (top *topology) eventPayload(runPath, eventType string) (map[string]string, bool) {
	top.t.Helper()
	streamCtx, cancel := context.WithTimeout(top.ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(streamCtx, http.MethodGet, top.service.url+runPath+"/events", nil)
	if err != nil {
		top.t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+top.bearers.actor)
	request.Header.Set("traceparent", top.trace)
	request.Header.Set("Accept", "text/event-stream")
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		return nil, false
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		top.t.Fatalf("stream status=%d", response.StatusCode)
	}
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var payload map[string]string
	var found bool
	var data []byte
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data = []byte(strings.TrimPrefix(line, "data: "))
			continue
		}
		if line != "" {
			continue
		}
		if len(data) == 0 {
			continue
		}
		var event struct {
			EventType string            `json:"eventType"`
			Payload   map[string]string `json:"payload"`
		}
		if err := json.Unmarshal(data, &event); err == nil && event.EventType == eventType {
			payload, found = event.Payload, true
		}
		data = nil
	}
	return payload, found
}

func (top *topology) waitForEvent(runPath, eventType string) map[string]string {
	top.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if payload, found := top.eventPayload(runPath, eventType); found {
			return payload
		}
		time.Sleep(300 * time.Millisecond)
	}
	top.t.Fatalf("the public stream never carried %s", eventType)
	return nil
}

// count runs one scalar count query for the run.
func (top *topology) count(query, runID string) int {
	top.t.Helper()
	var value int
	if err := top.observe.QueryRow(top.ctx, query, runID).Scan(&value); err != nil {
		top.t.Fatalf("count query: %v", err)
	}
	return value
}

// answerInput answers the run's open input request over HTTP.
func (top *topology) answerInput(runPath, etag, answer string) {
	top.t.Helper()
	response, payload := top.tryAnswerInput(runPath, etag, answer)
	if response.StatusCode != http.StatusOK {
		top.t.Fatalf("input response status=%d body=%s", response.StatusCode, payload)
	}
}

// tryAnswerInput answers the run's open input request and reports what the
// service decided, whatever it was.
func (top *topology) tryAnswerInput(runPath, etag, answer string) (*http.Response, []byte) {
	top.t.Helper()
	event := top.waitForEvent(runPath, "run.input-requested")
	requestID := event["requestId"]
	version, err := strconv.ParseUint(event["requestVersion"], 10, 64)
	if err != nil || requestID == "" {
		top.t.Fatalf("run.input-requested payload incomplete: %#v", event)
	}
	body := []byte(fmt.Sprintf(`{"kind":"SubmitInputResponseRequest","requestVersion":%d,"responsePayload":{"answer":%q}}`, version, answer))
	return top.actor(http.MethodPost, runPath+"/inputs/"+requestID+"/responses", "input-"+requestID, etag, body)
}

// approve approves the run's open approval request over HTTP.
func (top *topology) approve(runPath, etag string) {
	top.t.Helper()
	event := top.waitForEvent(runPath, "run.approval-requested")
	requestID := event["requestId"]
	version, err := strconv.ParseUint(event["decisionVersion"], 10, 64)
	if err != nil || requestID == "" || event["actionDigest"] == "" {
		top.t.Fatalf("run.approval-requested payload incomplete: %#v", event)
	}
	body := []byte(fmt.Sprintf(`{"kind":"SubmitApprovalDecisionRequest","decision":"approve","decisionVersion":%d,"actionDigest":%q}`, version, event["actionDigest"]))
	response, payload := top.call(top.bearers.reviewer, http.MethodPost, runPath+"/approvals/"+requestID+"/decisions", "approve-"+requestID, etag, body)
	if response.StatusCode != http.StatusOK {
		top.t.Fatalf("approval decision status=%d body=%s", response.StatusCode, payload)
	}
}
