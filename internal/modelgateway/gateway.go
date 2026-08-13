// Package modelgateway owns eligibility-first routing and adapter-neutral
// provider invocation. Context bytes are disclosed only after selection.
package modelgateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ancyloce/anvilkit-agent-service/internal/problem"
	"sort"
	"sync"
	"time"
)

type ProviderID string
type DataClass string

const (
	Public       DataClass = "public"
	Internal     DataClass = "internal"
	Confidential DataClass = "confidential"
	Restricted   DataClass = "restricted"
)

type Provider struct {
	ID                 ProviderID  `json:"id"`
	ModelVersion       string      `json:"modelVersion"`
	Regions            []string    `json:"regions"`
	DataClasses        []DataClass `json:"dataClasses"`
	Capabilities       []string    `json:"capabilities"`
	Retention          bool        `json:"retention"`
	Training           bool        `json:"training"`
	SafetyLevel        int         `json:"safetyLevel"`
	MaximumCostMicros  int64       `json:"maximumCostMicros"`
	Priority           int         `json:"priority"`
	Enabled            bool        `json:"enabled"`
	DisabledWorkspaces []string    `json:"disabledWorkspaces,omitempty"`
}
type Snapshot struct {
	Version   string     `json:"version"`
	Providers []Provider `json:"providers"`
	Digest    string     `json:"-"`
}
type Policy struct {
	Version           string
	AllowedProviders  []ProviderID
	AllowedRegions    []string
	DataClasses       []DataClass
	Capability        string
	AllowRetention    bool
	AllowTraining     bool
	MinimumSafety     int
	MaximumCostMicros int64
}
type Removal struct {
	Provider ProviderID
	Reasons  []string
}
type Selection struct {
	Provider          Provider
	Region            string
	DataClasses       []DataClass
	MaximumCostMicros int64
	SnapshotDigest    string
	PolicyVersion     string
	Removed           []Removal
	eligible          bool
}
type Registry struct {
	lock      sync.RWMutex
	current   string
	snapshots map[string]Snapshot
}

func NewRegistry(snapshot Snapshot) (*Registry, error) {
	r := &Registry{snapshots: map[string]Snapshot{}}
	if err := r.Update(snapshot); err != nil {
		return nil, err
	}
	return r, nil
}
func (r *Registry) Update(snapshot Snapshot) error {
	snapshot = normalizeSnapshot(snapshot)
	if err := validateSnapshot(snapshot); err != nil {
		return err
	}
	digest, err := snapshotDigest(snapshot)
	if err != nil {
		return err
	}
	snapshot.Digest = digest
	r.lock.Lock()
	defer r.lock.Unlock()
	if old, ok := r.snapshots[digest]; ok {
		if !equalSnapshot(old, snapshot) {
			return fmt.Errorf("registry digest collision")
		}
		r.current = digest
		return nil
	}
	r.snapshots[digest] = cloneSnapshot(snapshot)
	r.current = digest
	return nil
}
func (r *Registry) Current() Snapshot {
	r.lock.RLock()
	defer r.lock.RUnlock()
	return cloneSnapshot(r.snapshots[r.current])
}
func (r *Registry) ByDigest(digest string) (Snapshot, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	value, ok := r.snapshots[digest]
	return cloneSnapshot(value), ok
}
func (r *Registry) Select(workspace string, policy Policy) (Selection, error) {
	return selectSnapshot(r.Current(), workspace, policy)
}
func (r *Registry) Replay(digest, workspace string, policy Policy) (Selection, error) {
	snapshot, ok := r.ByDigest(digest)
	if !ok {
		return Selection{}, problem.New(problem.CodeResourceNotFound, "")
	}
	return selectSnapshot(snapshot, workspace, policy)
}
func selectSnapshot(snapshot Snapshot, workspace string, policy Policy) (Selection, error) {
	if workspace == "" || !validPolicy(policy) {
		return Selection{}, problem.New(problem.CodeRequestInvalid, "")
	}
	var eligible []Provider
	selection := Selection{SnapshotDigest: snapshot.Digest, PolicyVersion: policy.Version, DataClasses: append([]DataClass(nil), policy.DataClasses...), MaximumCostMicros: policy.MaximumCostMicros}
	for _, provider := range snapshot.Providers {
		var reasons []string
		if !provider.Enabled {
			reasons = append(reasons, "platform-disabled")
		}
		if contains(provider.DisabledWorkspaces, workspace) {
			reasons = append(reasons, "workspace-disabled")
		}
		if len(policy.AllowedProviders) > 0 && !containsProvider(policy.AllowedProviders, provider.ID) {
			reasons = append(reasons, "provider-not-allowed")
		}
		if !intersects(provider.Regions, policy.AllowedRegions) {
			reasons = append(reasons, "residency")
		}
		if !containsAllClasses(provider.DataClasses, policy.DataClasses) {
			reasons = append(reasons, "data-class")
		}
		if provider.Retention && !policy.AllowRetention {
			reasons = append(reasons, "retention")
		}
		if provider.Training && !policy.AllowTraining {
			reasons = append(reasons, "training")
		}
		if provider.SafetyLevel < policy.MinimumSafety {
			reasons = append(reasons, "safety")
		}
		if provider.MaximumCostMicros > policy.MaximumCostMicros {
			reasons = append(reasons, "cost")
		}
		if !contains(provider.Capabilities, policy.Capability) {
			reasons = append(reasons, "capability")
		}
		if len(reasons) > 0 {
			selection.Removed = append(selection.Removed, Removal{provider.ID, reasons})
			continue
		}
		eligible = append(eligible, provider)
	}
	if len(eligible) == 0 {
		details := problem.New(problem.CodeNoEligibleProvider, "")
		details.Detail = "current policy has no eligible provider"
		return selection, details
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].Priority != eligible[j].Priority {
			return eligible[i].Priority < eligible[j].Priority
		}
		return eligible[i].ID < eligible[j].ID
	})
	selection.Provider = eligible[0]
	selection.eligible = true
	selection.Region = selection.Provider.Regions[0]
	if len(policy.AllowedRegions) > 0 {
		for _, region := range selection.Provider.Regions {
			if contains(policy.AllowedRegions, region) {
				selection.Region = region
				break
			}
		}
	}
	return selection, nil
}

type AttemptID string
type InvokeRequest struct {
	RunID, WorkspaceID                      string
	ProjectID                               string
	Selection                               Selection
	Context                                 []byte
	DataClasses                             []DataClass
	MaximumOutputBytes                      int
	MaximumInputTokens, MaximumOutputTokens int64
	MaximumCostMicros                       int64
	Timeout                                 time.Duration
	MaximumAttempts                         int
	RetryBudget                             time.Duration
	Scenario                                string
}
type AdapterRequest struct {
	InvocationID       string
	PhysicalAttemptID  AttemptID
	Provider           ProviderID
	ModelVersion       string
	Context            []byte
	Scenario           string
	MaximumOutputBytes int
}
type AdapterResponse struct {
	Output                                []byte
	InputTokens, OutputTokens, CostMicros int64
	Retryable                             bool
	Continuation                          []byte
}
type Adapter interface {
	Invoke(context.Context, AdapterRequest) (AdapterResponse, error)
}
type Recorder interface {
	BeforeDisclosure(context.Context, InvocationRecord) error
	BeforeAttempt(context.Context, InvocationRecord) error
	Complete(context.Context, InvocationRecord) error
}
type InvocationRecord struct {
	InvocationID                          string
	PhysicalAttempts                      []AttemptID
	RunID, WorkspaceID, ProjectID         string
	RegistrySnapshotDigest, PolicyVersion string
	Provider                              ProviderID
	ModelVersion, Region                  string
	DisclosedDataClasses                  []DataClass
	StartedAt                             time.Time
	CompletedAt                           *time.Time
	InputTokens, OutputTokens, CostMicros int64
	OutputDigest                          string
	Problem                               *problem.Details
}
type IDs interface {
	InvocationID() string
	AttemptID(int) AttemptID
}
type Clock interface{ Now() time.Time }
type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}
type Gateway struct {
	adapters map[ProviderID]Adapter
	recorder Recorder
	ids      IDs
	clock    Clock
	sleeper  Sleeper
}

func NewGateway(adapters map[ProviderID]Adapter, recorder Recorder, ids IDs, clock Clock, sleeper Sleeper) (*Gateway, error) {
	if len(adapters) == 0 || recorder == nil || ids == nil || clock == nil || sleeper == nil {
		return nil, fmt.Errorf("gateway dependencies required")
	}
	copyAdapters := map[ProviderID]Adapter{}
	for id, adapter := range adapters {
		if id == "" || adapter == nil {
			return nil, fmt.Errorf("invalid adapter")
		}
		copyAdapters[id] = adapter
	}
	return &Gateway{copyAdapters, recorder, ids, clock, sleeper}, nil
}
func (g *Gateway) Invoke(ctx context.Context, request InvokeRequest) (AdapterResponse, InvocationRecord, error) {
	if !request.Selection.eligible || request.Selection.Provider.ID == "" || request.Selection.Region == "" || !contains(request.Selection.Provider.Regions, request.Selection.Region) || !isSHA256(request.Selection.SnapshotDigest) || request.RunID == "" || request.WorkspaceID == "" || request.ProjectID == "" || len(request.DataClasses) == 0 || !containsAllClasses(request.Selection.Provider.DataClasses, request.DataClasses) || !containsAllClasses(request.Selection.DataClasses, request.DataClasses) || request.MaximumCostMicros < 0 || request.MaximumCostMicros > request.Selection.MaximumCostMicros || request.MaximumOutputBytes < 1 || request.MaximumAttempts < 1 || request.Timeout <= 0 || request.RetryBudget < 0 {
		return AdapterResponse{}, InvocationRecord{}, problem.New(problem.CodeRequestInvalid, "")
	}
	adapter := g.adapters[request.Selection.Provider.ID]
	if adapter == nil {
		return AdapterResponse{}, InvocationRecord{}, problem.New(problem.CodeNoEligibleProvider, "")
	}
	invocationID := g.ids.InvocationID()
	if invocationID == "" {
		return AdapterResponse{}, InvocationRecord{}, fmt.Errorf("empty provider invocation identity")
	}
	record := InvocationRecord{InvocationID: invocationID, RunID: request.RunID, WorkspaceID: request.WorkspaceID, ProjectID: request.ProjectID, RegistrySnapshotDigest: request.Selection.SnapshotDigest, PolicyVersion: request.Selection.PolicyVersion, Provider: request.Selection.Provider.ID, ModelVersion: request.Selection.Provider.ModelVersion, Region: request.Selection.Region, DisclosedDataClasses: append([]DataClass(nil), request.DataClasses...), StartedAt: g.clock.Now()}
	if err := g.recorder.BeforeDisclosure(ctx, record); err != nil {
		return AdapterResponse{}, record, fmt.Errorf("record invocation before disclosure: %w", err)
	}
	started := g.clock.Now()
	var last error
	for attempt := 1; attempt <= request.MaximumAttempts; attempt++ {
		elapsed := g.clock.Now().Sub(started)
		if elapsed > request.RetryBudget && attempt > 1 {
			break
		}
		attemptID := g.ids.AttemptID(attempt)
		if attemptID == "" {
			last = fmt.Errorf("empty physical provider attempt identity")
			break
		}
		record.PhysicalAttempts = append(record.PhysicalAttempts, attemptID)
		if err := g.recorder.BeforeAttempt(ctx, record); err != nil {
			last = fmt.Errorf("record physical attempt before disclosure: %w", err)
			break
		}
		attemptCtx, cancel := context.WithTimeout(ctx, request.Timeout)
		response, err := adapter.Invoke(attemptCtx, AdapterRequest{record.InvocationID, attemptID, request.Selection.Provider.ID, request.Selection.Provider.ModelVersion, append([]byte(nil), request.Context...), request.Scenario, request.MaximumOutputBytes})
		cancel()
		if err != nil {
			last = err
			if !retryable(err) || attempt == request.MaximumAttempts {
				break
			}
			delay := retryJitter(record.InvocationID, attempt)
			if elapsed+delay > request.RetryBudget {
				break
			}
			if err := g.sleeper.Sleep(ctx, delay); err != nil {
				last = err
				break
			}
			continue
		}
		if len(response.Output) > request.MaximumOutputBytes || response.InputTokens < 0 || response.OutputTokens < 0 || response.CostMicros < 0 || response.InputTokens > request.MaximumInputTokens || response.OutputTokens > request.MaximumOutputTokens || response.CostMicros > request.MaximumCostMicros {
			last = problem.New(problem.CodeProviderLimitExceeded, "")
			break
		}
		record.InputTokens += response.InputTokens
		record.OutputTokens += response.OutputTokens
		record.CostMicros += response.CostMicros
		record.OutputDigest = digest(response.Output)
		completed := g.clock.Now()
		record.CompletedAt = &completed
		if err := g.recorder.Complete(ctx, record); err != nil {
			return AdapterResponse{}, record, err
		}
		return response, record, nil
	}
	details := problem.New(problem.CodeProviderUnavailable, "")
	details.Detail = "provider invocation exhausted its bounded attempts"
	if last != nil {
		var stable problem.Details
		if errors.As(last, &stable) {
			details = stable
		}
	}
	record.Problem = &details
	completed := g.clock.Now()
	record.CompletedAt = &completed
	if err := g.recorder.Complete(ctx, record); err != nil {
		return AdapterResponse{}, record, fmt.Errorf("record failed provider invocation: %w", err)
	}
	return AdapterResponse{}, record, details
}

// InvokeEligible performs eligibility before the request reaches any adapter or
// pre-disclosure recorder. It is the only routing entry point for unselected work.
func (g *Gateway) InvokeEligible(ctx context.Context, registry *Registry, policy Policy, request InvokeRequest) (AdapterResponse, InvocationRecord, error) {
	if registry == nil {
		return AdapterResponse{}, InvocationRecord{}, problem.New(problem.CodeRequestInvalid, "")
	}
	selection, err := registry.Select(request.WorkspaceID, policy)
	if err != nil {
		return AdapterResponse{}, InvocationRecord{}, err
	}
	request.Selection = selection
	return g.Invoke(ctx, request)
}

type RetryableError struct{ Err error }

func (e RetryableError) Error() string { return e.Err.Error() }
func (e RetryableError) Unwrap() error { return e.Err }
func retryable(err error) bool         { var value RetryableError; return errors.As(err, &value) }
func snapshotDigest(snapshot Snapshot) (string, error) {
	copyValue := normalizeSnapshot(snapshot)
	copyValue.Digest = ""
	sort.Slice(copyValue.Providers, func(i, j int) bool { return copyValue.Providers[i].ID < copyValue.Providers[j].ID })
	raw, err := json.Marshal(copyValue)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}
func normalizeSnapshot(value Snapshot) Snapshot {
	value = cloneSnapshot(value)
	value.Digest = ""
	for index := range value.Providers {
		provider := &value.Providers[index]
		sort.Strings(provider.Regions)
		sort.Slice(provider.DataClasses, func(i, j int) bool { return provider.DataClasses[i] < provider.DataClasses[j] })
		sort.Strings(provider.Capabilities)
		sort.Strings(provider.DisabledWorkspaces)
	}
	sort.Slice(value.Providers, func(i, j int) bool { return value.Providers[i].ID < value.Providers[j].ID })
	return value
}
func validateSnapshot(value Snapshot) error {
	if value.Version == "" || len(value.Providers) == 0 || len(value.Providers) > 128 {
		return fmt.Errorf("provider registry snapshot is empty or unbounded")
	}
	seen := map[ProviderID]bool{}
	for _, provider := range value.Providers {
		if provider.ID == "" || seen[provider.ID] || provider.ModelVersion == "" || len(provider.Regions) == 0 || len(provider.DataClasses) == 0 || len(provider.Capabilities) == 0 || provider.SafetyLevel < 0 || provider.MaximumCostMicros < 0 {
			return fmt.Errorf("provider registry entry %q is invalid", provider.ID)
		}
		seen[provider.ID] = true
		for _, class := range provider.DataClasses {
			if class != Public && class != Internal && class != Confidential && class != Restricted {
				return fmt.Errorf("provider registry entry %q has invalid data class", provider.ID)
			}
		}
	}
	return nil
}
func validPolicy(value Policy) bool {
	if value.Version == "" || value.Capability == "" || len(value.DataClasses) == 0 || value.MinimumSafety < 0 || value.MaximumCostMicros < 0 {
		return false
	}
	for _, class := range value.DataClasses {
		if class != Public && class != Internal && class != Confidential && class != Restricted {
			return false
		}
	}
	return true
}
func isSHA256(value string) bool {
	if len(value) != 71 || value[:7] != "sha256:" {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func cloneSnapshot(value Snapshot) Snapshot {
	raw, _ := json.Marshal(value)
	var result Snapshot
	_ = json.Unmarshal(raw, &result)
	result.Digest = value.Digest
	return result
}
func equalSnapshot(a, b Snapshot) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
func contains(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
func containsProvider(values []ProviderID, target ProviderID) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}
func intersects(a, b []string) bool {
	if len(b) == 0 {
		return true
	}
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}
func containsAllClasses(a, b []DataClass) bool {
	for _, target := range b {
		found := false
		for _, value := range a {
			if value == target {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func retryJitter(invocationID string, attempt int) time.Duration {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", invocationID, attempt)))
	ceiling := uint64(10*time.Millisecond) << uint(attempt-1)
	value := uint64(sum[0])<<8 | uint64(sum[1])
	return time.Duration(value % (ceiling + 1))
}
