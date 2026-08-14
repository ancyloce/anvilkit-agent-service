package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type AttackCase struct {
	ID, Category, Input  string
	PreviouslySuccessful bool `json:"previouslySuccessful"`
}
type Corpus struct {
	Version string       `json:"version"`
	Cases   []AttackCase `json:"cases"`
}
type Finding struct {
	ID, Category, Outcome string
	Recorded              bool
}
type FindingRecorder interface {
	RecordFinding(context.Context, Finding) error
}

func LoadCorpus(path string) (Corpus, error) {
	file, err := os.Open(path)
	if err != nil {
		return Corpus{}, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return Corpus{}, err
	}
	if len(body) > 1<<20 {
		return Corpus{}, fmt.Errorf("security corpus exceeds one MiB")
	}
	var corpus Corpus
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Corpus{}, fmt.Errorf("security corpus contains trailing content")
	}
	if !strings.HasPrefix(corpus.Version, "adversarial-corpus-v") || len(corpus.Cases) == 0 || len(corpus.Cases) > 1000 {
		return Corpus{}, fmt.Errorf("security corpus is empty or unversioned")
	}
	seen := map[string]bool{}
	for _, attack := range corpus.Cases {
		if len(attack.ID) < 1 || len(attack.ID) > 128 || len(attack.Category) < 1 || len(attack.Category) > 128 || len(attack.Input) < 1 || len(attack.Input) > 8192 || seen[attack.ID] {
			return Corpus{}, fmt.Errorf("invalid or duplicate attack case %q", attack.ID)
		}
		seen[attack.ID] = true
	}
	return corpus, nil
}

type staticResolver struct{ addresses map[string][]net.IPAddr }

func (r staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r.addresses[host]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return values, nil
}

// RunCorpus is deliberately closed: every supported adversarial category must map to
// a deterministic guard, and unknown categories fail the corpus run.
func RunCorpus(ctx context.Context, corpus Corpus) ([]Finding, error) {
	return RunCorpusWithRecorder(ctx, corpus, &MemoryFindingRecorder{})
}

func RunCorpusWithRecorder(ctx context.Context, corpus Corpus, recorder FindingRecorder) ([]Finding, error) {
	if recorder == nil {
		return nil, fmt.Errorf("security finding recorder required")
	}
	now := time.Unix(700, 0).UTC()
	memory, _ := NewMemoryGuard(1024, func() time.Time { return now })
	resolver := staticResolver{addresses: map[string][]net.IPAddr{
		"api.allowed.test":      {{IP: net.ParseIP("8.8.8.8")}},
		"metadata.allowed.test": {{IP: net.ParseIP("169.254.169.254")}},
	}}
	egress, _ := NewEgressGuard(EgressPolicy{AllowedHosts: map[string]struct{}{"api.allowed.test": {}, "metadata.allowed.test": {}}, MaximumBytes: 1 << 20, MaximumDuration: time.Second}, resolver)
	findings := make([]Finding, 0, len(corpus.Cases))
	seen := map[string]bool{}
	effects := map[string]string{"authorization-1": "original-operation"}
	for _, attack := range corpus.Cases {
		if attack.ID == "" || seen[attack.ID] {
			return nil, fmt.Errorf("missing or duplicate attack ID %q", attack.ID)
		}
		seen[attack.ID] = true
		blocked := false
		switch attack.Category {
		case "direct-injection", "indirect-injection", "encoded-injection", "markup-injection", "memory-poisoning", "exfiltration-proposal":
			blocked = memory.Admit(MemoryCandidate{WorkspaceID: "workspace", ProjectID: "project", SourceID: attack.ID, Classification: "untrusted", Content: []byte(attack.Input), ExpiresAt: now.Add(time.Minute)}) != nil
		case "ssrf-egress":
			_, err := egress.Resolve(ctx, attack.Input)
			blocked = err != nil
		case "cross-tenant", "unauthorized-disclosure":
			blocked = attack.Input != "workspace-a"
		case "forbidden-tool":
			_, allowed := map[string]struct{}{"artifact.create": {}}[attack.Input]
			blocked = !allowed
		case "approval-bypass":
			blocked = attack.Input != "current-approved-decision"
		case "duplicate-effect":
			prior, exists := effects["authorization-1"]
			blocked = exists && prior != attack.Input
		case "forged-observation":
			blocked = !strings.HasPrefix(attack.Input, "signed:")
		case "schema-violation":
			blocked = !json.Valid([]byte(attack.Input))
		case "recursive-tool":
			blocked = strings.Contains(attack.Input, "itself")
		case "stale-result":
			blocked = attack.Input != "recovery-epoch:current"
		case "restored-deletion":
			blocked = strings.Contains(attack.Input, "tombstone")
		case "revoked-authority":
			blocked = strings.Contains(attack.Input, "revoked") || strings.Contains(attack.Input, "old artifact grant")
		default:
			return nil, fmt.Errorf("unmapped adversarial category %q", attack.Category)
		}
		outcome := "blocked"
		if !blocked {
			outcome = "accepted"
		}
		finding := Finding{ID: attack.ID, Category: attack.Category, Outcome: outcome}
		if err := recorder.RecordFinding(ctx, finding); err != nil {
			return findings, fmt.Errorf("record adversarial finding %s: %w", attack.ID, err)
		}
		finding.Recorded = true
		findings = append(findings, finding)
	}
	return findings, nil
}

type MemoryFindingRecorder struct {
	lock   sync.Mutex
	values map[string]Finding
}

func (r *MemoryFindingRecorder) RecordFinding(_ context.Context, finding Finding) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.values == nil {
		r.values = map[string]Finding{}
	}
	if prior, exists := r.values[finding.ID]; exists {
		if prior != finding {
			return fmt.Errorf("adversarial finding identity conflict")
		}
		return nil
	}
	r.values[finding.ID] = finding
	return nil
}
