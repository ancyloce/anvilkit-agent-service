package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
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
	defer func() { _ = file.Close() }()
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

// Guard is the production decision one adversarial category must be refused
// by. Refuses reports whether the real guard rejected the case; a guard that
// cannot reach a decision returns an error, which is a corpus failure rather
// than a refusal — an evaluation that did not happen is never evidence that
// an attack was blocked.
type Guard interface {
	Refuses(ctx context.Context, attack AttackCase) (bool, error)
}

// GuardFunc adapts a function to Guard.
type GuardFunc func(ctx context.Context, attack AttackCase) (bool, error)

func (f GuardFunc) Refuses(ctx context.Context, attack AttackCase) (bool, error) {
	return f(ctx, attack)
}

// Guards binds every adversarial category to the production guard that owns
// it. The binding is the whole point of the corpus: an adversarial case
// evaluated by the corpus's own reasoning proves only that the corpus agrees
// with itself, which is what this file used to do — every category resolved to
// a comparison written beside the case it judged, so a case could be "blocked"
// while the production path it named would have admitted it. A category with
// no bound guard fails the run rather than passing unevaluated.
type Guards map[string]Guard

// RunCorpus evaluates every case against the production guard bound to its
// category and records one finding per case.
func RunCorpus(ctx context.Context, corpus Corpus, guards Guards) ([]Finding, error) {
	return RunCorpusWithRecorder(ctx, corpus, guards, &MemoryFindingRecorder{})
}

// RunCorpusWithRecorder is RunCorpus against an explicit finding recorder. A
// finding that cannot be recorded fails the run: an unrecorded refusal is not
// evidence of one.
func RunCorpusWithRecorder(ctx context.Context, corpus Corpus, guards Guards, recorder FindingRecorder) ([]Finding, error) {
	if recorder == nil {
		return nil, fmt.Errorf("security finding recorder required")
	}
	if len(guards) == 0 {
		return nil, fmt.Errorf("the adversarial corpus requires the production guards it is evaluated against")
	}
	findings := make([]Finding, 0, len(corpus.Cases))
	seen := map[string]bool{}
	for _, attack := range corpus.Cases {
		if attack.ID == "" || seen[attack.ID] {
			return nil, fmt.Errorf("missing or duplicate attack ID %q", attack.ID)
		}
		seen[attack.ID] = true
		guard, bound := guards[attack.Category]
		if !bound || guard == nil {
			return nil, fmt.Errorf("adversarial category %q is bound to no production guard", attack.Category)
		}
		refused, err := guard.Refuses(ctx, attack)
		if err != nil {
			return findings, fmt.Errorf("evaluate adversarial case %s against its production guard: %w", attack.ID, err)
		}
		outcome := "blocked"
		if !refused {
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

// Categories returns every category the corpus contains, so a caller can prove
// its bindings cover the corpus before running it.
func (c Corpus) Categories() []string {
	seen := map[string]bool{}
	values := make([]string, 0, len(c.Cases))
	for _, attack := range c.Cases {
		if !seen[attack.Category] {
			seen[attack.Category] = true
			values = append(values, attack.Category)
		}
	}
	sort.Strings(values)
	return values
}

type staticResolver struct{ addresses map[string][]net.IPAddr }

func (r staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	values, ok := r.addresses[host]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return values, nil
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
