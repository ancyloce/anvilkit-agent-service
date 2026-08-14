// Package contextcompiler owns deterministic, authorized, minimized context
// compilation. Untrusted layers are data and can never replace policy layers.
package contextcompiler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type SnapshotID string
type Classification string

const (
	Public       Classification = "public"
	Internal     Classification = "internal"
	Confidential Classification = "confidential"
	Restricted   Classification = "restricted"
)

type Trust string

const (
	System         Trust = "system"
	Agent          Trust = "agent"
	Tools          Trust = "tools"
	User           Trust = "user"
	Retrieved      Trust = "retrieved"
	ToolOutput     Trust = "tool-output"
	ProviderOutput Trust = "provider-output"
)

type PolicyReference struct {
	PolicyID string `json:"policyId"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}
type Source struct {
	ID             string
	Trust          Trust
	Classification Classification
	Content        string
	TenantID       string
	TokenBudget    int
}
type Request struct {
	TenantID        string
	WorkspaceID     string
	ProjectID       string
	RunID           string
	Sources         []Source
	Policy          PolicyReference
	RedactionPolicy PolicyReference
	Replacement     string
	TotalTokens     int
	CompiledAt      time.Time
	Memory          Memory
}
type Memory interface {
	Load(context.Context, string) ([]Source, error)
}
type Layer struct {
	LayerID        string         `json:"layerId"`
	Position       int            `json:"position"`
	Digest         string         `json:"digest"`
	Classification Classification `json:"classification"`
	Redacted       bool           `json:"redacted"`
	TokenBudget    int            `json:"tokenBudget"`
}
type TokenBudgets struct {
	Total  int `json:"total"`
	System int `json:"system"`
	User   int `json:"user"`
	Tools  int `json:"tools"`
	Memory int `json:"memory"`
}
type Redaction struct {
	Policy            PolicyReference `json:"policy"`
	RemovedFieldCount int             `json:"removedFieldCount"`
	ReplacementMarker string          `json:"replacementMarker"`
}
type Compiled struct {
	APIVersion         string           `json:"apiVersion"`
	Kind               string           `json:"kind"`
	OrderedTrustLayers []Layer          `json:"orderedTrustLayers"`
	LayerDigests       []string         `json:"layerDigests"`
	Classifications    []Classification `json:"classifications"`
	Redaction          Redaction        `json:"redaction"`
	TokenBudgets       TokenBudgets     `json:"tokenBudgets"`
	PolicySnapshot     PolicyReference  `json:"policySnapshot"`
	CompiledAt         string           `json:"compiledAt"`
}
type Disclosure struct {
	LayerID        string
	Trust          Trust
	Classification Classification
	Content        string
}
type Result struct {
	Evidence    Compiled
	Disclosure  []Disclosure
	Truncations map[string]int
}
type EvidenceRecorder interface {
	Record(context.Context, Request, Result) error
}

type Compiler struct{ secrets []string }

func New(secrets []string) *Compiler {
	values := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			values = append(values, secret)
		}
	}
	sort.Strings(values)
	return &Compiler{secrets: values}
}

func (c *Compiler) Compile(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if request.Memory != nil {
		return Result{}, fmt.Errorf("durable memory is forbidden in foundation")
	}
	if request.TenantID == "" || request.WorkspaceID == "" || request.ProjectID == "" || request.RunID == "" || len(request.Sources) == 0 || len(request.Sources) > 128 || request.TotalTokens < 1 || request.TotalTokens > 1_000_000 || request.CompiledAt.IsZero() || !validPolicy(request.Policy) || !validPolicy(request.RedactionPolicy) {
		return Result{}, fmt.Errorf("context compilation authority is incomplete")
	}
	if request.Replacement == "" {
		request.Replacement = "[REDACTED]"
	}
	if len(request.Replacement) > 64 || !utf8.ValidString(request.Replacement) {
		return Result{}, fmt.Errorf("redaction replacement is invalid")
	}
	sources := append([]Source(nil), request.Sources...)
	sort.Slice(sources, func(i, j int) bool {
		left, right := trustRank(sources[i].Trust), trustRank(sources[j].Trust)
		if left != right {
			return left < right
		}
		return sources[i].ID < sources[j].ID
	})
	result := Result{Evidence: Compiled{APIVersion: "anvilkit.io/contracts/v1", Kind: "CompiledContext", PolicySnapshot: request.Policy, CompiledAt: request.CompiledAt.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z"), Redaction: Redaction{Policy: request.RedactionPolicy, ReplacementMarker: request.Replacement}, TokenBudgets: TokenBudgets{Total: request.TotalTokens, Memory: 0}}, Truncations: map[string]int{}}
	seen := map[string]bool{}
	classes := map[Classification]bool{}
	remaining := request.TotalTokens
	for position, source := range sources {
		if !opaque(source.ID, 128) || seen[source.ID] || source.TenantID != request.TenantID || trustRank(source.Trust) < 0 || !validClass(source.Classification) || !utf8.ValidString(source.Content) {
			return Result{}, fmt.Errorf("context source identity, scope, trust, or classification is invalid")
		}
		seen[source.ID] = true
		content, removed, err := c.minimize(source.Content, request.Replacement)
		if err != nil {
			return Result{}, fmt.Errorf("context source %s: %w", source.ID, err)
		}
		budget := source.TokenBudget
		if budget < 0 {
			return Result{}, fmt.Errorf("negative token budget")
		}
		if budget > remaining {
			budget = remaining
		}
		capacity := budget * 4
		if capacity < len(content) {
			truncated := truncateUTF8(content, capacity)
			result.Truncations[source.ID] = len(content) - len(truncated)
			content = truncated
		}
		remaining -= budget
		digest := digest([]byte(content))
		result.Evidence.OrderedTrustLayers = append(result.Evidence.OrderedTrustLayers, Layer{LayerID: source.ID, Position: position, Digest: digest, Classification: source.Classification, Redacted: removed > 0, TokenBudget: budget})
		result.Evidence.LayerDigests = append(result.Evidence.LayerDigests, digest)
		result.Disclosure = append(result.Disclosure, Disclosure{LayerID: source.ID, Trust: source.Trust, Classification: source.Classification, Content: content})
		result.Evidence.Redaction.RemovedFieldCount += removed
		classes[source.Classification] = true
		switch source.Trust {
		case System, Agent:
			result.Evidence.TokenBudgets.System += budget
		case Tools:
			result.Evidence.TokenBudgets.Tools += budget
		default:
			result.Evidence.TokenBudgets.User += budget
		}
	}
	for _, class := range []Classification{Public, Internal, Confidential, Restricted} {
		if classes[class] {
			result.Evidence.Classifications = append(result.Evidence.Classifications, class)
		}
	}
	return result, nil
}

func (c *Compiler) CompileAndRecord(ctx context.Context, request Request, recorder EvidenceRecorder) (Result, error) {
	if recorder == nil {
		return Result{}, fmt.Errorf("context evidence recorder is required")
	}
	result, err := c.Compile(ctx, request)
	if err != nil {
		return Result{}, err
	}
	if err := recorder.Record(ctx, request, result); err != nil {
		return Result{}, fmt.Errorf("record compiled context evidence: %w", err)
	}
	return result, nil
}

func (c *Compiler) minimize(content, replacement string) (string, int, error) {
	lower := strings.ToLower(content)
	for _, marker := range []string{"private_key", "private-key", "aws_secret_access_key", "-----begin private key-----", "-----begin rsa private key-----", "-----begin ec private key-----"} {
		if strings.Contains(lower, marker) {
			return "", 0, fmt.Errorf("credential or signed URL detected")
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)authorization\s*:\s*(bearer|basic)\s+\S+`),
		regexp.MustCompile(`(?i)["']?(password|passwd|api[_-]?key|secret[_-]?access[_-]?key)["']?\s*[:=]\s*[^\s,;}]+`),
	} {
		if pattern.MatchString(content) {
			return "", 0, fmt.Errorf("credential or signed URL detected")
		}
	}
	for _, field := range strings.Fields(content) {
		candidate := strings.Trim(field, "\"'()[]{}<>,.;")
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			continue
		}
		query := parsed.Query()
		for key := range query {
			switch strings.ToLower(key) {
			case "x-amz-signature", "x-goog-signature", "signature", "sig", "se", "sp", "sv":
				return "", 0, fmt.Errorf("credential or signed URL detected")
			}
		}
	}
	removed := 0
	for _, secret := range c.secrets {
		if count := strings.Count(content, secret); count > 0 {
			content = strings.ReplaceAll(content, secret, replacement)
			removed += count
		}
	}
	for _, secret := range c.secrets {
		if strings.Contains(content, secret) {
			return "", 0, fmt.Errorf("registered secret survived redaction")
		}
	}
	return content, removed, nil
}

func trustRank(value Trust) int {
	switch value {
	case System:
		return 0
	case Agent:
		return 1
	case Tools:
		return 2
	case User:
		return 3
	case Retrieved:
		return 4
	case ToolOutput:
		return 5
	case ProviderOutput:
		return 6
	default:
		return -1
	}
}
func validClass(value Classification) bool {
	return value == Public || value == Internal || value == Confidential || value == Restricted
}
func validPolicy(value PolicyReference) bool {
	return opaque(value.PolicyID, 128) && opaque(value.Version, 64) && regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(value.Digest)
}
func opaque(value string, maximum int) bool {
	return len(value) <= maximum && regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`).MatchString(value)
}
func truncateUTF8(value string, maximum int) string {
	if maximum >= len(value) {
		return value
	}
	if maximum <= 0 {
		return ""
	}
	for maximum > 0 && !utf8.RuneStart(value[maximum]) {
		maximum--
	}
	return value[:maximum]
}
func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func (r Result) MarshalEvidence() ([]byte, error) { return json.Marshal(r.Evidence) }
