package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/ancyloce/anvilkit-agent-service/internal/security"
)

// MemoryAdmission decides whether untrusted content may enter the run's
// durable memory. The memory guard satisfies it.
//
// Tool output is untrusted content by construction: it is whatever a tool
// returned, and a tool reached something outside the service to produce it.
// That output is carried between turns and compiled into the next prompt, so
// admitting it unexamined is what makes indirect prompt injection and memory
// poisoning work — the attacker never has to reach the model directly, only
// something the model will later be shown.
type MemoryAdmission interface {
	Admit(security.MemoryCandidate) error
}

// DestinationGuard is the mediated outbound exchange, and it is the whole of
// what the pipeline can do with an address: the name is resolved once, the
// connection is pinned to exactly that resolution, every redirect is
// re-decided, and the duration and the response are bounded. The egress guard
// satisfies it.
//
// It carries Fetch alone deliberately. The port used to offer Resolve as
// well, and the pipeline used it as a preflight: it asked whether a
// destination was permitted, and then handed the tool the address to reach on
// its own. Everything the guard decides is undone by that second act — the
// name resolves again and can answer differently, a redirect is a destination
// nothing re-decided, and a body arrives with no bound. Asking a question
// about a connection somebody else is going to make is not a boundary, so the
// question is no longer on this port: the exchange is made here or it is not
// made.
type DestinationGuard interface {
	Fetch(ctx context.Context, raw string) (security.Response, error)
}

// RetrievalCapable is implemented by a tool executor whose catalogued tools
// need something read from an address a run named. It is how a network-capable
// tool is declared, and declaring it is the only way to become one: nothing
// under this service can open a connection of its own — the module boundary
// check refuses an HTTP client or a dialer outside the exact files that
// mediate egress — so a tool reaches outside through the exchange the pipeline
// performs for it or it does not reach outside at all.
//
// An executor that does not implement this is explicitly networkless, and a
// tool call it makes that names an outbound destination is refused rather than
// fetched.
type RetrievalCapable interface {
	// RetrievalTools names every tool this executor requires the mediated
	// exchange for. Each must be a tool the approved catalog attests; the
	// pipeline refuses to compose an executor that claims retrieval for
	// anything else, so the declaration cannot widen what a deployment
	// dispatches.
	RetrievalTools() []string
}

// RetrievedDocument is what one mediated exchange returned, handed to the tool
// that needed it.
//
// The address is not on it. A tool receives what was read, never a place to
// read from: the destination is named by digest so evidence and a tool's own
// output can be correlated without the tool ever holding an address it might
// be tempted — or instructed by the content it is processing — to reach.
type RetrievedDocument struct {
	DestinationDigest string
	StatusCode        int
	MediaType         string
	Body              []byte
}

// memoryRetention bounds how long admitted tool output is treated as live
// memory. It is short because carried notes exist to inform the next few
// turns, not to accumulate.
const memoryRetention = time.Hour

// admitToolOutput proves one tool's output may be carried into the run's
// memory. It answers the note to carry: the output when it is admissible, and
// a denial that names the tool and carries none of the refused content when it
// is not.
//
// The denial deliberately does not quote what was refused. A guard that
// reports hostile content by including it has admitted it — into the same
// notes, on the same path to the same prompt.
func admitToolOutput(guard MemoryAdmission, snapshot memoryScope, toolID string, output []byte, now time.Time) (string, bool) {
	candidate := security.MemoryCandidate{
		WorkspaceID:    snapshot.WorkspaceID,
		ProjectID:      snapshot.ProjectID,
		SourceID:       snapshot.RunID,
		Classification: "untrusted",
		Content:        output,
		ExpiresAt:      now.Add(memoryRetention),
	}
	if err := guard.Admit(candidate); err != nil {
		return "tool output refused admission to run memory: " + toolID, false
	}
	return "tool " + toolID + " output: " + truncate(string(output), 2048), true
}

// memoryScope is the tenant and run identity one admission is made under.
type memoryScope struct{ WorkspaceID, ProjectID, RunID string }

// proposedDestinations reads every outbound destination a tool call's
// arguments name.
//
// It walks the decoded arguments rather than the raw bytes so an address
// nested anywhere in the payload is found, and it treats any absolute URL as a
// destination. That is deliberately broad: the alternative is a list of
// argument names known to carry addresses, which is a list that goes stale the
// moment a tool gains a field. A tool call that mentions an address it does
// not intend to reach is refused rather than admitted, which is the direction
// to be wrong in.
func proposedDestinations(arguments json.RawMessage) []string {
	var decoded any
	if len(arguments) == 0 || json.Unmarshal(arguments, &decoded) != nil {
		return nil
	}
	seen := map[string]struct{}{}
	var found []string
	var walk func(any)
	walk = func(value any) {
		switch typed := value.(type) {
		case string:
			candidate := strings.TrimSpace(typed)
			if !absoluteURL(candidate) {
				return
			}
			if _, already := seen[candidate]; already {
				return
			}
			seen[candidate] = struct{}{}
			found = append(found, candidate)
		case []any:
			for _, item := range typed {
				walk(item)
			}
		case map[string]any:
			for _, item := range typed {
				walk(item)
			}
		}
	}
	walk(decoded)
	return found
}

// absoluteURL reports whether a string names an absolute network address. A
// bare path, an identifier, or a sentence is not one.
func absoluteURL(value string) bool {
	if len(value) < 8 || len(value) > 2048 || !strings.Contains(value, "://") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return false
	}
	return true
}

// destinationDigest names a refused destination in evidence without recording
// the address itself. The audit needs to distinguish one refusal from another
// and to correlate repeats; it does not need to keep a copy of wherever a
// model was trying to reach, and evidence is read by people.
func destinationDigest(destination string) string {
	sum := sha256.Sum256([]byte(destination))
	return "sha256:" + hex.EncodeToString(sum[:])
}
