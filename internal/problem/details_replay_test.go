package problem

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Structured ProblemDetails cross durable boundaries as JSON. Replay must
// reconstruct the same typed value, not a code-only husk.
func TestDetailsRoundTripReconstructsStructuredDetails(t *testing.T) {
	for _, code := range Codes() {
		t.Run(string(code), func(t *testing.T) {
			original := New(code, "0af7651916cd43dd8448eb211c80319c")
			original.Detail = "durable operation detail for " + string(code)
			original.Stage = "execute-turn"
			original.RunID = "run.replay"
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var restored Details
			if err := json.Unmarshal(raw, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.Code != original.Code || restored.Detail != original.Detail {
				t.Fatalf("code/detail lost: %+v", restored)
			}
			if restored.Type != original.Type || restored.Title != original.Title || restored.Status != original.Status || restored.Retryability != original.Retryability {
				t.Fatalf("registry-derived fields lost: %+v", restored)
			}
			if restored.Stage != original.Stage || restored.RunID != original.RunID || restored.TraceID != original.TraceID {
				t.Fatalf("correlation fields lost: %+v", restored)
			}
			if restored.Error() != original.Error() {
				t.Fatalf("error text drifted: %q vs %q", restored.Error(), original.Error())
			}
			// Re-marshalling a restored value must reproduce the same bytes,
			// so repeated durable hops cannot degrade the payload.
			second, err := json.Marshal(restored)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(raw, second) {
				t.Fatalf("round trip is not idempotent:\n%s\n%s", raw, second)
			}
		})
	}
}

// A details value carrying only the registry title must not gain a spurious
// detail when it is replayed.
func TestDetailsRoundTripKeepsEmptyDetailEmpty(t *testing.T) {
	original := New(CodeBudgetDenied, "")
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var restored Details
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Detail != "" {
		t.Fatalf("title fallback became a detail: %q", restored.Detail)
	}
	if restored.Message != original.Title {
		t.Fatalf("message = %q, want the registry title", restored.Message)
	}
}
