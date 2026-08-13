package recovery

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestOperationalRunbookCoversAllFourteenIndexedSubjects(t *testing.T) {
	body, err := os.ReadFile("../../../../docs/runbooks/agent-service-operations.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "## Deploy and rollback") {
		t.Fatal("deploy/rollback procedure missing")
	}
	for subject := 1; subject <= 14; subject++ {
		if !strings.Contains(text, fmt.Sprintf("## %d.", subject)) {
			t.Fatalf("runbook subject %d missing", subject)
		}
	}
	if strings.Count(text, "Exercise:") < 14 || !strings.Contains(text, "Platform SRE") || !strings.Contains(text, "Security") || !strings.Contains(text, "Pending Gates F/G/H") {
		t.Fatal("runbook exercise or review posture is incomplete")
	}
}
