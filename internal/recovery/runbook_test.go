package recovery

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The operational recovery invariant is verified against tracked, machine
// readable data inside this repository. It used to be verified by grepping a
// runbook document that lives outside the tracked tree, which made the check
// unrunnable from a clean checkout; the invariant itself is unchanged and is
// now enforced on both sides — the index the service declares and the tracked
// golden the runbook is written against must agree exactly.
func TestOperationalProceduresCoverAllFourteenIndexedSubjects(t *testing.T) {
	declared := OperationalProcedures()
	if err := declared.Validate(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/operational-subjects.json")
	if err != nil {
		t.Fatal(err)
	}
	tracked, err := ParseOperationalIndex(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracked.Validate(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(declared, tracked) {
		t.Fatal("the declared operational index and the tracked golden have drifted")
	}
	for subject := 1; subject <= RequiredOperationalSubjects; subject++ {
		found := false
		for _, entry := range tracked.Subjects {
			if entry.Index == subject {
				found = true
			}
		}
		if !found {
			t.Fatalf("operational subject %d missing", subject)
		}
	}
	exercises := 0
	for _, entry := range tracked.Subjects {
		if entry.Exercise != "" {
			exercises++
		}
	}
	if exercises != RequiredOperationalSubjects {
		t.Fatalf("subjects carrying an exercise = %d, want %d", exercises, RequiredOperationalSubjects)
	}
	posture := map[string]string{}
	for _, entry := range tracked.Review {
		posture[entry.Reviewer] = entry.PendingGates
	}
	if posture["Platform SRE"] != "Pending Gates F/G/H" || posture["Security"] != "Pending Gates F/G" {
		t.Fatalf("review posture is incomplete: %v", posture)
	}
}

// A malformed or incomplete index must fail closed rather than be tolerated.
func TestOperationalIndexFailsClosedOnIncompleteData(t *testing.T) {
	base := OperationalProcedures()
	cases := map[string]func(*OperationalIndex){
		"missing deploy procedure": func(i *OperationalIndex) { i.DeployAndRollback = "" },
		"dropped subject":          func(i *OperationalIndex) { i.Subjects = i.Subjects[:len(i.Subjects)-1] },
		"reindexed subject":        func(i *OperationalIndex) { i.Subjects[3].Index = 9 },
		"subject without exercise": func(i *OperationalIndex) { i.Subjects[5].Exercise = "" },
		"subject without reviewer": func(i *OperationalIndex) { i.Subjects[7].Reviewers = nil },
		"duplicate exercise":       func(i *OperationalIndex) { i.Subjects[2].Exercise = i.Subjects[1].Exercise },
		"unknown reviewer":         func(i *OperationalIndex) { i.Subjects[0].Reviewers = []string{"Someone Else"} },
		"missing review posture":   func(i *OperationalIndex) { i.Review = i.Review[:1] },
		"posture without gates":    func(i *OperationalIndex) { i.Review[1].PendingGates = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			broken, err := ParseOperationalIndex(raw)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&broken)
			if err := broken.Validate(); err == nil {
				t.Fatal("incomplete operational index was accepted")
			}
		})
	}
	if _, err := ParseOperationalIndex([]byte(`{"deployAndRollback":"x","unknown":1}`)); err == nil {
		t.Fatal("an index carrying unknown fields was accepted")
	}
	if _, err := ParseOperationalIndex([]byte(`{"deployAndRollback":"x"} {}`)); err == nil {
		t.Fatal("an index with trailing JSON was accepted")
	}
}
