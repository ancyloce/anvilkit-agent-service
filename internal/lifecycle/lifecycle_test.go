package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestReadinessMatrixFailsEachCriticalDependency(t *testing.T) {
	names := []string{"workflow-db", "migration-compatibility", "recovery-register", "rpo0-journal", "authoritative-time", "signing", "contract-material", "policy-material", "protected-audit"}
	for failed := range names {
		dependencies := make([]Dependency, 0, len(names))
		for index, name := range names {
			index := index
			dependencies = append(dependencies, Dependency{Name: name, Check: CheckFunc(func(context.Context) error {
				if index == failed {
					return errors.New("unavailable")
				}
				return nil
			})})
		}
		if NewReadiness(dependencies...).Status(context.Background()).Ready {
			t.Fatalf("readiness stayed true with %s unavailable", names[failed])
		}
	}
}

func TestProviderIsNotABaseReadinessDependency(t *testing.T) {
	if !NewReadiness().Status(context.Background()).Ready {
		t.Fatal("provider eligibility must not affect base readiness")
	}
}

func TestShutdownOrder(t *testing.T) {
	var got []Stage
	hook := func(stage Stage) Hook {
		return Hook{Name: "hook", Stage: stage, Run: func(context.Context) error { got = append(got, stage); return nil }}
	}
	shutdown := NewShutdown(hook(CleanupLeases), hook(CheckpointExecutors), hook(StopIngress), hook(GuideStreamReconnect))
	if err := shutdown.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []Stage{StopIngress, GuideStreamReconnect, CheckpointExecutors, CleanupLeases}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}
