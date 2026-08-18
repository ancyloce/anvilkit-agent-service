package persistence

import (
	"strings"
	"testing"
)

func TestValidateColocatedIgnoresRoleCredentials(t *testing.T) {
	err := ValidateColocated(
		DatabaseTarget{Name: "control", URL: "postgres://control:secret@db.example.invalid:5432/anvilkit"},
		DatabaseTarget{Name: "events", URL: "postgres://events:different@DB.EXAMPLE.INVALID:5432/anvilkit"},
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateColocatedRejectsDifferentDatabaseOrServer(t *testing.T) {
	tests := map[string]string{
		"database": "postgres://events@db.example.invalid:5432/events",
		"server":   "postgres://events@other-db.example.invalid:5432/anvilkit",
		"port":     "postgres://events@db.example.invalid:5433/anvilkit",
	}
	for name, target := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateColocated(
				DatabaseTarget{Name: "control", URL: "postgres://control@db.example.invalid:5432/anvilkit"},
				DatabaseTarget{Name: "events", URL: target},
			)
			if err == nil || !strings.Contains(err.Error(), "control and events") {
				t.Fatalf("split target was accepted: %v", err)
			}
		})
	}
}
