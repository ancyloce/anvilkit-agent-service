package postgres

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ancyloce/anvilkit-agent-service/internal/events"
)

// The durable public event store has exactly one write path, and it is the
// projector's. This test is the structural guard on that: it fails the moment
// any exported entry point of this package accepts a stored event, a rendered
// projection, or anything else carrying a caller-supplied source evidence
// reference or projector digest.
//
// It is deliberately a property of the package's shape rather than of one
// method's behaviour. A bypass is not usually added as an obviously wrong
// write — it is added as a convenience for a test, and the shape is what
// notices.
func TestNoExportedWritePathAcceptsCallerSuppliedProvenance(t *testing.T) {
	forbidden := map[reflect.Type]string{
		reflect.TypeOf(events.Event{}):     "a stored public event",
		reflect.TypeOf(events.Projected{}): "a rendered projection with its provenance",
	}
	for _, receiver := range []reflect.Type{
		reflect.TypeOf(&Reader{}),
		reflect.TypeOf(&Inbox{}),
		reflect.TypeOf(&ProjectionWriter{}),
		reflect.TypeOf(&EvidenceStore{}),
		reflect.TypeOf(&StreamCursors{}),
	} {
		for index := 0; index < receiver.NumMethod(); index++ {
			method := receiver.Method(index)
			signature := method.Type
			for parameter := 0; parameter < signature.NumIn(); parameter++ {
				argument := signature.In(parameter)
				for argument.Kind() == reflect.Pointer || argument.Kind() == reflect.Slice {
					argument = argument.Elem()
				}
				if description, refused := forbidden[argument]; refused {
					t.Fatalf("%s.%s accepts %s from its caller: the projector owns provenance, so no exported write path may take one", receiver.Elem().Name(), method.Name, description)
				}
			}
		}
	}
}

// The Fact a projection is written from carries the producing component's
// material and the run-local correlation — and no provenance. Provenance is
// derived, so there is no field on the input for a caller to fill in.
func TestTheProjectionInputCarriesNoProvenanceField(t *testing.T) {
	for _, shape := range []reflect.Type{reflect.TypeOf(Fact{}), reflect.TypeOf(events.Projection{})} {
		for index := 0; index < shape.NumField(); index++ {
			field := shape.Field(index)
			lowered := strings.ToLower(field.Name)
			if !field.IsExported() {
				continue
			}
			if strings.Contains(lowered, "evidenceid") || strings.Contains(lowered, "projectordigest") {
				t.Fatalf("%s.%s is a caller-settable provenance field", shape.Name(), field.Name)
			}
		}
	}
}
