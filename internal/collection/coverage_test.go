package collection

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestCoverageStatesHaveExactWireValuesAndValidity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		state CoverageState
		wire  string
	}{
		{CoverageComplete, "complete"},
		{CoveragePartial, "partial"},
		{CoverageUnavailable, "unavailable"},
		{CoverageNotRequested, "not_requested"},
	}
	for _, test := range tests {
		if test.state.String() != test.wire {
			t.Errorf("%v.String() = %q, want %q", test.state, test.state.String(), test.wire)
		}
		if !test.state.Valid() {
			t.Errorf("%q should be valid", test.state)
		}
		encoded, err := json.Marshal(test.state)
		if err != nil {
			t.Fatalf("marshal %q: %v", test.state, err)
		}
		if string(encoded) != `"`+test.wire+`"` {
			t.Errorf("json.Marshal(%q) = %s, want %q", test.state, encoded, `"`+test.wire+`"`)
		}
	}
	for _, state := range []CoverageState{"", "Complete", "unknown"} {
		if state.Valid() {
			t.Errorf("%q should be invalid", state)
		}
	}
}

func TestCoverageJSONUsesExactKeysAndOmitsUnsetTimestamps(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Coverage{
		State:         CoveragePartial,
		RetainedBytes: 42,
		RecordCount:   3,
		Truncated:     true,
		Reason:        "retention limit",
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"state":"partial","retained_bytes":42,"record_count":3,"truncated":true,"reason":"retention limit"}`
	if string(encoded) != want {
		t.Fatalf("json.Marshal(Coverage) = %s, want %s", encoded, want)
	}
}

func TestCoverageJSONIncludesTimestampFields(t *testing.T) {
	t.Parallel()

	requestedStart := time.Date(2026, 9, 1, 1, 2, 3, 0, time.UTC)
	requestedEnd := requestedStart.Add(time.Hour)
	actualStart := requestedStart.Add(10 * time.Minute)
	actualEnd := requestedEnd.Add(-10 * time.Minute)
	encoded, err := json.Marshal(Coverage{
		State:          CoverageComplete,
		RequestedStart: &requestedStart,
		RequestedEnd:   &requestedEnd,
		ActualStart:    &actualStart,
		ActualEnd:      &actualEnd,
		RetainedBytes:  128,
		RecordCount:    8,
	})
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"state":"complete","requested_start":"2026-09-01T01:02:03Z","requested_end":"2026-09-01T02:02:03Z","actual_start":"2026-09-01T01:12:03Z","actual_end":"2026-09-01T01:52:03Z","retained_bytes":128,"record_count":8,"truncated":false}`
	if string(encoded) != want {
		t.Fatalf("json.Marshal(Coverage) = %s, want %s", encoded, want)
	}
}

func TestInitializeCoverageMarksRequestedAndReservedSources(t *testing.T) {
	t.Parallel()

	got := InitializeCoverage([]Source{
		SourceKubernetes,
		SourcePrometheus,
		SourceKubernetes,
		Source("invalid"),
	})
	want := map[Source]Coverage{
		SourceKubernetes: {State: CoverageUnavailable},
		SourceZitadel:    {State: CoverageNotRequested},
		SourceWorkload:   {State: CoverageNotRequested},
		SourcePrometheus: {State: CoverageUnavailable},
		SourcePhoenix:    {State: CoverageNotRequested},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("InitializeCoverage() = %#v, want %#v", got, want)
	}
	if _, exists := got[Source("invalid")]; exists {
		t.Fatal("InitializeCoverage retained invalid requested source")
	}
}

func TestInitializeCoverageReturnsFreshMap(t *testing.T) {
	t.Parallel()

	first := InitializeCoverage(nil)
	first[SourceKubernetes] = Coverage{State: CoverageComplete}
	first[Source("injected")] = Coverage{State: CoverageComplete}

	second := InitializeCoverage(nil)
	if second[SourceKubernetes].State != CoverageNotRequested {
		t.Fatalf("InitializeCoverage shares mutable state: %#v", second)
	}
	if _, exists := second[Source("injected")]; exists {
		t.Fatalf("InitializeCoverage shares map entries: %#v", second)
	}
}
