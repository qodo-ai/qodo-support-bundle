package collection

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSourcesHaveExactUniqueWireValues(t *testing.T) {
	t.Parallel()

	want := []Source{
		SourceKubernetes,
		SourceZitadel,
		SourceWorkload,
		SourcePrometheus,
		SourcePhoenix,
	}
	wantStrings := []string{
		"kubernetes",
		"zitadel",
		"workload",
		"prometheus",
		"phoenix",
	}

	got := SupportedSources()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("SupportedSources() = %v, want %v", got, want)
	}

	seen := make(map[Source]bool, len(got))
	for i, source := range got {
		if source.String() != wantStrings[i] {
			t.Errorf("%v.String() = %q, want %q", source, source.String(), wantStrings[i])
		}
		if seen[source] {
			t.Errorf("duplicate supported source %q", source)
		}
		seen[source] = true

		encoded, err := json.Marshal(source)
		if err != nil {
			t.Fatalf("marshal %q: %v", source, err)
		}
		if string(encoded) != `"`+wantStrings[i]+`"` {
			t.Errorf("json.Marshal(%q) = %s, want %q", source, encoded, `"`+wantStrings[i]+`"`)
		}
	}
}

func TestSourceValidity(t *testing.T) {
	t.Parallel()

	for _, source := range SupportedSources() {
		if !source.Valid() {
			t.Errorf("%q should be valid", source)
		}
	}
	for _, source := range []Source{"", "Kubernetes", "unknown"} {
		if source.Valid() {
			t.Errorf("%q should be invalid", source)
		}
	}
}

func TestSupportedSourcesReturnsFreshSlice(t *testing.T) {
	t.Parallel()

	first := SupportedSources()
	first[0] = Source("mutated")

	second := SupportedSources()
	if second[0] != SourceKubernetes {
		t.Fatalf("SupportedSources shares mutable storage: %v", second)
	}
}
