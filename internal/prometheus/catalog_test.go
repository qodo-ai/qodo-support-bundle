package prometheus

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuiltinCatalogV1Contract(t *testing.T) {
	t.Parallel()
	const goldenSHA256 = "cbf9d2de97a2f055eda836c1dee38e2846a47fdaa6d0c3afb15d473b34765b22"
	if digest := fmt.Sprintf("%x", sha256.Sum256(catalogV1JSON)); digest != goldenSHA256 {
		t.Fatalf("catalog golden hash = %s, want %s", digest, goldenSHA256)
	}
	catalog := BuiltinCatalog()
	if catalog.Version != CatalogVersion {
		t.Fatalf("version = %q", catalog.Version)
	}
	if err := validateCatalog(catalog); err != nil {
		t.Fatalf("validateCatalog() error = %v", err)
	}
	expectedCategories := map[string]bool{
		"pod_container_cpu":             false,
		"memory_working_set_and_limits": false,
		"restart_oom":                   false,
		"replica_availability":          false,
		"request_rate":                  false,
		"error_rate":                    false,
		"latency":                       false,
		"queue_saturation":              false,
		"storage_pressure":              false,
	}
	type contractEntry struct {
		ID       string `json:"id"`
		Metric   string `json:"metric"`
		Selector string `json:"selector"`
	}
	fixture, err := os.ReadFile("testdata/catalog_v1_contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract []contractEntry
	if err := json.Unmarshal(fixture, &contract); err != nil {
		t.Fatal(err)
	}
	if len(contract) != len(catalog.Queries) {
		t.Fatalf("contract entries = %d, queries = %d", len(contract), len(catalog.Queries))
	}
	for index, query := range catalog.Queries {
		expectedCategories[query.Category] = true
		if query.ID != contract[index].ID ||
			!strings.Contains(query.PromQL, contract[index].Metric) ||
			!strings.Contains(query.PromQL, contract[index].Selector) {
			t.Fatalf("query %d does not satisfy contract: %+v", index, query)
		}
		if query.StepSeconds != int64(time.Minute/time.Second) {
			t.Fatalf("%s step = %d", query.ID, query.StepSeconds)
		}
	}
	for category, found := range expectedCategories {
		if !found {
			t.Fatalf("missing category %q", category)
		}
	}
}

func TestBuiltinCatalogIsImmutableCopy(t *testing.T) {
	t.Parallel()
	first := BuiltinCatalog()
	first.Version = "changed"
	first.Queries[0].PromQL = "caller supplied"
	first.Queries[0].RetainLabels[0] = "secret"
	second := BuiltinCatalog()
	if second.Version != CatalogVersion ||
		second.Queries[0].PromQL == "caller supplied" ||
		second.Queries[0].RetainLabels[0] == "secret" {
		t.Fatal("BuiltinCatalog returned mutable package state")
	}
}

func TestCatalogRejectsUnknownFieldsDuplicatesAndMissingCategories(t *testing.T) {
	t.Parallel()
	tests := [][]byte{
		[]byte(`{"version":"v1","version":"v1","queries":[]}`),
		[]byte(`{"version":"v1","queries":[],"extra":true}`),
		[]byte(`{"version":"v1","queries":[{"id":"only","category":"request_rate","description":"x","promql":"up","step_seconds":60,"retain_labels":["job"]}]}`),
	}
	for _, input := range tests {
		if _, err := decodeCatalog(input); err == nil {
			t.Fatalf("decodeCatalog(%s) unexpectedly succeeded", input)
		}
	}
}

func TestConfigDefaultsAndLimits(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	config := Config{
		Namespace:  "observability",
		Namespaces: []string{"team-a"},
		Start:      start,
		End:        start.Add(time.Hour),
	}.WithDefaults()
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	defaults := DefaultConfig()
	config.Namespace = ""
	config.Namespaces = nil
	config.Start = time.Time{}
	config.End = time.Time{}
	if !reflect.DeepEqual(config, defaults) {
		t.Fatalf("defaults mismatch:\n got: %+v\nwant: %+v", config, defaults)
	}

	invalid := Config{
		Namespace:  "observability",
		Namespaces: []string{"team-a"},
		Start:      start,
		End:        start.Add(MaximumWindow + time.Second),
	}
	if err := invalid.Validate(); err == nil {
		t.Fatal("oversized window accepted")
	}
	invalid.End = start.Add(time.Hour)
	invalid.Step = MinimumStep - time.Second
	if err := invalid.Validate(); err == nil {
		t.Fatal("undersized step accepted")
	}
	invalid.Step = 0
	invalid.MaxResponseBytes = MaximumResponseBytes + 1
	if err := invalid.Validate(); err == nil {
		t.Fatal("oversized response limit accepted")
	}
}

func TestNamespaceScopeRenderingIsDeterministicAnchoredAndURLSafe(t *testing.T) {
	t.Parallel()
	callerNamespaces := []string{"team-b", "team-a"}
	config := testConfig()
	config.Namespaces = callerNamespaces
	config = config.WithDefaults()
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(callerNamespaces, []string{"team-b", "team-a"}) {
		t.Fatalf("caller input mutated: %#v", callerNamespaces)
	}
	if !reflect.DeepEqual(config.Namespaces, []string{"team-a", "team-b"}) {
		t.Fatalf("normalized scope = %#v", config.Namespaces)
	}
	scope, err := namespaceScopeRegex(config)
	if err != nil {
		t.Fatal(err)
	}
	if scope != "^(?:team-a|team-b)$" {
		t.Fatalf("scope regex = %q", scope)
	}
	rendered, err := renderScopedPromQL(BuiltinCatalog().Queries[0], config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, namespaceRegexToken) ||
		!strings.Contains(rendered, `namespace=~"^(?:team-a|team-b)$"`) {
		t.Fatalf("rendered query = %q", rendered)
	}
	encoded := url.Values{"query": {rendered}}.Encode()
	decoded, err := url.ParseQuery(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Get("query") != rendered {
		t.Fatalf("URL round trip changed query: %q", decoded.Get("query"))
	}
}

func TestAllNamespacesUsesFixedSafeRegex(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Namespaces = nil
	config.AllNamespaces = true
	config = config.WithDefaults()
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	rendered, err := renderScopedPromQL(BuiltinCatalog().Queries[0], config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered, `namespace=~".*"`) ||
		strings.Contains(rendered, namespaceRegexToken) {
		t.Fatalf("rendered all-namespace query = %q", rendered)
	}
}

func TestInvalidNamespaceScopesFailClosed(t *testing.T) {
	t.Parallel()
	tooMany := make([]string, MaximumNamespaces+1)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("ns-%03d", index)
	}
	tests := []struct {
		name          string
		namespaces    []string
		allNamespaces bool
	}{
		{name: "empty explicit"},
		{name: "all with explicit", namespaces: []string{"team-a"}, allNamespaces: true},
		{name: "duplicate", namespaces: []string{"team-a", "team-a"}},
		{name: "oversized", namespaces: tooMany},
		{name: "regex injection", namespaces: []string{`team-a|.*`}},
		{name: "selector injection", namespaces: []string{`team-a"}`}},
		{name: "slash", namespaces: []string{"team/a"}},
		{name: "uppercase", namespaces: []string{"Team-a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := testConfig()
			config.Namespaces = test.namespaces
			config.AllNamespaces = test.allNamespaces
			if err := config.Validate(); err == nil {
				t.Fatalf("unsafe scope accepted: %#v", config)
			}
		})
	}
}

func TestCatalogRejectsMissingOrUnapprovedScopeTokens(t *testing.T) {
	t.Parallel()
	for name, mutate := range map[string]func(*Query){
		"missing selector scope": func(query *Query) {
			query.PromQL = strings.Replace(
				query.PromQL,
				namespaceSelectorTemplate,
				`namespace=~".*"`,
				1,
			)
		},
		"unapproved token": func(query *Query) {
			query.PromQL = strings.Replace(
				query.PromQL,
				namespaceRegexToken,
				"{{caller_scope}}",
				1,
			)
		},
		"wrong label": func(query *Query) {
			query.PromQL = strings.Replace(
				query.PromQL,
				namespaceSelectorTemplate,
				`other_namespace=~"`+namespaceRegexToken+`"`,
				1,
			)
		},
	} {
		t.Run(name, func(t *testing.T) {
			catalog := BuiltinCatalog()
			mutate(&catalog.Queries[0])
			if err := validateCatalog(catalog); err == nil {
				t.Fatal("unsafe catalog accepted")
			}
		})
	}
}
