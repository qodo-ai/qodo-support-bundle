package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
)

type byteReader struct {
	reader io.Reader
}

func (reader byteReader) Read(buffer []byte) (int, error) {
	return reader.reader.Read(buffer[:1])
}

func TestContextDisplayLabelShowsCompactFriendlyGKEName(t *testing.T) {
	t.Parallel()
	const contextName = "gke_codium-development_us-central1_development-cluster"
	got := contextDisplayLabel(contextName, "")
	if got != "development-cluster (codium-development)" {
		t.Fatalf("label=%q", got)
	}
}

func TestContextDisplayLabelMarksOnlyActualCurrentContext(t *testing.T) {
	t.Parallel()
	const current = "gke_project_us-central1_current"
	explicitDefault := contextDisplayLabel(
		"gke_project_us-central1_flag-selected",
		current,
	)
	actualCurrent := contextDisplayLabel(current, current)

	if strings.Contains(explicitDefault, "CURRENT") {
		t.Fatalf("flag default mislabeled as current: %q", explicitDefault)
	}
	if !strings.Contains(actualCurrent, "CURRENT") {
		t.Fatalf("actual current marker missing: %q", actualCurrent)
	}
}

func TestContextDisplayLabelLeavesUnknownFormatsUnchanged(t *testing.T) {
	t.Parallel()
	const contextName = "customer-context"
	if got := contextDisplayLabel(contextName, ""); got != contextName {
		t.Fatalf("unknown context label=%q", got)
	}
}

func TestProductionContextDetectionIsConservative(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		contextName string
		want        bool
	}{
		{"gke_project_us-central1_prod", true},
		{"gke_project_us-central1_production-cluster", true},
		{"gke_production-project_us-central1_development", false},
		{"customer-production-context", false},
		{"gke_project_us-central1_product", false},
	} {
		if got := isProductionContext(test.contextName); got != test.want {
			t.Fatalf("context=%q production=%t want=%t", test.contextName, got, test.want)
		}
	}
}

func TestWizardCopyIncludesStepsAndPersistentHelp(t *testing.T) {
	t.Parallel()
	if got := wizardStepTitle(1, "Choose a Kubernetes cluster"); got !=
		"Step 1 of 5 · Choose a Kubernetes cluster" {
		t.Fatalf("step title=%q", got)
	}
	for _, expected := range []string{"arrows", "/", "Enter", "Ctrl+C"} {
		if !strings.Contains(wizardNavigationHelp, expected) {
			t.Fatalf("navigation help missing %q: %q", expected, wizardNavigationHelp)
		}
	}
	for _, expected := range []string{"arrows", "Space", "x", "Enter"} {
		if !strings.Contains(wizardMultiSelectHelp, expected) {
			t.Fatalf("multi-select help missing %q: %q", expected, wizardMultiSelectHelp)
		}
	}
}

func TestFullContextSelectKeepsFilteringEnabled(t *testing.T) {
	t.Parallel()
	value := ""
	field := newContextSelect(
		"Available clusters",
		contextOptions([]string{"alpha", "beta"}, "", false),
		&value,
	)
	if !field.GetFiltering() {
		t.Fatal("full context selector disabled Huh filtering")
	}
	description := field.View()
	if !strings.Contains(description, "/") {
		t.Fatalf("filter help is not visible: %q", description)
	}
}

func TestContextOptionsKeepDisplaySeparateFromKubectlValue(t *testing.T) {
	t.Parallel()
	const contextName = "gke_project_us-central1_production"
	options := contextOptions([]string{contextName}, contextName, false)
	if len(options) != 1 {
		t.Fatalf("options=%v", options)
	}
	if options[0].Value != contextName {
		t.Fatalf("option value changed: %q", options[0].Value)
	}
	if !strings.Contains(options[0].Key, "CURRENT") {
		t.Fatalf("option label=%q", options[0].Key)
	}
}

func TestPrimaryContextOptionsOnlyShowPrimaryAndChangeChoice(t *testing.T) {
	t.Parallel()
	const (
		primary = "gke_project_us-central1_primary"
		current = "gke_project_us-central1_current"
	)
	options := primaryContextOptions(primary, current)
	if len(options) != 2 {
		t.Fatalf("options=%v", options)
	}
	if options[0].Value != primary ||
		options[0].Key != "primary (project)" ||
		options[1].Value != chooseAnotherContextValue ||
		options[1].Key != "Choose another cluster" {
		t.Fatalf("options=%v", options)
	}
}

func TestPrimaryContextOptionsMarkOnlyKubeconfigCurrent(t *testing.T) {
	t.Parallel()
	const current = "gke_project_us-central1_current"
	options := primaryContextOptions(current, current)
	if len(options) != 2 || !strings.Contains(options[0].Key, "CURRENT") {
		t.Fatalf("options=%v", options)
	}
}

func TestPrimaryContextOptionsWithoutCurrentOnlyOfferChange(t *testing.T) {
	t.Parallel()
	options := primaryContextOptions("", "")
	if len(options) != 1 ||
		options[0].Value != chooseAnotherContextValue {
		t.Fatalf("options=%v", options)
	}
}

func TestContextOptionsDisambiguateOnlyDuplicateFriendlyLabels(t *testing.T) {
	t.Parallel()
	contexts := []string{
		"gke_project_us-central1_shared",
		"gke_project_europe-west1_shared",
		"gke_other_us-central1_unique",
		"customer-context",
		"shared (project)",
	}
	options := contextOptions(contexts, "", false)
	if len(options) != len(contexts) {
		t.Fatalf("options=%v", options)
	}
	for index := 0; index < 2; index++ {
		if !strings.Contains(options[index].Key, contexts[index]) {
			t.Fatalf("duplicate option was not disambiguated: %q", options[index].Key)
		}
	}
	if strings.Contains(options[2].Key, contexts[2]) {
		t.Fatalf("unique friendly option dumped raw context: %q", options[2].Key)
	}
	if options[3].Key != contexts[3] {
		t.Fatalf("unknown context changed: %q", options[3].Key)
	}
	if options[4].Key == contexts[4] ||
		!strings.Contains(options[4].Key, contexts[4]) ||
		!strings.Contains(options[0].Key, contexts[0]) ||
		!strings.Contains(options[1].Key, contexts[1]) {
		t.Fatalf("cross-format collision was not disambiguated: %v", options)
	}
	for index, option := range options {
		if option.Value != contexts[index] {
			t.Fatalf("option %d value=%q want=%q", index, option.Value, contexts[index])
		}
	}
}

func TestContextOptionsDisambiguateGKEAndRawLabelCollision(t *testing.T) {
	t.Parallel()
	contexts := []string{
		"gke_project_us-central1_shared",
		"shared (project)",
	}
	options := contextOptions(contexts, "", false)
	if len(options) != len(contexts) {
		t.Fatalf("options=%v", options)
	}
	if options[0].Key == options[1].Key {
		t.Fatalf("distinct contexts have identical labels: %v", options)
	}
	for index, option := range options {
		if option.Value != contexts[index] ||
			!strings.Contains(option.Key, contexts[index]) {
			t.Fatalf("option %d was not safely disambiguated: %v", index, options)
		}
	}
}

func TestValidateContextChoiceAllowsChooseAnotherTransition(t *testing.T) {
	t.Parallel()
	if err := validateContextChoice(chooseAnotherContextValue); err != nil {
		t.Fatalf("choose another rejected: %v", err)
	}
	if err := validateContextChoice(""); err == nil {
		t.Fatal("empty context choice accepted")
	}
}

func TestInteractiveSummaryShowsExactRawContext(t *testing.T) {
	t.Parallel()
	const contextName = "gke_project_us-central1_customer"
	got := interactiveSummary(
		contextName,
		"all",
		true,
		nil,
		"30m",
		"",
		nil,
		"",
	)
	if !strings.Contains(got, contextName) {
		t.Fatalf("summary omitted exact context: %q", got)
	}
}

func TestAccessibleWizardUsesPlainModeAndTheme(t *testing.T) {
	t.Setenv("ACCESSIBLE", "1")
	forms := newHuhInteractiveForms()
	if !forms.Accessible {
		t.Fatal("ACCESSIBLE did not enable plain form mode")
	}
	if forms.Theme == nil {
		t.Fatal("wizard theme is nil")
	}
}

func TestAccessibleContextChoiceExpandsOnlyAfterChooseAnother(t *testing.T) {
	t.Parallel()
	const (
		current   = "gke_project_us-central1_current"
		alternate = "gke_project_us-central1_alternate"
	)
	settings := interactiveSettings{Context: current}
	var output bytes.Buffer
	err := (huhInteractiveForms{Accessible: true, Theme: qodoScoutTheme()}).
		ChooseContext(
			context.Background(),
			&settings,
			interactiveContextCatalog{
				Names:   []string{current, alternate},
				Current: current,
			},
			byteReader{reader: strings.NewReader("2\n2\n")},
			&output,
		)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Context != alternate {
		t.Fatalf("selected context=%q", settings.Context)
	}
	parts := strings.SplitN(output.String(), "Available clusters", 2)
	if len(parts) != 2 {
		t.Fatalf("full context list did not open:\n%s", output.String())
	}
	if strings.Contains(parts[0], "alternate (project)") {
		t.Fatalf("alternate leaked onto primary screen:\n%s", parts[0])
	}
	for _, expected := range []string{
		"CURRENT · current (project)",
		"Choose another cluster",
		"alternate (project)",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q:\n%s", expected, output.String())
		}
	}
}

func TestAccessibleAlternateProductionWarningCanGoBack(t *testing.T) {
	t.Parallel()
	const (
		current    = "gke_project_us-central1_current"
		production = "gke_project_us-central1_production"
	)
	settings := interactiveSettings{Context: current}
	var output bytes.Buffer
	err := (huhInteractiveForms{Accessible: true, Theme: qodoScoutTheme()}).
		ChooseContext(
			context.Background(),
			&settings,
			interactiveContextCatalog{
				Names:   []string{current, production},
				Current: current,
			},
			byteReader{reader: strings.NewReader("2\n2\nn\n1\n")},
			&output,
		)
	if err != nil {
		t.Fatal(err)
	}
	if settings.Context != current {
		t.Fatalf("context after production back=%q", settings.Context)
	}
	if !strings.Contains(output.String(), productionContextWarning(production)) {
		t.Fatalf("production warning missing:\n%s", output.String())
	}
}

func TestProductionWarningCopyIsFactual(t *testing.T) {
	t.Parallel()
	got := productionContextWarning("gke_project_us-central1_production")
	for _, expected := range []string{
		"read-only",
		"sensitive production diagnostics",
		"gke_project_us-central1_production",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("warning %q missing %q", got, expected)
		}
	}
}
