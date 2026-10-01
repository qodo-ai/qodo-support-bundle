package app

import (
	"strings"
	"testing"
)

func TestContextDisplayLabelShowsFriendlyGKENameAndExactValue(t *testing.T) {
	t.Parallel()
	const contextName = "gke_codium-development_us-central1_development-cluster"
	got := contextDisplayLabel(contextName, "")
	for _, expected := range []string{
		"development-cluster",
		"us-central1",
		"codium-development",
		contextName,
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("label %q missing %q", got, expected)
		}
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
	if !strings.Contains(options[0].Key, "CURRENT") ||
		!strings.Contains(options[0].Key, contextName) {
		t.Fatalf("option label=%q", options[0].Key)
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
