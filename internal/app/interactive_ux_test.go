package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
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

func TestWizardTitlesUseUnicodeAndASCIIFallbacks(t *testing.T) {
	t.Parallel()
	if got := wizardTitle(true); got !=
		"Qodo Scout · Read-only on-prem diagnostics" {
		t.Fatalf("Unicode title=%q", got)
	}
	if got := wizardTitle(false); got !=
		"Qodo Scout - Read-only on-prem diagnostics" {
		t.Fatalf("ASCII title=%q", got)
	}
	if got := wizardSetupTitle(true); got != "Qodo Scout · Setup" {
		t.Fatalf("Unicode setup title=%q", got)
	}
	if got := wizardSetupTitle(false); got != "Qodo Scout - Setup" {
		t.Fatalf("ASCII setup title=%q", got)
	}
}

func TestWizardUsesApprovedCombinedSafetySentence(t *testing.T) {
	t.Parallel()
	const want = "Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted."
	if got := securityStatement(true); got != want {
		t.Fatalf("security statement:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if got := securityStatement(false); got != want {
		t.Fatalf("ASCII security statement:\ngot:\n%s\nwant:\n%s", got, want)
	}
	for _, forbidden := range []string{
		"logs never contain secrets",
		"never collects secrets from logs",
		"guaranteed secret-free",
		"secret-free",
		"review before sharing",
	} {
		if strings.Contains(strings.ToLower(securityStatement(true)), forbidden) {
			t.Fatalf("security statement makes absolute log claim: %q", securityStatement(true))
		}
	}
}

func TestWizardProgressHeaderShowsAllFiveStepStates(t *testing.T) {
	t.Parallel()
	const wantUnicode = "✓ Cluster  ● Scope  ○ Logs  ○ Sources  ○ Confirm"
	if got := wizardProgressHeader(2, true); got != wantUnicode {
		t.Fatalf("Unicode header=%q want=%q", got, wantUnicode)
	}
	const wantASCII = "[ok] Cluster  [>] Scope  [ ] Logs  [ ] Sources  [ ] Confirm"
	if got := wizardProgressHeader(2, false); got != wantASCII {
		t.Fatalf("ASCII header=%q want=%q", got, wantASCII)
	}
	for step := 1; step <= 5; step++ {
		header := wizardProgressHeader(step, true)
		if strings.Count(header, "✓") != step-1 ||
			strings.Count(header, "●") != 1 ||
			strings.Count(header, "○") != 5-step {
			t.Fatalf("step %d header states=%q", step, header)
		}
	}
}

func TestWizardFieldTitlesPersistHeaderAcrossEveryPage(t *testing.T) {
	t.Parallel()
	pages := []struct {
		step  int
		title string
	}{
		{1, "Cluster"},
		{1, "Available clusters"},
		{1, "Confirm production cluster"},
		{2, "Scope"},
		{2, "Choose namespaces"},
		{3, "Log window"},
		{3, "Custom log window"},
		{4, "Extra sources · optional"},
		{4, "Prometheus namespace"},
		{4, "Phoenix namespace"},
		{4, "Platform namespace"},
		{5, "Output"},
		{5, "Custom path"},
		{5, "Ready to collect"},
	}
	for _, page := range pages {
		got := wizardFieldTitle(page.step, page.title, true, false, 0)
		header := wizardProgressHeader(page.step, true)
		if !strings.HasPrefix(got, header+"\n\n") ||
			strings.Count(got, header) != 1 {
			t.Fatalf("step=%d title=%q got=%q", page.step, page.title, got)
		}
	}
}

func TestStyledWizardHeaderHonorsASCIIMode(t *testing.T) {
	t.Parallel()
	got := ansi.Strip(styledWizardProgressHeader(3, false, true))
	const want = "[ok] Cluster  [ok] Scope  [>] Logs  [ ] Sources  [ ] Confirm"
	if got != want {
		t.Fatalf("styled ASCII header=%q want=%q", got, want)
	}
}

func TestWizardFieldTitleRevertsStateWhenNavigatingBack(t *testing.T) {
	t.Parallel()
	forward := wizardFieldTitle(4, "Extra sources · optional", true, false, 0)
	back := wizardFieldTitle(2, "Scope", true, false, 0)
	if !strings.HasPrefix(forward, wizardProgressHeader(4, true)) ||
		!strings.HasPrefix(back, wizardProgressHeader(2, true)) {
		t.Fatalf("headers did not follow active page: forward=%q back=%q", forward, back)
	}
}

func TestWizardRenderedScreensAdvanceAndRevertFiveStepHeader(t *testing.T) {
	t.Setenv("ACCESSIBLE", "")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("LC_ALL", "")
	t.Setenv("LC_CTYPE", "")

	settings := interactiveSettings{
		Context:                 "gke_project_us-central1_development",
		ContextSummary:          "Development",
		ExcludeSystemNamespaces: true,
		Namespaces:              []string{"qodo"},
		Since:                   45 * time.Minute,
		Prometheus:              true,
		PrometheusNamespace:     "monitoring",
		Phoenix:                 true,
		PhoenixNamespace:        "monitoring",
		Zitadel:                 true,
		PlatformNamespace:       "qodo",
		PlatformPod:             "platform-0",
		PlatformContainer:       "platform",
		Output:                  "/tmp/bundle.tar.gz",
	}
	pages := []struct {
		step  int
		title string
	}{
		{2, "Scope"},
		{2, "Namespaces"},
		{3, "Log window"},
		{3, "Custom log lookback"},
		{4, "Extra sources · optional"},
		{4, "Prometheus namespace"},
		{4, "Phoenix namespace"},
		{4, "Platform namespace"},
		{5, "Output"},
		{5, "Custom path"},
		{5, "Ready to collect"},
	}
	assertScreen := func(form *huh.Form, page struct {
		step  int
		title string
	}) {
		t.Helper()
		screen := ansi.Strip(form.View())
		wantHeader := wizardProgressHeader(page.step, true)
		if strings.Count(screen, wantHeader) != 1 ||
			!strings.Contains(screen, page.title) {
			t.Fatalf(
				"screen %q did not render step %d exactly once:\n%s",
				page.title,
				page.step,
				screen,
			)
		}
		for step := 1; step <= 5; step++ {
			if step != page.step &&
				strings.Contains(screen, wizardProgressHeader(step, true)) {
				t.Fatalf(
					"screen %q retained step %d header while step %d was active:\n%s",
					page.title,
					step,
					page.step,
					screen,
				)
			}
		}
	}
	forms := huhInteractiveForms{
		RunForm: func(
			_ context.Context,
			form *huh.Form,
			_ io.Reader,
			_ io.Writer,
		) error {
			var applyCommand func(tea.Cmd)
			applyCommand = func(command tea.Cmd) {
				if command == nil {
					return
				}
				message := command()
				if batch, ok := message.(tea.BatchMsg); ok {
					for _, child := range batch {
						applyCommand(child)
					}
					return
				}
				_, next := form.Update(message)
				applyCommand(next)
			}
			refresh := func() {
				_, command := form.Update(tea.WindowSizeMsg{Width: 100, Height: 40})
				applyCommand(command)
			}
			refresh()
			for index, page := range pages {
				if index > 0 {
					form.NextGroup()
					refresh()
				}
				assertScreen(form, page)
			}
			for index := len(pages) - 2; index >= 0; index-- {
				form.PrevGroup()
				refresh()
				assertScreen(form, pages[index])
			}
			return nil
		},
	}
	if err := forms.Configure(
		context.Background(),
		&settings,
		[]string{"qodo", "monitoring"},
		strings.NewReader(""),
		io.Discard,
	); err != nil {
		t.Fatal(err)
	}
}

func TestWizardFieldTitleWrapsNarrowHeaderWithoutDroppingSteps(t *testing.T) {
	t.Parallel()
	got := wizardFieldTitle(3, "Log window", false, false, 30)
	for _, step := range []string{"Cluster", "Scope", "Logs", "Sources", "Confirm"} {
		if !strings.Contains(got, step) {
			t.Fatalf("narrow title dropped %q: %q", step, got)
		}
	}
	for _, line := range strings.Split(strings.SplitN(got, "\n\n", 2)[0], "\n") {
		if terminalDisplayWidth(line) > 30 {
			t.Fatalf("narrow header line exceeds width: %q", line)
		}
	}
}

func TestOptionalCollectorCopyAndDefaults(t *testing.T) {
	t.Parallel()
	if got := optionalCollectorDescription(true); got !=
		"Kubernetes data is already included." {
		t.Fatalf("optional collector description=%q", got)
	}
	if got := optionalCollectorDescription(false); got !=
		"Kubernetes data is already included." {
		t.Fatalf("ASCII optional collector description=%q", got)
	}
	options := optionalCollectorOptions()
	want := []struct {
		label string
		value string
	}{
		{"Prometheus", "prometheus"},
		{"Phoenix", "phoenix"},
		{"Zitadel check", "zitadel"},
	}
	if len(options) != len(want) {
		t.Fatalf("options=%v", options)
	}
	for index, expected := range want {
		if options[index].Key != expected.label || options[index].Value != expected.value {
			t.Fatalf("option %d=%+v want=%+v", index, options[index], expected)
		}
	}
	if got := selectedCollectors(interactiveSettings{}); len(got) != 0 {
		t.Fatalf("optional sources selected by default: %v", got)
	}
}

func TestCompactWizardGroupOptions(t *testing.T) {
	t.Parallel()
	assertOptions := func(
		name string,
		got []huh.Option[string],
		want []string,
	) {
		t.Helper()
		if len(got) != len(want) {
			t.Fatalf("%s options=%v", name, got)
		}
		for index, label := range want {
			if got[index].Key != label {
				t.Fatalf("%s option %d=%q want=%q", name, index, got[index].Key, label)
			}
		}
	}
	assertOptions("scope", namespaceScopeOptions(true), []string{
		"All application namespaces",
		"Choose namespaces…",
	})
	assertOptions("logs", logWindowOptions(), []string{
		"30 minutes",
		"1 hour",
		"6 hours",
		"Custom",
	})
	assertOptions("output", outputModeOptions(true), []string{
		"Automatic (~/.qodo-support-bundles)",
		"Custom path…",
	})
	assertOptions("ASCII output", outputModeOptions(false), []string{
		"Automatic (~/.qodo-support-bundles)",
		"Custom path...",
	})
	for _, title := range []string{
		"Scope",
		"Log window",
		"Extra sources · optional",
		"Output",
		"Ready to collect",
	} {
		if got := wizardStepTitle(2, title); got != title {
			t.Fatalf("group title=%q want=%q", got, title)
		}
	}
}

func TestDependentFieldsOnlyAppearForSelectedExtras(t *testing.T) {
	t.Parallel()
	if collectorSettingsVisible(nil, "prometheus") {
		t.Fatal("Prometheus settings visible without selection")
	}
	if !collectorSettingsVisible([]string{"prometheus"}, "prometheus") {
		t.Fatal("Prometheus settings hidden after selection")
	}
	if collectorSettingsVisible([]string{"prometheus"}, "phoenix") {
		t.Fatal("Phoenix settings visible for a different source")
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

func TestWizardGroupsDoNotDuplicateHuhFooterHelp(t *testing.T) {
	t.Parallel()
	for _, accessible := range []bool{false, true} {
		for _, multi := range []bool{false, true} {
			if got := wizardGroupDescription(accessible, multi); got != "" {
				t.Fatalf("group repeats help: %q", got)
			}
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
		options[1].Key != "Choose another…" {
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

func TestContextOptionsDisambiguateCurrentMarkerCollision(t *testing.T) {
	t.Parallel()
	const current = "gke_project_us-central1_shared"
	contexts := []string{
		current,
		"shared (project)  CURRENT",
	}
	options := contextOptions(contexts, current, false)
	if len(options) != len(contexts) {
		t.Fatalf("options=%v", options)
	}
	if options[0].Key == options[1].Key {
		t.Fatalf("current marker collision left identical labels: %v", options)
	}
	for index, option := range options {
		if option.Value != contexts[index] ||
			!strings.Contains(option.Key, contexts[index]) {
			t.Fatalf("option %d was not safely disambiguated: %v", index, options)
		}
	}
}

func TestContextOptionsGuaranteeUniqueFinalLabels(t *testing.T) {
	t.Parallel()
	contexts := []string{
		"gke_project_us-central1_shared",
		"gke_project_europe-west1_shared",
		"shared (project) — gke_project_us-central1_shared",
	}
	options := contextOptions(contexts, "", false)
	if len(options) != len(contexts) {
		t.Fatalf("options=%v", options)
	}
	labels := make(map[string]struct{}, len(options))
	for index, option := range options {
		if option.Value != contexts[index] {
			t.Fatalf("option %d value=%q want=%q", index, option.Value, contexts[index])
		}
		if _, exists := labels[option.Key]; exists {
			t.Fatalf("duplicate final label %q: %v", option.Key, options)
		}
		labels[option.Key] = struct{}{}
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

func TestInteractiveSummaryUsesFriendlyAlignedReview(t *testing.T) {
	t.Parallel()
	const contextName = "gke_project_us-central1_customer"
	got := interactiveSummary(
		contextName,
		"Customer",
		"all",
		true,
		nil,
		"30m",
		"",
		nil,
		"",
		80,
		true,
	)
	if strings.Contains(got, contextName) {
		t.Fatalf("summary dumped unambiguous raw context: %q", got)
	}
	const want = "" +
		"Ready to collect\n" +
		"Cluster   Customer\n" +
		"Scope     All application namespaces\n" +
		"Logs      30 minutes\n" +
		"Extras    None\n" +
		"Output    Automatic\n\n" +
		"! Review before sharing"
	if got != want {
		t.Fatalf("summary:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestInteractiveSummaryUsesNarrowASCIIFallback(t *testing.T) {
	t.Parallel()
	got := interactiveSummary(
		"customer-context",
		"Customer",
		"selected",
		true,
		[]string{"bundle-alon-google"},
		"1h",
		"",
		[]string{"prometheus", "phoenix"},
		"/tmp/bundle.tar.gz",
		32,
		false,
	)
	const want = "" +
		"Ready to collect\n" +
		"Cluster: Customer\n" +
		"Scope: bundle-alon-google\n" +
		"Logs: 1 hour\n" +
		"Extras: Prometheus, Phoenix\n" +
		"Output: /tmp/bundle.tar.gz\n\n" +
		"[!] Review before sharing"
	if got != want {
		t.Fatalf("narrow summary:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestConfirmationContextKeepsRawValueWhenFriendlyLabelsCollide(t *testing.T) {
	t.Parallel()
	const selected = "gke_project_us-central1_shared"
	got := confirmationContextLabel(selected, []string{
		selected,
		"gke_project_europe-west1_shared",
	})
	if !strings.Contains(got, "Shared") || !strings.Contains(got, selected) {
		t.Fatalf("ambiguous context detail=%q", got)
	}
}

func TestConfirmationContextDetectsGKEAndRawLabelCollision(t *testing.T) {
	t.Parallel()
	const gke = "gke_project_us-central1_customer"
	contexts := []string{gke, "Customer"}
	for _, selected := range contexts {
		got := confirmationContextLabel(selected, contexts)
		if !strings.Contains(got, "context:") ||
			!strings.Contains(got, selected) {
			t.Fatalf("selected=%q ambiguous label=%q", selected, got)
		}
	}
}

func TestDiscoveryStatusUsesFriendlySelectedContext(t *testing.T) {
	t.Parallel()
	const raw = "gke_codium-development_us-central1_development-cluster"
	got := discoveryStatusLine(raw, true)
	const want = "Checking read-only Kubernetes access and finding namespaces in Development cluster…"
	if got != want {
		t.Fatalf("discovery status=%q want=%q", got, want)
	}
	if strings.Contains(got, raw) {
		t.Fatalf("discovery status leaked raw context: %q", got)
	}
}

func TestDiscoveryStatusSafelyFallsBackForUnknownContext(t *testing.T) {
	t.Parallel()
	got := discoveryStatusLine("customer-context\x1b[31m\nspoof", true)
	if got != "Checking read-only Kubernetes access and finding namespaces in customer-context [31m spoof…" {
		t.Fatalf("unknown-context fallback=%q", got)
	}
	if strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("unknown-context fallback retained controls: %q", got)
	}
}

func TestDiscoveryStatusSanitizesRecognizedGKEContext(t *testing.T) {
	t.Parallel()
	got := discoveryStatusLine(
		"gke_customer_us-central1_development\x1b[31m-cluster",
		true,
	)
	if strings.ContainsAny(got, "\x1b\n\r") {
		t.Fatalf("recognized GKE context retained controls: %q", got)
	}
	const want = "Checking read-only Kubernetes access and finding namespaces in Development [31m cluster…"
	if got != want {
		t.Fatalf("recognized GKE context=%q want=%q", got, want)
	}
}

func TestDiscoveryStatusCapitalizesUnicodeClusterName(t *testing.T) {
	t.Parallel()
	got := discoveryStatusLine(
		"gke_customer_europe-west1_équipe-cluster",
		true,
	)
	const want = "Checking read-only Kubernetes access and finding namespaces in Équipe cluster…"
	if got != want {
		t.Fatalf("Unicode discovery status=%q want=%q", got, want)
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

func TestQodoThemeUsesSemanticColors(t *testing.T) {
	t.Parallel()
	theme := qodoScoutThemeFor(true)
	palette := qodoScoutColors()
	tests := []struct {
		name string
		got  lipgloss.TerminalColor
		want lipgloss.TerminalColor
	}{
		{"title", theme.Group.Title.GetForeground(), palette.Purple},
		{"focus", theme.Focused.Title.GetForeground(), palette.Purple},
		{"selector", theme.Focused.SelectSelector.GetForeground(), palette.Cyan},
		{"safe selection", theme.Focused.SelectedPrefix.GetForeground(), palette.Green},
		{"failure", theme.Focused.ErrorMessage.GetForeground(), palette.Red},
		{"help", theme.Help.ShortKey.GetForeground(), palette.Neutral},
	}
	for _, test := range tests {
		if fmt.Sprintf("%#v", test.got) != fmt.Sprintf("%#v", test.want) {
			t.Fatalf("%s color=%#v want=%#v", test.name, test.got, test.want)
		}
	}
}

func TestWizardPlainModesContainNoANSIAndKeepCopy(t *testing.T) {
	for _, test := range []struct {
		name       string
		accessible bool
		noColor    string
	}{
		{name: "accessible", accessible: true},
		{name: "NO_COLOR", noColor: "1"},
		{name: "non-TTY"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", test.noColor)
			var output bytes.Buffer
			enabled := wizardColorEnabled(test.accessible, &output)
			got := semanticWizardText(wizardSafe, "Read-only", enabled)
			if strings.Contains(got, "\x1b") {
				t.Fatalf("plain output contains ANSI: %q", got)
			}
			if ansi.Strip(got) != "Read-only" {
				t.Fatalf("plain copy changed: %q", got)
			}
		})
	}
}

func TestRedirectedDiscoveryStatusContainsNoANSI(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	var output bytes.Buffer
	(huhInteractiveForms{}).DiscoveryStatus(
		"gke_project_us-central1_development",
		&output,
	)
	if strings.Contains(output.String(), "\x1b") {
		t.Fatalf("redirected status contains ANSI: %q", output.String())
	}
	if !strings.Contains(output.String(), "Development cluster") {
		t.Fatalf("redirected status lost friendly label: %q", output.String())
	}
}

func TestStyledWizardCopyMatchesPlainGoldenAfterStrippingANSI(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind wizardSemantic
		text string
	}{
		{wizardTitleAccent, wizardTitle(true)},
		{wizardActive, "Development cluster  CURRENT"},
		{wizardSafe, "✓ Read-only"},
		{wizardWarning, "! Review before sharing"},
		{wizardFailure, "Collection failed"},
		{wizardSecondary, "gke_project_us-central1_development"},
	} {
		styled := semanticWizardText(test.kind, test.text, true)
		if got := ansi.Strip(styled); got != test.text {
			t.Fatalf("styled copy=%q want=%q", got, test.text)
		}
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
		wizardProgressHeader(1, false),
		"Qodo Scout - Setup",
		"Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted.",
		"current (project)  CURRENT",
		"Choose another...",
		"alternate (project)",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output missing %q:\n%s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), "\x1b") ||
		strings.Contains(output.String(), "Review before sharing") {
		t.Fatalf("accessible context screen has ANSI or duplicate caveat:\n%s", output.String())
	}
	if strings.Count(output.String(), securityStatement(false)) != 1 {
		t.Fatalf("safety sentence repeated:\n%s", output.String())
	}
}

func TestAccessibleConfigureTranscriptUsesCompactGroupsAndHidesDependencies(t *testing.T) {
	t.Parallel()
	settings := interactiveSettings{
		Context:                 "gke_project_us-central1_development",
		ContextSummary:          "Development",
		ExcludeSystemNamespaces: true,
		Since:                   30 * time.Minute,
	}
	var output bytes.Buffer
	err := (huhInteractiveForms{Accessible: true, Theme: qodoScoutThemeFor(false)}).
		Configure(
			context.Background(),
			&settings,
			[]string{"bundle-alon-google", "monitoring"},
			byteReader{reader: strings.NewReader("1\n1\n0\n1\ny\n")},
			&output,
		)
	if err != nil {
		t.Fatal(err)
	}
	transcript := output.String()
	for _, expected := range []string{
		wizardProgressHeader(2, false),
		wizardProgressHeader(3, false),
		wizardProgressHeader(4, false),
		wizardProgressHeader(5, false),
		"Scope",
		"All application namespaces",
		"Log window",
		"30 minutes",
		"Extra sources - optional",
		"Kubernetes data is already included.",
		"Output",
		"Automatic (~/.qodo-support-bundles)",
		"Ready to collect",
		"[!] Review before sharing",
	} {
		if !strings.Contains(transcript, expected) {
			t.Fatalf("accessible transcript missing %q:\n%s", expected, transcript)
		}
	}
	for _, hidden := range []string{
		"Prometheus namespace",
		"Phoenix namespace",
		"Trace ID",
		"Platform pod",
		"qodo-support-bundle-....tar.gz",
		"↑↓ move",
		"Space/x toggle",
		"\x1b",
	} {
		if strings.Contains(transcript, hidden) {
			t.Fatalf("accessible transcript unexpectedly contains %q:\n%s", hidden, transcript)
		}
	}
}

func TestAccessibleConfirmationMatchesSwitchToAutomaticOutput(t *testing.T) {
	t.Parallel()
	const staleOutput = "/tmp/stale-custom.tar.gz"
	settings := interactiveSettings{
		Context:                 "gke_project_us-central1_development",
		ContextSummary:          "Development",
		ExcludeSystemNamespaces: true,
		Since:                   30 * time.Minute,
		Output:                  staleOutput,
	}
	var output bytes.Buffer
	err := (huhInteractiveForms{Accessible: true}).
		Configure(
			context.Background(),
			&settings,
			[]string{"bundle-alon-google"},
			byteReader{reader: strings.NewReader("1\n1\n0\n1\ny\n")},
			&output,
		)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), staleOutput) ||
		!strings.Contains(output.String(), "Output    Automatic") {
		t.Fatalf("confirmation did not match automatic output:\n%s", output.String())
	}
	if settings.Output != "" {
		t.Fatalf("automatic output retained custom path %q", settings.Output)
	}
}

func TestAccessibleExtraSourcePrioritizesNewlySelectedNamespace(t *testing.T) {
	t.Parallel()
	settings := interactiveSettings{
		Context:        "gke_project_us-central1_development",
		ContextSummary: "Development",
		Since:          30 * time.Minute,
	}
	var output bytes.Buffer
	err := (huhInteractiveForms{Accessible: true}).
		Configure(
			context.Background(),
			&settings,
			[]string{"bundle-alon-google", "monitoring"},
			byteReader{reader: strings.NewReader(
				"2\n2\n0\n1\n1\n0\n1\n1\ny\n",
			)},
			&output,
		)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(output.String(), "Prometheus namespace", 2)
	if len(parts) != 2 ||
		!strings.Contains(parts[1], "1. monitoring\n2. bundle-alon-google") {
		t.Fatalf("selected namespace was not prioritized:\n%s", output.String())
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
