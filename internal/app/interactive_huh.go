package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
)

type huhInteractiveForms struct {
	Accessible bool
	Theme      *huh.Theme
	RunForm    func(context.Context, *huh.Form, io.Reader, io.Writer) error
}

func newHuhInteractiveForms() huhInteractiveForms {
	accessible := os.Getenv("ACCESSIBLE") != ""
	return huhInteractiveForms{
		Accessible: accessible,
		Theme:      qodoScoutThemeFor(!accessible && os.Getenv("NO_COLOR") == ""),
	}
}

func (forms huhInteractiveForms) ChooseContext(
	ctx context.Context,
	settings *interactiveSettings,
	catalog interactiveContextCatalog,
	stdin io.Reader,
	stderr io.Writer,
) error {
	primaryContext := settings.Context
	showAll := false
	unicode := !forms.Accessible && terminalUnicode()
	color := wizardColorEnabled(forms.Accessible, stderr)
	width := terminalWidth(stderr)
	introShown := false
	for {
		showIntro := !introShown
		introShown = true
		choice := primaryContext
		title := "Cluster"
		options := primaryContextOptionsForMode(primaryContext, catalog.Current, unicode)
		if showAll {
			choice = settings.Context
			title = "Available clusters"
			options = contextOptions(catalog.Names, catalog.Current, false)
		}
		fieldContent := title
		if showIntro {
			fieldContent = wizardSetupTitle(unicode) + "\n" +
				semanticWizardText(
					wizardSafe,
					securityStatement(unicode),
					color,
				) + "\n\n" + title
		}
		title = wizardFieldTitle(1, fieldContent, unicode, color, width)
		options = styleCurrentContext(options, catalog.Current, color)
		form := huh.NewForm(
			wizardGroup(
				1,
				wizardSetupTitle(unicode),
				false,
				forms.Accessible,
				newContextSelect(title, options, &choice).
					Description(wizardDescription("", false)).
					Validate(validateContextChoice),
			),
		)
		if err := forms.run(ctx, form, stdin, stderr); err != nil {
			return err
		}
		if choice == chooseAnotherContextValue {
			showAll = true
			continue
		}
		productionApproved := false
		if isProductionContext(choice) {
			productionForm := huh.NewForm(
				wizardGroup(
					1,
					"Confirm production cluster",
					false,
					forms.Accessible,
					huh.NewConfirm().
						Title(wizardFieldTitle(
							1,
							semanticWizardText(
								wizardWarning,
								productionContextWarning(choice),
								color,
							),
							unicode,
							color,
							width,
						)).
						Description(wizardDescription(
							"Continue or go back to choose another cluster.",
							false,
						)).
						Affirmative("Continue").
						Negative("Go back").
						Value(&productionApproved),
				),
			)
			if err := forms.run(ctx, productionForm, stdin, stderr); err != nil {
				return err
			}
		}
		settings.Context = choice
		if !isProductionContext(choice) || productionApproved {
			settings.ContextSummary = confirmationContextLabel(choice, catalog.Names)
			return nil
		}
		showAll = false
	}
}

func (forms huhInteractiveForms) DiscoveryStatus(
	kubeContext string,
	stderr io.Writer,
) {
	_, _ = fmt.Fprintln(
		stderr,
		discoveryStatusLine(
			kubeContext,
			!wizardColorEnabled(forms.Accessible, stderr),
		),
	)
}

func (forms huhInteractiveForms) Configure(
	ctx context.Context,
	settings *interactiveSettings,
	namespaces []string,
	stdin io.Reader,
	stderr io.Writer,
) error {
	scope := "all"
	if !settings.AllNamespaces && len(settings.Namespaces) > 0 {
		scope = "selected"
	}
	settings.Namespaces = availableSelections(settings.Namespaces, namespaces)
	durationPreset, customDuration := interactiveDurationDefaults(settings.Since)
	collectors := selectedCollectors(*settings)
	outputMode := "automatic"
	if strings.TrimSpace(settings.Output) != "" {
		outputMode = "custom"
	}
	unicode := !forms.Accessible && terminalUnicode()
	width := terminalWidth(stderr)
	color := wizardColorEnabled(forms.Accessible, stderr)
	fieldTitle := func(step int, title string) string {
		return wizardFieldTitle(step, title, unicode, color, width)
	}
	settings.Confirmed = true

	namespaceOptions := stringOptions(namespaces)
	if forms.Accessible {
		if err := forms.configureAccessible(
			ctx,
			settings,
			stdin,
			stderr,
			&scope,
			namespaceOptions,
			&durationPreset,
			&customDuration,
			&collectors,
			namespaces,
			&outputMode,
		); err != nil {
			return err
		}
		return finalizeInteractiveSettings(
			settings,
			scope,
			durationPreset,
			customDuration,
			collectors,
			outputMode,
		)
	}
	form := huh.NewForm(
		wizardGroup(
			2,
			"Scope",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(2, "Scope")).
				Description(wizardDescription("", false)).
				Options(namespaceScopeOptionsForMode(
					settings.ExcludeSystemNamespaces,
					unicode,
				)...).
				Value(&scope),
		),
		wizardGroup(
			2,
			"Select namespaces",
			true,
			forms.Accessible,
			huh.NewMultiSelect[string]().
				Title(fieldTitle(2, "Namespaces")).
				Description(wizardDescription("", true)).
				Options(namespaceOptions...).
				Value(&settings.Namespaces).
				Validate(func(values []string) error {
					if scope == "selected" && len(values) == 0 {
						return errors.New("select at least one namespace")
					}
					return nil
				}),
		).WithHideFunc(
			func() bool { return scope != "selected" },
		),
		wizardGroup(
			3,
			"Log window",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(3, "Log window")).
				Description(wizardDescription("", false)).
				Options(logWindowOptions()...).
				Value(&durationPreset),
		),
		wizardGroup(
			3,
			"Set custom log window",
			false,
			forms.Accessible,
			huh.NewInput().
				Title(fieldTitle(3, "Custom log lookback")).
				Description(wizardDescription("", false)).
				Placeholder("45m").
				Value(&customDuration).
				Validate(validateInteractiveDuration),
		).WithHideFunc(
			func() bool { return durationPreset != "custom" },
		),
		wizardGroup(
			4,
			extraSourcesTitle(unicode),
			true,
			forms.Accessible,
			huh.NewMultiSelect[string]().
				Title(fieldTitle(4, extraSourcesTitle(unicode))).
				Description(wizardDescription(
					optionalCollectorDescription(!forms.Accessible),
					true,
				)).
				Options(optionalCollectorOptions()...).
				Value(&collectors),
		),
		wizardGroup(
			4,
			"Configure Prometheus",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(4, "Prometheus namespace")).
				Description(wizardDescription("", false)).
				OptionsFunc(func() []huh.Option[string] {
					return stringOptions(orderedCollectorNamespaces(
						scope,
						settings.Namespaces,
						namespaces,
					))
				}, []any{&scope, &settings.Namespaces}).
				Value(&settings.PrometheusNamespace),
		).WithHideFunc(
			func() bool { return !collectorSettingsVisible(collectors, "prometheus") },
		),
		wizardGroup(
			4,
			"Configure Phoenix",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(4, "Phoenix namespace")).
				Description(wizardDescription("", false)).
				OptionsFunc(func() []huh.Option[string] {
					return stringOptions(orderedCollectorNamespaces(
						scope,
						settings.Namespaces,
						namespaces,
					))
				}, []any{&scope, &settings.Namespaces}).
				Value(&settings.PhoenixNamespace),
			huh.NewInput().
				Title("Trace ID (optional)").
				Description(wizardDescription(
					"Exact 32-character hexadecimal trace ID.",
					false,
				)).
				Value(&settings.TraceID).
				Validate(validateInteractiveTraceID),
		).WithHideFunc(
			func() bool { return !collectorSettingsVisible(collectors, "phoenix") },
		),
		wizardGroup(
			4,
			"Configure Zitadel",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(4, "Platform namespace")).
				Description(wizardDescription("", false)).
				OptionsFunc(func() []huh.Option[string] {
					return stringOptions(orderedCollectorNamespaces(
						scope,
						settings.Namespaces,
						namespaces,
					))
				}, []any{&scope, &settings.Namespaces}).
				Value(&settings.PlatformNamespace),
			huh.NewInput().
				Title("Platform pod").
				Description(wizardDescription("", false)).
				Value(&settings.PlatformPod).
				Validate(requiredInteractiveValue("platform pod")),
			huh.NewInput().
				Title("Platform container").
				Description(wizardDescription("", false)).
				Value(&settings.PlatformContainer).
				Validate(requiredInteractiveValue("platform container")),
		).WithHideFunc(
			func() bool { return !collectorSettingsVisible(collectors, "zitadel") },
		),
		wizardGroup(
			5,
			"Output",
			false,
			forms.Accessible,
			huh.NewSelect[string]().
				Title(fieldTitle(5, "Output")).
				Options(outputModeOptions(unicode)...).
				Value(&outputMode),
		),
		wizardGroup(
			5,
			"Custom output path",
			false,
			forms.Accessible,
			huh.NewInput().
				Title(fieldTitle(5, "Custom path")).
				Placeholder("~/qodo-support-bundles/qodo-support-bundle-….tar.gz").
				Value(&settings.Output).
				Validate(validateCustomOutputPath),
		).WithHideFunc(func() bool { return outputMode != "custom" }),
		wizardGroup(
			5,
			"Confirm",
			false,
			forms.Accessible,
			huh.NewConfirm().
				TitleFunc(func() string {
					summaryOutput := ""
					if outputMode == "custom" {
						summaryOutput = settings.Output
					}
					return fieldTitle(5, styleWizardSummary(interactiveSummary(
						settings.Context,
						settings.ContextSummary,
						scope,
						settings.ExcludeSystemNamespaces,
						settings.Namespaces,
						durationPreset,
						customDuration,
						collectors,
						summaryOutput,
						width,
						unicode,
					), color))
				}, nil).
				Description(wizardDescription("", false)).
				Affirmative("Collect").
				Negative("Cancel").
				Value(&settings.Confirmed),
		),
	)
	if err := forms.run(ctx, form, stdin, stderr); err != nil {
		return err
	}

	return finalizeInteractiveSettings(
		settings,
		scope,
		durationPreset,
		customDuration,
		collectors,
		outputMode,
	)
}

func finalizeInteractiveSettings(
	settings *interactiveSettings,
	scope string,
	durationPreset string,
	customDuration string,
	collectors []string,
	outputMode string,
) error {
	settings.AllNamespaces = scope == "all"
	if settings.AllNamespaces {
		settings.Namespaces = nil
	}
	durationValue := durationPreset
	if durationPreset == "custom" {
		durationValue = customDuration
	}
	duration, err := time.ParseDuration(strings.TrimSpace(durationValue))
	if err != nil {
		return err
	}
	settings.Since = duration
	settings.Prometheus = slices.Contains(collectors, "prometheus")
	settings.Phoenix = slices.Contains(collectors, "phoenix")
	settings.Zitadel = slices.Contains(collectors, "zitadel")
	if outputMode == "automatic" {
		settings.Output = ""
	}
	return nil
}

func (forms huhInteractiveForms) configureAccessible(
	ctx context.Context,
	settings *interactiveSettings,
	stdin io.Reader,
	stderr io.Writer,
	scope *string,
	namespaceOptions []huh.Option[string],
	durationPreset *string,
	customDuration *string,
	collectors *[]string,
	namespaces []string,
	outputMode *string,
) error {
	run := func(groups ...*huh.Group) error {
		return forms.run(ctx, huh.NewForm(groups...), stdin, stderr)
	}
	if err := run(wizardGroup(
		2, "Scope", false, true,
		huh.NewSelect[string]().
			Title(accessibleWizardTitle(2, "Scope")).
			Options(namespaceScopeOptionsForMode(
				settings.ExcludeSystemNamespaces,
				false,
			)...).
			Value(scope),
	)); err != nil {
		return err
	}
	if *scope == "selected" {
		if err := run(wizardGroup(
			2, "Select namespaces", true, true,
			huh.NewMultiSelect[string]().
				Title(accessibleWizardTitle(2, "Choose namespaces")).
				Options(namespaceOptions...).
				Value(&settings.Namespaces).
				Validate(func(values []string) error {
					if len(values) == 0 {
						return errors.New("select at least one namespace")
					}
					return nil
				}),
		)); err != nil {
			return err
		}
	}
	collectorNamespaceOptions := stringOptions(orderedCollectorNamespaces(
		*scope,
		settings.Namespaces,
		namespaces,
	))
	if err := run(wizardGroup(
		3, "Log window", false, true,
		huh.NewSelect[string]().
			Title(accessibleWizardTitle(3, "Log window")).
			Options(logWindowOptions()...).
			Value(durationPreset),
	)); err != nil {
		return err
	}
	if *durationPreset == "custom" {
		if err := run(wizardGroup(
			3, "Custom log window", false, true,
			huh.NewInput().
				Title(accessibleWizardTitle(3, "Custom log window")).
				Placeholder("45m").
				Value(customDuration).
				Validate(validateInteractiveDuration),
		)); err != nil {
			return err
		}
	}
	if err := run(wizardGroup(
		4, extraSourcesTitle(false), true, true,
		huh.NewMultiSelect[string]().
			Title(accessibleWizardTitle(
				4,
				extraSourcesTitle(false)+"\n"+
					optionalCollectorDescription(false),
			)).
			Options(optionalCollectorOptions()...).
			Value(collectors),
	)); err != nil {
		return err
	}
	if collectorSettingsVisible(*collectors, "prometheus") {
		if err := run(wizardGroup(
			4, "Prometheus", false, true,
			huh.NewSelect[string]().
				Title(accessibleWizardTitle(4, "Prometheus namespace")).
				Options(collectorNamespaceOptions...).
				Value(&settings.PrometheusNamespace),
		)); err != nil {
			return err
		}
	}
	if collectorSettingsVisible(*collectors, "phoenix") {
		if err := run(wizardGroup(
			4, "Phoenix", false, true,
			huh.NewSelect[string]().
				Title(accessibleWizardTitle(4, "Phoenix namespace")).
				Options(collectorNamespaceOptions...).
				Value(&settings.PhoenixNamespace),
			huh.NewInput().
				Title("Trace ID (optional)").
				Value(&settings.TraceID).
				Validate(validateInteractiveTraceID),
		)); err != nil {
			return err
		}
	}
	if collectorSettingsVisible(*collectors, "zitadel") {
		if err := run(wizardGroup(
			4, "Zitadel check", false, true,
			huh.NewSelect[string]().
				Title(accessibleWizardTitle(4, "Platform namespace")).
				Options(collectorNamespaceOptions...).
				Value(&settings.PlatformNamespace),
			huh.NewInput().
				Title("Platform pod").
				Value(&settings.PlatformPod).
				Validate(requiredInteractiveValue("platform pod")),
			huh.NewInput().
				Title("Platform container").
				Value(&settings.PlatformContainer).
				Validate(requiredInteractiveValue("platform container")),
		)); err != nil {
			return err
		}
	}
	if err := run(wizardGroup(
		5, "Output", false, true,
		huh.NewSelect[string]().
			Title(accessibleWizardTitle(5, "Output")).
			Options(outputModeOptions(false)...).
			Value(outputMode),
	)); err != nil {
		return err
	}
	if *outputMode == "custom" {
		if err := run(wizardGroup(
			5, "Custom output path", false, true,
			huh.NewInput().
				Title(accessibleWizardTitle(5, "Custom path")).
				Placeholder("~/qodo-support-bundles/qodo-support-bundle-....tar.gz").
				Value(&settings.Output).
				Validate(validateCustomOutputPath),
		)); err != nil {
			return err
		}
	}
	summaryOutput := ""
	if *outputMode == "custom" {
		summaryOutput = settings.Output
	}
	return run(wizardGroup(
		5, "Ready to collect", false, true,
		huh.NewConfirm().
			Title(accessibleWizardTitle(5, interactiveSummary(
				settings.Context,
				settings.ContextSummary,
				*scope,
				settings.ExcludeSystemNamespaces,
				settings.Namespaces,
				*durationPreset,
				*customDuration,
				*collectors,
				summaryOutput,
				0,
				false,
			))).
			Affirmative("Collect").
			Negative("Cancel").
			Value(&settings.Confirmed),
	))
}

func (forms huhInteractiveForms) run(
	ctx context.Context,
	form *huh.Form,
	stdin io.Reader,
	stderr io.Writer,
) error {
	if forms.RunForm != nil {
		return forms.RunForm(ctx, form, stdin, stderr)
	}
	return form.
		WithInput(stdin).
		WithOutput(stderr).
		WithAccessible(forms.Accessible).
		WithTheme(qodoScoutThemeFor(wizardColorEnabled(forms.Accessible, stderr))).
		WithShowHelp(true).
		RunWithContext(ctx)
}

func interactiveDurationDefaults(duration time.Duration) (string, string) {
	if duration <= 0 {
		duration = 30 * time.Minute
	}
	value := duration.String()
	switch value {
	case "30m0s":
		return "30m", "30m"
	case "1h0m0s":
		return "1h", "1h"
	case "6h0m0s":
		return "6h", "6h"
	default:
		return "custom", value
	}
}

func stringOptions(values []string) []huh.Option[string] {
	options := make([]huh.Option[string], 0, len(values))
	for _, value := range values {
		options = append(options, huh.NewOption(value, value))
	}
	return options
}

func availableSelections(selected []string, available []string) []string {
	result := make([]string, 0, len(selected))
	for _, value := range selected {
		if slices.Contains(available, value) {
			result = append(result, value)
		}
	}
	return result
}

func orderedCollectorNamespaces(
	scope string,
	selected []string,
	available []string,
) []string {
	if scope != "selected" {
		return append([]string(nil), available...)
	}
	ordered := make([]string, 0, len(available))
	for _, value := range selected {
		if slices.Contains(available, value) && !slices.Contains(ordered, value) {
			ordered = append(ordered, value)
		}
	}
	for _, value := range available {
		if !slices.Contains(ordered, value) {
			ordered = append(ordered, value)
		}
	}
	return ordered
}

func selectedCollectors(settings interactiveSettings) []string {
	var collectors []string
	if settings.Prometheus {
		collectors = append(collectors, "prometheus")
	}
	if settings.Phoenix {
		collectors = append(collectors, "phoenix")
	}
	if settings.Zitadel {
		collectors = append(collectors, "zitadel")
	}
	return collectors
}

func validateInteractiveTraceID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if len(value) != 32 {
		return errors.New("trace ID must contain exactly 32 hexadecimal characters")
	}
	for _, character := range value {
		if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
			return errors.New("trace ID must contain only hexadecimal characters")
		}
	}
	return nil
}

func requiredInteractiveValue(label string) func(string) error {
	return func(value string) error {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", label)
		}
		return nil
	}
}

func validateCustomOutputPath(value string) error {
	return requiredInteractiveValue("custom output path")(value)
}

func interactiveSummary(
	kubeContext string,
	contextLabel string,
	scope string,
	excludeSystemNamespaces bool,
	namespaces []string,
	durationPreset string,
	customDuration string,
	collectors []string,
	output string,
	width int,
	unicode bool,
) string {
	if strings.TrimSpace(contextLabel) == "" {
		contextLabel = terminalLine(kubeContext)
	}
	scopeText := allNamespaceScopeLabel(excludeSystemNamespaces)
	if scope == "selected" {
		scopeText = strings.Join(namespaces, ", ")
	}
	duration := durationPreset
	if duration == "custom" {
		duration = customDuration
	}
	duration = interactiveDurationLabel(duration)
	extras := make([]string, 0, len(collectors))
	for _, collector := range collectors {
		switch collector {
		case "prometheus":
			extras = append(extras, "Prometheus")
		case "phoenix":
			extras = append(extras, "Phoenix")
		case "zitadel":
			extras = append(extras, "Zitadel check")
		}
	}
	if len(extras) == 0 {
		extras = []string{"None"}
	}
	if strings.TrimSpace(output) == "" {
		output = "Automatic"
	} else {
		output = terminalLine(output)
	}
	review := "[!] Review before sharing"
	if unicode {
		review = "! Review before sharing"
	}
	rows := [][2]string{
		{"Cluster", terminalLine(contextLabel)},
		{"Scope", scopeText},
		{"Logs", duration},
		{"Extras", strings.Join(extras, ", ")},
		{"Output", output},
	}
	lines := []string{"Ready to collect"}
	if width == 0 || width >= 44 {
		for _, row := range rows {
			lines = append(lines, fmt.Sprintf("%-9s %s", row[0], row[1]))
		}
	} else {
		for _, row := range rows {
			lines = append(lines, row[0]+": "+row[1])
		}
	}
	return strings.Join(append(lines, "", review), "\n")
}

func interactiveDurationLabel(value string) string {
	switch strings.TrimSpace(value) {
	case "30m", "30m0s":
		return "30 minutes"
	case "1h", "1h0m0s":
		return "1 hour"
	case "6h", "6h0m0s":
		return "6 hours"
	default:
		return terminalLine(value)
	}
}

func allNamespaceScopeLabel(excludeSystemNamespaces bool) string {
	if excludeSystemNamespaces {
		return "All application namespaces"
	}
	return "All namespaces (including system namespaces)"
}
