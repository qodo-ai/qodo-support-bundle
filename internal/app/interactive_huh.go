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
}

func newHuhInteractiveForms() huhInteractiveForms {
	return huhInteractiveForms{
		Accessible: os.Getenv("ACCESSIBLE") != "",
		Theme:      qodoScoutTheme(),
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
	for {
		choice := primaryContext
		title := "Cluster context"
		options := primaryContextOptions(primaryContext, catalog.Current)
		if showAll {
			choice = settings.Context
			title = "Available clusters"
			options = contextOptions(catalog.Names, catalog.Current, false)
		}
		form := huh.NewForm(
			wizardGroup(
				1,
				"Choose a Kubernetes cluster",
				false,
				newContextSelect(title, options, &choice).
					Description(wizardDescription(
						"Friendly labels keep the exact context for collection and confirmation.",
						false,
					)).
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
					huh.NewConfirm().
						Title(productionContextWarning(choice)).
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
		discoveryStatusLine(kubeContext, forms.Accessible),
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
	settings.Confirmed = true

	namespaceOptions := stringOptions(namespaces)
	form := huh.NewForm(
		wizardGroup(
			2,
			"Choose namespace scope",
			false,
			huh.NewSelect[string]().
				Title("Namespace scope").
				Description(wizardDescription("", false)).
				Options(
					huh.NewOption(
						allNamespaceScopeLabel(settings.ExcludeSystemNamespaces),
						"all",
					),
					huh.NewOption("Selected namespaces", "selected"),
				).
				Value(&scope),
		),
		wizardGroup(
			2,
			"Select namespaces",
			true,
			huh.NewMultiSelect[string]().
				Title("Namespaces").
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
			"Choose diagnostics",
			false,
			huh.NewSelect[string]().
				Title("Log lookback").
				Description(wizardDescription("", false)).
				Options(
					huh.NewOption("30 minutes", "30m"),
					huh.NewOption("1 hour", "1h"),
					huh.NewOption("6 hours", "6h"),
					huh.NewOption("Custom", "custom"),
				).
				Value(&durationPreset),
		),
		wizardGroup(
			3,
			"Set custom log window",
			false,
			huh.NewInput().
				Title("Custom log lookback").
				Description(wizardDescription("", false)).
				Placeholder("45m").
				Value(&customDuration).
				Validate(validateInteractiveDuration),
		).WithHideFunc(
			func() bool { return durationPreset != "custom" },
		),
		wizardGroup(
			3,
			"Choose optional diagnostics",
			true,
			huh.NewMultiSelect[string]().
				Title("Optional collectors").
				Description(wizardDescription(
					"No credentials or Kubernetes Secrets are requested.",
					true,
				)).
				Options(
					huh.NewOption("Prometheus telemetry", "prometheus"),
					huh.NewOption("Phoenix traces", "phoenix"),
					huh.NewOption("Zitadel connectivity", "zitadel"),
				).
				Value(&collectors),
		),
		wizardGroup(
			3,
			"Configure Prometheus",
			false,
			huh.NewSelect[string]().
				Title("Prometheus namespace").
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
			func() bool { return !slices.Contains(collectors, "prometheus") },
		),
		wizardGroup(
			3,
			"Configure Phoenix",
			false,
			huh.NewSelect[string]().
				Title("Phoenix namespace").
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
			func() bool { return !slices.Contains(collectors, "phoenix") },
		),
		wizardGroup(
			3,
			"Configure Zitadel",
			false,
			huh.NewSelect[string]().
				Title("Platform namespace").
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
			func() bool { return !slices.Contains(collectors, "zitadel") },
		),
		wizardGroup(
			4,
			"Choose output path",
			false,
			huh.NewInput().
				Title("Output archive path").
				Description(wizardDescription(
					"Leave blank for the default Qodo Scout archive path.",
					false,
				)).
				Placeholder("~/qodo-support-bundles/qodo-support-bundle-….tar.gz").
				Value(&settings.Output),
		),
		wizardGroup(
			5,
			"Review and confirm",
			false,
			huh.NewConfirm().
				TitleFunc(func() string {
					return interactiveSummary(
						settings.Context,
						scope,
						settings.ExcludeSystemNamespaces,
						settings.Namespaces,
						durationPreset,
						customDuration,
						collectors,
						settings.Output,
					)
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
	return nil
}

func (forms huhInteractiveForms) run(
	ctx context.Context,
	form *huh.Form,
	stdin io.Reader,
	stderr io.Writer,
) error {
	return form.
		WithInput(stdin).
		WithOutput(stderr).
		WithAccessible(forms.Accessible).
		WithTheme(forms.Theme).
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

func interactiveSummary(
	kubeContext string,
	scope string,
	excludeSystemNamespaces bool,
	namespaces []string,
	durationPreset string,
	customDuration string,
	collectors []string,
	output string,
) string {
	scopeText := strings.ToLower(allNamespaceScopeLabel(excludeSystemNamespaces))
	if scope == "selected" {
		scopeText = strings.Join(namespaces, ", ")
	}
	duration := durationPreset
	if duration == "custom" {
		duration = customDuration
	}
	if len(collectors) == 0 {
		collectors = []string{"none"}
	}
	if strings.TrimSpace(output) == "" {
		output = "automatic default"
	} else {
		output = terminalLine(output)
	}
	return fmt.Sprintf(
		"Collect context %s; scope %s; logs %s; optional %s; output %s?",
		kubeContext,
		scopeText,
		duration,
		strings.Join(collectors, ", "),
		output,
	)
}

func allNamespaceScopeLabel(excludeSystemNamespaces bool) string {
	if excludeSystemNamespaces {
		return "All application namespaces"
	}
	return "All namespaces (including system namespaces)"
}
