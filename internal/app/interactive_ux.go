package app

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

const (
	chooseAnotherContextValue = "\x00choose-another-context"
)

func wizardTitle(unicode bool) string {
	if unicode {
		return "Qodo Scout · Read-only on-prem diagnostics"
	}
	return "Qodo Scout - Read-only on-prem diagnostics"
}

func wizardSetupTitle(unicode bool) string {
	if unicode {
		return "Qodo Scout · Setup"
	}
	return "Qodo Scout - Setup"
}

func securityStatement(_ bool) string {
	return "Read-only diagnostics: no cluster changes, no Kubernetes Secret objects, and sensitive text is redacted."
}

func wizardProgressHeader(step int, unicode bool) string {
	names := []string{"Cluster", "Scope", "Logs", "Sources", "Confirm"}
	parts := make([]string, 0, len(names))
	for index, name := range names {
		position := index + 1
		marker := "[ ]"
		switch {
		case position < step:
			marker = "[ok]"
		case position == step:
			marker = "[>]"
		}
		if unicode {
			switch {
			case position < step:
				marker = "✓"
			case position == step:
				marker = "●"
			default:
				marker = "○"
			}
		}
		parts = append(parts, marker+" "+name)
	}
	return strings.Join(parts, "  ")
}

func styledWizardProgressHeader(
	step int,
	unicode bool,
	enabled bool,
) string {
	if !enabled {
		return wizardProgressHeader(step, unicode)
	}
	names := []string{"Cluster", "Scope", "Logs", "Sources", "Confirm"}
	parts := make([]string, 0, len(names))
	for index, name := range names {
		position := index + 1
		marker, semantic := "○", wizardSecondary
		if !unicode {
			marker = "[ ]"
		}
		switch {
		case position < step:
			marker, semantic = "✓", wizardSafe
			if !unicode {
				marker = "[ok]"
			}
		case position == step:
			marker, semantic = "●", wizardActive
			if !unicode {
				marker = "[>]"
			}
		}
		parts = append(parts, semanticWizardText(
			semantic,
			marker+" "+name,
			true,
		))
	}
	return strings.Join(parts, "  ")
}

func accessibleWizardTitle(step int, title string) string {
	return wizardFieldTitle(step, title, false, false, 0)
}

func wizardFieldTitle(
	step int,
	title string,
	unicode bool,
	color bool,
	width int,
) string {
	header := styledWizardProgressHeader(step, unicode, color)
	if width > 0 && terminalDisplayWidth(wizardProgressHeader(step, unicode)) > width {
		header = wrapWizardProgressHeader(step, unicode, width)
	}
	return header + "\n\n" + title
}

func wrapWizardProgressHeader(step int, unicode bool, width int) string {
	parts := strings.Split(wizardProgressHeader(step, unicode), "  ")
	lines := make([]string, 0, len(parts))
	line := ""
	for _, part := range parts {
		candidate := part
		if line != "" {
			candidate = line + "  " + part
		}
		if line != "" && terminalDisplayWidth(candidate) > width {
			lines = append(lines, line)
			line = part
			continue
		}
		line = candidate
	}
	if line != "" {
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func optionalCollectorDescription(_ bool) string {
	return "Kubernetes data is already included."
}

func optionalCollectorOptions() []huh.Option[string] {
	return []huh.Option[string]{
		huh.NewOption("Prometheus", "prometheus"),
		huh.NewOption("Phoenix", "phoenix"),
		huh.NewOption("Zitadel check", "zitadel"),
	}
}

func namespaceScopeOptions(excludeSystemNamespaces bool) []huh.Option[string] {
	return namespaceScopeOptionsForMode(excludeSystemNamespaces, true)
}

func namespaceScopeOptionsForMode(
	excludeSystemNamespaces bool,
	unicode bool,
) []huh.Option[string] {
	selected := "Choose namespaces..."
	if unicode {
		selected = "Choose namespaces…"
	}
	return []huh.Option[string]{
		huh.NewOption(allNamespaceScopeLabel(excludeSystemNamespaces), "all"),
		huh.NewOption(selected, "selected"),
	}
}

func extraSourcesTitle(unicode bool) string {
	if unicode {
		return "Extra sources · optional"
	}
	return "Extra sources - optional"
}

func logWindowOptions() []huh.Option[string] {
	return []huh.Option[string]{
		huh.NewOption("30 minutes", "30m"),
		huh.NewOption("1 hour", "1h"),
		huh.NewOption("6 hours", "6h"),
		huh.NewOption("Custom", "custom"),
	}
}

func outputModeOptions(unicode bool) []huh.Option[string] {
	custom := "Custom path..."
	if unicode {
		custom = "Custom path…"
	}
	return []huh.Option[string]{
		huh.NewOption("Automatic (~/.qodo-support-bundles)", "automatic"),
		huh.NewOption(custom, "custom"),
	}
}

func collectorSettingsVisible(collectors []string, collector string) bool {
	return slices.Contains(collectors, collector)
}

type gkeContextName struct {
	Project  string
	Location string
	Cluster  string
}

type wizardSemantic int

const (
	wizardTitleAccent wizardSemantic = iota
	wizardActive
	wizardSafe
	wizardWarning
	wizardFailure
	wizardSecondary
)

type wizardPalette struct {
	Purple  lipgloss.AdaptiveColor
	Cyan    lipgloss.AdaptiveColor
	Green   lipgloss.AdaptiveColor
	Amber   lipgloss.AdaptiveColor
	Red     lipgloss.AdaptiveColor
	Neutral lipgloss.AdaptiveColor
}

func qodoScoutColors() wizardPalette {
	return wizardPalette{
		Purple:  lipgloss.AdaptiveColor{Light: "#6D28D9", Dark: "#A78BFA"},
		Cyan:    lipgloss.AdaptiveColor{Light: "#0369A1", Dark: "#67E8F9"},
		Green:   lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#86EFAC"},
		Amber:   lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FCD34D"},
		Red:     lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#FCA5A5"},
		Neutral: lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#94A3B8"},
	}
}

func semanticWizardText(kind wizardSemantic, text string, enabled bool) string {
	if !enabled {
		return text
	}
	palette := qodoScoutColors()
	style := lipgloss.NewStyle()
	switch kind {
	case wizardTitleAccent:
		style = style.Foreground(palette.Purple).Bold(true)
	case wizardActive:
		style = style.Foreground(palette.Cyan).Bold(true)
	case wizardSafe:
		style = style.Foreground(palette.Green)
	case wizardWarning:
		style = style.Foreground(palette.Amber)
	case wizardFailure:
		style = style.Foreground(palette.Red)
	case wizardSecondary:
		style = style.Foreground(palette.Neutral).Faint(true)
	}
	return style.Render(text)
}

func wizardColorEnabled(accessible bool, writer io.Writer) bool {
	termName := os.Getenv("TERM")
	return !accessible &&
		os.Getenv("NO_COLOR") == "" &&
		termName != "" &&
		!strings.EqualFold(termName, "dumb") &&
		terminalWriter(writer)
}

func parseGKEContextName(value string) (gkeContextName, bool) {
	parts := strings.SplitN(value, "_", 4)
	if len(parts) != 4 ||
		parts[0] != "gke" ||
		parts[1] == "" ||
		parts[2] == "" ||
		parts[3] == "" {
		return gkeContextName{}, false
	}
	return gkeContextName{
		Project:  parts[1],
		Location: parts[2],
		Cluster:  parts[3],
	}, true
}

func contextDisplayLabel(contextName string, currentContext string) string {
	label := contextName
	if parsed, ok := parseGKEContextName(contextName); ok {
		label = fmt.Sprintf("%s (%s)", parsed.Cluster, parsed.Project)
	}
	if contextName == currentContext {
		label += "  CURRENT"
	}
	return label
}

func contextOptions(
	contexts []string,
	currentContext string,
	includePlaceholder bool,
) []huh.Option[string] {
	options := make([]huh.Option[string], 0, len(contexts)+1)
	if includePlaceholder {
		options = append(options, huh.NewOption("Choose a context", ""))
	}
	labels := make([]string, len(contexts))
	labelCounts := make(map[string]int)
	for index, contextName := range contexts {
		labels[index] = contextDisplayLabel(contextName, currentContext)
		labelCounts[labels[index]]++
	}
	usedLabels := make(map[string]struct{}, len(contexts))
	for index, contextName := range contexts {
		label := labels[index]
		if labelCounts[label] > 1 {
			label += " — " + contextName
		}
		baseLabel := label
		for suffix := 2; ; suffix++ {
			if _, exists := usedLabels[label]; !exists {
				break
			}
			label = fmt.Sprintf("%s [%d]", baseLabel, suffix)
		}
		usedLabels[label] = struct{}{}
		options = append(
			options,
			huh.NewOption(
				label,
				contextName,
			),
		)
	}
	return options
}

func primaryContextOptions(
	primaryContext string,
	currentContext string,
) []huh.Option[string] {
	return primaryContextOptionsForMode(primaryContext, currentContext, true)
}

func primaryContextOptionsForMode(
	primaryContext string,
	currentContext string,
	unicode bool,
) []huh.Option[string] {
	options := make([]huh.Option[string], 0, 2)
	if primaryContext != "" {
		options = append(
			options,
			huh.NewOption(
				contextDisplayLabel(primaryContext, currentContext),
				primaryContext,
			),
		)
	}
	return append(
		options,
		huh.NewOption(chooseAnotherLabel(unicode), chooseAnotherContextValue),
	)
}

func chooseAnotherLabel(unicode bool) string {
	if unicode {
		return "Choose another…"
	}
	return "Choose another..."
}

func styleCurrentContext(
	options []huh.Option[string],
	currentContext string,
	enabled bool,
) []huh.Option[string] {
	if !enabled {
		return options
	}
	for index := range options {
		if options[index].Value == currentContext {
			options[index].Key = semanticWizardText(
				wizardActive,
				options[index].Key,
				true,
			)
		}
	}
	return options
}

func styleWizardSummary(summary string, enabled bool) string {
	if !enabled {
		return summary
	}
	lines := strings.Split(summary, "\n")
	if len(lines) > 0 {
		lines[0] = semanticWizardText(wizardTitleAccent, lines[0], true)
	}
	if len(lines) > 1 {
		last := len(lines) - 1
		lines[last] = semanticWizardText(wizardWarning, lines[last], true)
	}
	for index, line := range lines {
		rawStart := strings.Index(line, "(context: ")
		if rawStart < 0 || !strings.HasSuffix(line, ")") {
			continue
		}
		lines[index] = line[:rawStart] + semanticWizardText(
			wizardSecondary,
			line[rawStart:],
			true,
		)
	}
	return strings.Join(lines, "\n")
}

func newContextSelect(
	title string,
	options []huh.Option[string],
	value *string,
) *huh.Select[string] {
	return huh.NewSelect[string]().
		Title(title).
		Description(wizardDescription(
			"Press / and type to filter the available clusters.",
			false,
		)).
		Options(options...).
		Filtering(true).
		Value(value)
}

func validateContextChoice(choice string) error {
	if choice == "" {
		return errors.New("choose a Kubernetes context")
	}
	return nil
}

func isProductionContext(contextName string) bool {
	parsed, ok := parseGKEContextName(contextName)
	if !ok {
		return false
	}
	for _, token := range strings.FieldsFunc(
		strings.ToLower(parsed.Cluster),
		func(character rune) bool {
			return character == '-' || character == '.'
		},
	) {
		if token == "prod" || token == "production" {
			return true
		}
	}
	return false
}

func productionContextWarning(contextName string) string {
	return fmt.Sprintf(
		"Collection is read-only but may access sensitive production diagnostics in %s.",
		terminalLine(contextName),
	)
}

func wizardStepTitle(_ int, title string) string {
	return title
}

func wizardDescription(content string, _ bool) string {
	return content
}

func wizardGroupDescription(_ bool, _ bool) string {
	return ""
}

func wizardGroup(
	step int,
	title string,
	multiSelect bool,
	accessible bool,
	fields ...huh.Field,
) *huh.Group {
	return huh.NewGroup(fields...).
		Title("").
		Description(wizardGroupDescription(accessible, multiSelect))
}

func discoveryStatusLine(contextName string, accessible bool) string {
	message := fmt.Sprintf(
		"Checking read-only Kubernetes access and finding namespaces in %s…",
		selectedContextLabel(contextName),
	)
	if accessible {
		return message
	}
	return lipgloss.NewStyle().
		Foreground(qodoScoutColors().Cyan).
		Bold(true).
		Render(message)
}

func selectedContextLabel(contextName string) string {
	parsed, ok := parseGKEContextName(contextName)
	if !ok {
		return terminalLine(contextName)
	}
	words := strings.Fields(strings.NewReplacer("-", " ", "_", " ").Replace(parsed.Cluster))
	if len(words) == 0 {
		return terminalLine(contextName)
	}
	first, size := utf8.DecodeRuneInString(words[0])
	words[0] = strings.ToUpper(string(first)) + words[0][size:]
	if words[len(words)-1] != "cluster" {
		words = append(words, "cluster")
	}
	return terminalLine(strings.Join(words, " "))
}

func confirmationContextLabel(contextName string, contexts []string) string {
	raw := terminalLine(contextName)
	label := confirmationContextBaseLabel(raw)
	collisions := 0
	for _, candidate := range contexts {
		if confirmationContextBaseLabel(terminalLine(candidate)) == label {
			collisions++
		}
	}
	if collisions > 1 {
		return fmt.Sprintf("%s (context: %s)", label, raw)
	}
	return label
}

func confirmationContextBaseLabel(contextName string) string {
	parsed, ok := parseGKEContextName(contextName)
	if !ok {
		return contextName
	}
	return compactClusterLabel(parsed.Cluster)
}

func compactClusterLabel(cluster string) string {
	label := selectedContextLabel("gke_project_location_" + cluster)
	label = strings.TrimSuffix(label, " cluster")
	return label
}

func qodoScoutTheme() *huh.Theme {
	return qodoScoutThemeFor(true)
}

func qodoScoutThemeFor(enabled bool) *huh.Theme {
	theme := huh.ThemeBase()
	if !enabled {
		return theme
	}
	palette := qodoScoutColors()
	theme.Group.Title = theme.Group.Title.Foreground(palette.Purple).Bold(true)
	theme.Group.Description = theme.Group.Description.Foreground(palette.Neutral)
	theme.Focused.Title = theme.Focused.Title.Foreground(palette.Purple).Bold(true)
	theme.Focused.Description = theme.Focused.Description.Foreground(palette.Neutral)
	theme.Focused.SelectSelector = theme.Focused.SelectSelector.Foreground(palette.Cyan).Bold(true)
	theme.Focused.MultiSelectSelector = theme.Focused.MultiSelectSelector.Foreground(palette.Cyan).Bold(true)
	theme.Focused.SelectedOption = theme.Focused.SelectedOption.Foreground(palette.Purple).Bold(true)
	theme.Focused.SelectedPrefix = theme.Focused.SelectedPrefix.Foreground(palette.Green).Bold(true)
	theme.Focused.ErrorIndicator = theme.Focused.ErrorIndicator.Foreground(palette.Red)
	theme.Focused.ErrorMessage = theme.Focused.ErrorMessage.Foreground(palette.Red)
	theme.Help.ShortKey = theme.Help.ShortKey.Foreground(palette.Neutral)
	theme.Help.ShortDesc = theme.Help.ShortDesc.Foreground(palette.Neutral)
	theme.Focused.FocusedButton = theme.Focused.FocusedButton.
		Background(palette.Purple).
		Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#111827"}).
		Bold(true)
	return theme
}
