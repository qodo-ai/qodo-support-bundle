package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

const (
	wizardPurpose             = "Qodo Scout · Secure diagnostics for Qodo on-prem environments"
	wizardNavigationHelp      = "Use arrows to navigate · / to filter · Enter to select or continue · Ctrl+C to cancel"
	wizardMultiSelectHelp     = "Use arrows to move · Space or x to toggle multiple · Enter to continue · Ctrl+C to cancel"
	chooseAnotherContextValue = "\x00choose-another-context"
)

type gkeContextName struct {
	Project  string
	Location string
	Cluster  string
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
		label = "CURRENT · " + label
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
	friendlyCounts := make(map[string]int)
	for _, contextName := range contexts {
		if _, ok := parseGKEContextName(contextName); ok {
			friendlyCounts[contextDisplayLabel(contextName, "")]++
		}
	}
	for _, contextName := range contexts {
		label := contextDisplayLabel(contextName, currentContext)
		if friendlyCounts[contextDisplayLabel(contextName, "")] > 1 {
			label += " — " + contextName
		}
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
		huh.NewOption("Choose another cluster", chooseAnotherContextValue),
	)
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

func wizardStepTitle(step int, title string) string {
	return fmt.Sprintf("Step %d of 5 · %s", step, title)
}

func wizardDescription(content string, multiSelect bool) string {
	help := wizardNavigationHelp
	if multiSelect {
		help = wizardMultiSelectHelp
	}
	if content == "" {
		return help
	}
	return content + "\n" + help
}

func wizardGroup(
	step int,
	title string,
	multiSelect bool,
	fields ...huh.Field,
) *huh.Group {
	help := wizardNavigationHelp
	if multiSelect {
		help = wizardMultiSelectHelp
	}
	return huh.NewGroup(fields...).
		Title(wizardStepTitle(step, title)).
		Description(wizardPurpose + "\n" + help)
}

func discoveryStatusLine(contextName string, accessible bool) string {
	message := fmt.Sprintf(
		"Checking cluster access and discovering namespaces for %s…",
		terminalLine(contextName),
	)
	if accessible {
		return message
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.AdaptiveColor{Light: "#005A8D", Dark: "#7DD3FC"}).
		Bold(true).
		Render(message)
}

func qodoScoutTheme() *huh.Theme {
	theme := huh.ThemeBase()
	accent := lipgloss.AdaptiveColor{Light: "#005A8D", Dark: "#7DD3FC"}
	emphasis := lipgloss.AdaptiveColor{Light: "#17324D", Dark: "#E5F4FF"}
	muted := lipgloss.AdaptiveColor{Light: "#4B5563", Dark: "#A7B4C2"}

	theme.Group.Title = theme.Group.Title.Foreground(accent).Bold(true)
	theme.Group.Description = theme.Group.Description.Foreground(muted)
	theme.Focused.Title = theme.Focused.Title.Foreground(emphasis).Bold(true)
	theme.Focused.Description = theme.Focused.Description.Foreground(muted)
	theme.Focused.SelectSelector = theme.Focused.SelectSelector.Foreground(accent)
	theme.Focused.MultiSelectSelector = theme.Focused.MultiSelectSelector.Foreground(accent)
	theme.Focused.SelectedPrefix = theme.Focused.SelectedPrefix.Foreground(accent)
	theme.Focused.FocusedButton = theme.Focused.FocusedButton.
		Background(accent).
		Foreground(lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#07131D"}).
		Bold(true)
	return theme
}
