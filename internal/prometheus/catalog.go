package prometheus

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/qodo-ai/qodo-support-bundle/internal/redact"
)

const CatalogVersion = "v1"

const (
	namespaceRegexToken       = "{{namespace_regex}}"
	namespaceSelectorTemplate = `namespace=~"` + namespaceRegexToken + `"`
	allNamespacesRegex        = ".*"
	systemNamespacesRegex     = "^(?:kube-system|kube-public|kube-node-lease|gmp-system|gmp-public|cnrm-system|configconnector-operator-system|gke-managed-.*)$"
)

//go:embed catalog/v1.json
var catalogV1JSON []byte

var builtInCatalog = mustLoadCatalog(catalogV1JSON)

var catalogCategories = map[string]struct{}{
	"pod_container_cpu":             {},
	"memory_working_set_and_limits": {},
	"restart_oom":                   {},
	"replica_availability":          {},
	"request_rate":                  {},
	"error_rate":                    {},
	"latency":                       {},
	"queue_saturation":              {},
	"storage_pressure":              {},
}

// BuiltinCatalog returns a deep copy of the first versioned query catalog.
func BuiltinCatalog() Catalog {
	return cloneCatalog(builtInCatalog)
}

func mustLoadCatalog(data []byte) Catalog {
	catalog, err := decodeCatalog(data)
	if err != nil {
		panic(fmt.Sprintf("%v: %v", ErrInvalidCatalog, err))
	}
	return catalog
}

func decodeCatalog(data []byte) (Catalog, error) {
	if !utf8.Valid(data) {
		return Catalog{}, fmt.Errorf("catalog is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return Catalog{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var catalog Catalog
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return Catalog{}, err
	}
	if err := validateCatalog(catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func validateCatalog(catalog Catalog) error {
	if catalog.Version != CatalogVersion {
		return fmt.Errorf("version is %q", catalog.Version)
	}
	if len(catalog.Queries) == 0 || len(catalog.Queries) > MaximumQueries {
		return fmt.Errorf("query count is out of range")
	}
	seenIDs := make(map[string]struct{}, len(catalog.Queries))
	seenCategories := make(map[string]struct{}, len(catalogCategories))
	previousID := ""
	for _, query := range catalog.Queries {
		if !validIdentifier(query.ID) {
			return fmt.Errorf("invalid query id")
		}
		if query.ID <= previousID {
			return fmt.Errorf("query ids are not strictly sorted")
		}
		previousID = query.ID
		if _, duplicate := seenIDs[query.ID]; duplicate {
			return fmt.Errorf("duplicate query id")
		}
		seenIDs[query.ID] = struct{}{}
		if _, approved := catalogCategories[query.Category]; !approved {
			return fmt.Errorf("unknown query category")
		}
		seenCategories[query.Category] = struct{}{}
		if strings.TrimSpace(query.Description) != query.Description ||
			query.Description == "" ||
			strings.ContainsAny(query.Description, "\r\n") {
			return fmt.Errorf("invalid query description")
		}
		if strings.TrimSpace(query.PromQL) != query.PromQL ||
			query.PromQL == "" ||
			strings.ContainsAny(query.PromQL, "\r\n") {
			return fmt.Errorf("invalid query expression")
		}
		tokenCount, validTokenForms := namespaceTokenCount(query.PromQL)
		withoutApprovedTokens := strings.ReplaceAll(
			query.PromQL,
			namespaceRegexToken,
			"",
		)
		if !validTokenForms ||
			tokenCount == 0 ||
			strings.Count(withoutApprovedTokens, "{") != tokenCount ||
			strings.Count(withoutApprovedTokens, "}") != tokenCount ||
			strings.Contains(withoutApprovedTokens, "{{") ||
			strings.Contains(withoutApprovedTokens, "}}") {
			return fmt.Errorf("query is not strictly namespace scoped")
		}
		if query.StepSeconds < int64(MinimumStep.Seconds()) ||
			query.StepSeconds > int64(MaximumStep.Seconds()) {
			return fmt.Errorf("query step is out of range")
		}
		if len(query.RetainLabels) == 0 || len(query.RetainLabels) > 16 {
			return fmt.Errorf("retained label count is out of range")
		}
		previousLabel := ""
		for _, label := range query.RetainLabels {
			if !validLabelName(label) ||
				redact.IsSensitiveKey(label) ||
				label <= previousLabel {
				return fmt.Errorf("invalid or unsorted retained label")
			}
			previousLabel = label
		}
	}
	if len(seenCategories) != len(catalogCategories) {
		return fmt.Errorf("catalog does not cover every category")
	}
	return nil
}

func namespaceTokenCount(expression string) (int, bool) {
	const prefix = `namespace=~"`
	count := 0
	searchFrom := 0
	for {
		relative := strings.Index(expression[searchFrom:], namespaceRegexToken)
		if relative < 0 {
			return count, true
		}
		tokenStart := searchFrom + relative
		labelStart := tokenStart - len(prefix)
		tokenEnd := tokenStart + len(namespaceRegexToken)
		if labelStart <= 0 ||
			expression[labelStart:tokenStart] != prefix ||
			(expression[labelStart-1] != '{' && expression[labelStart-1] != ',') ||
			tokenEnd+1 >= len(expression) ||
			expression[tokenEnd] != '"' ||
			(expression[tokenEnd+1] != ',' && expression[tokenEnd+1] != '}') {
			return count, false
		}
		count++
		searchFrom = tokenEnd
	}
}

func namespaceScopeRegex(config Config) (string, error) {
	if err := validateNamespaceScope(config); err != nil {
		return "", err
	}
	if config.AllNamespaces {
		return allNamespacesRegex, nil
	}
	namespaces := append([]string(nil), config.Namespaces...)
	sort.Strings(namespaces)
	escaped := make([]string, len(namespaces))
	for index, namespace := range namespaces {
		escaped[index] = regexp.QuoteMeta(namespace)
	}
	return "^(?:" + strings.Join(escaped, "|") + ")$", nil
}

func renderScopedPromQL(query Query, config Config) (string, error) {
	tokenCount, validTokenForms := namespaceTokenCount(query.PromQL)
	if !validTokenForms || tokenCount == 0 {
		return "", ErrInvalidCatalog
	}
	scopeRegex, err := namespaceScopeRegex(config)
	if err != nil {
		return "", err
	}
	selector := `namespace=~"` + scopeRegex + `"`
	if config.ExcludeSystemNamespaces {
		selector += `,namespace!~"` + systemNamespacesRegex + `"`
	}
	rendered := strings.ReplaceAll(
		query.PromQL,
		namespaceSelectorTemplate,
		selector,
	)
	if rendered == query.PromQL ||
		strings.Contains(rendered, namespaceRegexToken) ||
		strings.Contains(rendered, "{{") ||
		strings.Contains(rendered, "}}") {
		return "", ErrInvalidCatalog
	}
	return rendered, nil
}

func cloneCatalog(catalog Catalog) Catalog {
	result := Catalog{
		Version: catalog.Version,
		Queries: make([]Query, len(catalog.Queries)),
	}
	for index, query := range catalog.Queries {
		result.Queries[index] = query
		result.Queries[index].RetainLabels = append([]string(nil), query.RetainLabels...)
	}
	return result
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' && index > 0 ||
			character == '_' && index > 0 {
			continue
		}
		return false
	}
	return true
}

func validLabelName(value string) bool {
	if len(value) == 0 || len(value) > 128 || value == "__name__" {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' && index > 0 ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

func labelAllowlist(query Query) map[string]struct{} {
	labels := make(map[string]struct{}, len(query.RetainLabels))
	for _, label := range query.RetainLabels {
		labels[label] = struct{}{}
	}
	return labels
}

func sortedLabelIdentity(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var identity strings.Builder
	for _, key := range keys {
		identity.WriteString(key)
		identity.WriteByte('=')
		identity.WriteString(labels[key])
		identity.WriteByte(0)
	}
	return identity.String()
}
