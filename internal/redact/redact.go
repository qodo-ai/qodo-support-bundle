package redact

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

const Replacement = "[REDACTED]"

const sensitiveAssignmentKeyPattern = `access[_-]?token|refresh[_-]?token|id[_-]?token|token|api[_-]?key|password|passwd|secret|client[_-]?secret|client[_-]?assertion|authorization|proxy[_-]?authorization|cookie|set-cookie|credentials?|private[_-]?key|email|first[_-]?name|last[_-]?name|full[_-]?name|phone|address|ssn|mrn`

var sensitiveKeys = map[string]struct{}{
	"accesstoken":        {},
	"address":            {},
	"apikey":             {},
	"authorization":      {},
	"clientassertion":    {},
	"clientsecret":       {},
	"cookie":             {},
	"credential":         {},
	"email":              {},
	"firstname":          {},
	"fullname":           {},
	"idtoken":            {},
	"lastname":           {},
	"mrn":                {},
	"password":           {},
	"passwd":             {},
	"phone":              {},
	"privatekey":         {},
	"proxyauthorization": {},
	"refreshtoken":       {},
	"samlresponse":       {},
	"secret":             {},
	"session":            {},
	"setcookie":          {},
	"ssn":                {},
	"token":              {},
	"xapikey":            {},
}

type replacementPattern struct {
	expression  *regexp.Regexp
	replacement string
}

// Redactor removes common credential and personal-data forms from diagnostic data.
type Redactor struct {
	patterns []replacementPattern
}

// New creates a redactor with the built-in fail-closed field policy.
func New() *Redactor {
	return &Redactor{
		patterns: []replacementPattern{
			{
				expression:  regexp.MustCompile(`(?i)(bearer|basic)[ \t]+[A-Za-z0-9._~+/\-=]+`),
				replacement: `${1} ` + Replacement,
			},
			{
				expression:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
				replacement: Replacement,
			},
			{
				expression: regexp.MustCompile(
					`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*)"(?:\\.|[^"])*"`,
				),
				replacement: `${1}"` + Replacement + `"`,
			},
			{
				expression: regexp.MustCompile(
					`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*)'(?:\\.|[^'])*'`,
				),
				replacement: `${1}'` + Replacement + `'`,
			},
			{
				expression: regexp.MustCompile(
					`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*["']?)[^"',;&\s]+`,
				),
				replacement: `${1}` + Replacement,
			},
			{
				expression: regexp.MustCompile(
					`(?i)([?&](?:access_token|refresh_token|id_token|api_key|password|client_secret|code|state)=)[^&#\s]+`,
				),
				replacement: `${1}` + Replacement,
			},
			{
				expression:  regexp.MustCompile(`(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b`),
				replacement: Replacement,
			},
			{
				expression:  regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
				replacement: Replacement,
			},
			{
				expression:  regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`),
				replacement: Replacement,
			},
			{
				expression:  regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
				replacement: Replacement,
			},
		},
	}
}

// IsSensitiveKey reports whether a field must be removed rather than inspected.
func IsSensitiveKey(key string) bool {
	normalized := strings.Map(func(character rune) rune {
		switch {
		case character >= 'A' && character <= 'Z':
			return character + ('a' - 'A')
		case character >= 'a' && character <= 'z':
			return character
		case character >= '0' && character <= '9':
			return character
		default:
			return -1
		}
	}, key)
	_, sensitive := sensitiveKeys[normalized]
	if sensitive {
		return true
	}
	for _, marker := range []string{
		"authorization",
		"clientassertion",
		"cookie",
		"credential",
		"email",
		"firstname",
		"fullname",
		"lastname",
		"mrn",
		"password",
		"phone",
		"privatekey",
		"proxyauthorization",
		"secret",
		"session",
		"ssn",
		"token",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

// Text redacts sensitive values embedded in unstructured text.
func (redactor *Redactor) Text(value string) string {
	result := value
	for _, pattern := range redactor.patterns {
		result = pattern.expression.ReplaceAllString(result, pattern.replacement)
	}
	return result
}

// Header preserves safe header values and records sensitive headers as present.
func (redactor *Redactor) Header(name string, value string) string {
	if IsSensitiveKey(name) {
		return Replacement
	}
	switch strings.ToLower(name) {
	case "location", "referer":
		return redactor.URL(value)
	}
	return redactor.Text(value)
}

// URL sanitizes credentials and sensitive query parameters.
func (redactor *Redactor) URL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return redactor.Text(rawURL)
	}
	if parsed.User != nil {
		parsed.User = url.User(Replacement)
	}
	query := parsed.Query()
	for key, values := range query {
		for index, value := range values {
			if IsSensitiveKey(key) ||
				strings.EqualFold(key, "code") ||
				strings.EqualFold(key, "state") {
				values[index] = Replacement
			} else {
				values[index] = redactor.Text(value)
			}
		}
		query[key] = values
	}
	parsed.RawQuery = query.Encode()
	parsed.Fragment = ""
	return redactor.Text(parsed.String())
}

// Value recursively sanitizes JSON-compatible data.
func (redactor *Redactor) Value(key string, value any) any {
	if IsSensitiveKey(key) {
		return Replacement
	}
	switch typed := value.(type) {
	case map[string]any:
		sanitized := make(map[string]any, len(typed))
		for childKey, childValue := range typed {
			sanitized[childKey] = redactor.Value(childKey, childValue)
		}
		return sanitized
	case []any:
		sanitized := make([]any, len(typed))
		for index, childValue := range typed {
			sanitized[index] = redactor.Value("", childValue)
		}
		return sanitized
	case string:
		return redactor.Text(typed)
	default:
		return value
	}
}

// JSONLine sanitizes a structured log line, falling back to text redaction.
func (redactor *Redactor) JSONLine(line string) string {
	var value any
	if err := json.Unmarshal([]byte(line), &value); err != nil {
		if jsonStart := strings.IndexAny(line, "{["); jsonStart > 0 {
			var suffix any
			if suffixErr := json.Unmarshal([]byte(line[jsonStart:]), &suffix); suffixErr == nil {
				sanitized, marshalErr := json.Marshal(redactor.Value("", suffix))
				if marshalErr == nil {
					return redactor.Text(line[:jsonStart]) + string(sanitized)
				}
			}
		}
		return redactor.Text(line)
	}
	sanitized, err := json.Marshal(redactor.Value("", value))
	if err != nil {
		return redactor.Text(line)
	}
	return string(sanitized)
}
