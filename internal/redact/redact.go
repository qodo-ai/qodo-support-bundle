package redact

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	Replacement             = "[REDACTED]"
	RulesetVersion          = "1"
	maxEncodedQueryKeyBytes = 2048
)

// RulesetMetadata identifies the exact built-in redaction policy.
type RulesetMetadata struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

const sensitiveAssignmentKeyPattern = `aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id|access[_-]?token|refresh[_-]?token|id[_-]?token|code[_-]?verifier|saml[_-]?response|session(?:[_-]?id)?|token|api[_-]?key|password|passwd|secret|client[_-]?secret|client[_-]?assertion|authorization|proxy[_-]?authorization|cookie|set-cookie|credentials?|private[_-]?key|email|first[_-]?name|last[_-]?name|full[_-]?name|phone|address|ssn|mrn|date[_-]?of[_-]?birth|birth[_-]?date|dob`

var sensitiveKeys = map[string]struct{}{
	"accesstoken":        {},
	"address":            {},
	"apikey":             {},
	"authorization":      {},
	"awsaccesskeyid":     {},
	"awssecretaccesskey": {},
	"birthdate":          {},
	"clientassertion":    {},
	"clientsecret":       {},
	"codeverifier":       {},
	"cookie":             {},
	"credential":         {},
	"dateofbirth":        {},
	"dob":                {},
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

var malformedURLUserinfoPattern = regexp.MustCompile(
	`(?i)((?:[a-z][a-z0-9+.-]*:)?//)[^/?#\s]*@`,
)

var textQueryAssignmentPattern = regexp.MustCompile(
	`[?&][^=&#\s]*=[^&#\s]*`,
)

// Redactor removes common credential and personal-data forms from diagnostic data.
type Redactor struct {
	patterns []replacementPattern
}

// New creates a redactor with the built-in fail-closed field policy.
func New() *Redactor {
	return &Redactor{
		patterns: []replacementPattern{
			{
				expression:  malformedURLUserinfoPattern,
				replacement: `${1}` + Replacement + "@",
			},
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

// Ruleset returns a stable version and hash for audit manifests.
func (redactor *Redactor) Ruleset() RulesetMetadata {
	parts := []string{
		RulesetVersion,
		Replacement,
		sensitiveAssignmentKeyPattern,
		malformedURLUserinfoPattern.String(),
		textQueryAssignmentPattern.String(),
		fmt.Sprint(maxEncodedQueryKeyBytes),
	}
	keys := make([]string, 0, len(sensitiveKeys))
	for key := range sensitiveKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts = append(parts, keys...)
	for _, pattern := range redactor.patterns {
		parts = append(parts, pattern.expression.String(), pattern.replacement)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return RulesetMetadata{
		Version: RulesetVersion,
		SHA256:  fmt.Sprintf("%x", digest),
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
		"awsaccesskeyid",
		"clientassertion",
		"codeverifier",
		"cookie",
		"credential",
		"dateofbirth",
		"email",
		"firstname",
		"fullname",
		"lastname",
		"mrn",
		"password",
		"phone",
		"privatekey",
		"proxyauthorization",
		"birthdate",
		"samlresponse",
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
	return redactTextQueryAssignments(result)
}

func redactTextQueryAssignments(value string) string {
	return textQueryAssignmentPattern.ReplaceAllStringFunc(value, func(assignment string) string {
		equals := strings.IndexByte(assignment, '=')
		if equals < 0 {
			return assignment
		}
		encodedKey := assignment[1:equals]
		decodedKey, err := decodeTextQueryKey(encodedKey)
		if err == nil && !isSensitiveURLQueryKey(decodedKey) {
			return assignment
		}
		return assignment[:equals+1] + Replacement
	})
}

func decodeTextQueryKey(encodedKey string) (string, error) {
	if encodedKey == "" || len(encodedKey) > maxEncodedQueryKeyBytes {
		return "", errors.New("invalid query key length")
	}
	decodedKey, err := url.QueryUnescape(encodedKey)
	if err != nil {
		return "", fmt.Errorf("decode query key: %w", err)
	}
	return decodedKey, nil
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
		withoutUserinfo := malformedURLUserinfoPattern.ReplaceAllString(
			rawURL,
			`${1}`+Replacement+"@",
		)
		if fragmentStart := strings.IndexByte(withoutUserinfo, '#'); fragmentStart >= 0 {
			withoutUserinfo = withoutUserinfo[:fragmentStart]
		}
		return redactor.redactMalformedURLQuery(withoutUserinfo)
	}
	if parsed.User != nil {
		parsed.User = url.User(Replacement)
	}
	query := parsed.Query()
	for key, values := range query {
		for index, value := range values {
			if isSensitiveURLQueryKey(key) {
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

func (redactor *Redactor) redactMalformedURLQuery(rawURL string) string {
	queryStart := strings.IndexByte(rawURL, '?')
	if queryStart < 0 {
		return redactor.Text(rawURL)
	}
	parts := strings.Split(rawURL[queryStart+1:], "&")
	for index, part := range parts {
		key, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			parts[index] = redactor.Text(part)
			continue
		}
		decodedKey, err := decodeTextQueryKey(key)
		if err != nil || isSensitiveURLQueryKey(decodedKey) {
			parts[index] = key + "=" + Replacement
			continue
		}
		parts[index] = redactor.Text(part)
	}
	return redactor.Text(rawURL[:queryStart]) + "?" + strings.Join(parts, "&")
}

func isSensitiveURLQueryKey(key string) bool {
	return IsSensitiveKey(key) ||
		strings.EqualFold(key, "code") ||
		strings.EqualFold(key, "state") ||
		strings.EqualFold(key, "key")
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
			sanitizedKey := redactor.Text(childKey)
			if sanitizedKey == "" {
				continue
			}
			sanitized[sanitizedKey] = redactor.Value(childKey, childValue)
		}
		return sanitized
	case []any:
		sanitized := make([]any, len(typed))
		for index, childValue := range typed {
			sanitized[index] = redactor.Value("", childValue)
		}
		return sanitized
	case string:
		if isURLKey(key) {
			return redactor.URL(typed)
		}
		return redactor.Text(typed)
	default:
		return value
	}
}

func isURLKey(key string) bool {
	normalized := strings.ToLower(key)
	for _, semanticKey := range []string{"url", "uri", "location", "referer"} {
		if normalized == semanticKey {
			return true
		}
		for _, separator := range []string{"_", "-", "."} {
			if strings.HasSuffix(normalized, separator+semanticKey) {
				return true
			}
		}
	}
	return false
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
