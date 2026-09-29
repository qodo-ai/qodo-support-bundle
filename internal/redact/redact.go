package redact

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

const (
	Replacement             = "[REDACTED]"
	RulesetVersion          = "1"
	maxEncodedQueryKeyBytes = 2048
	maxJSONKeyBytes         = 2048
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

var semanticURLFieldNames = []string{"location", "referer", "uri", "url"}

var semanticURLFieldSeparators = []string{"-", ".", "_"}

var extraSensitiveURLQueryKeys = []string{"code", "key", "state"}

type replacementPattern struct {
	expression  *regexp.Regexp
	replacement string
}

var malformedURLUserinfoPattern = regexp.MustCompile(
	`(?i)((?:[a-z][a-z0-9+.-]*:)?//)[^/?#\s]*@`,
)

var authorizationAssignmentPattern = regexp.MustCompile(
	`(?i)(\b(?:proxy[-_]?authorization|authorization)[ \t]*["']?[ \t]*[:=][ \t]*)[^\r\n]+`,
)

var textQueryAssignmentPattern = regexp.MustCompile(
	`[?&][^=&#\s]*=[^&#\s]*`,
)

var apiKeySuffixPattern = regexp.MustCompile(`(?i)(?:^|[_.-])api[_.-]?key$`)

var jsonAssignmentPrefixPattern = regexp.MustCompile(
	`["']?([A-Za-z0-9_.-]+)["']?[ \t]*[:=][ \t]*$`,
)

var unquotedSensitiveAssignmentPattern = regexp.MustCompile(
	`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*)([^"';&\s]+)`,
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
				expression:  authorizationAssignmentPattern,
				replacement: `${1}` + Replacement,
			},
			{
				expression:  regexp.MustCompile(`(?i)(bearer|basic)[ \t]+[A-Za-z0-9._~+/\-=]+`),
				replacement: `${1} ` + Replacement,
			},
			{
				expression:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{8,}\b`),
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
					`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*)"[^"\r\n]*$`,
				),
				replacement: `${1}"` + Replacement,
			},
			{
				expression: regexp.MustCompile(
					`(?i)((?:` + sensitiveAssignmentKeyPattern + `)[ \t]*["']?[ \t]*[:=][ \t]*)'[^'\r\n]*$`,
				),
				replacement: `${1}'` + Replacement,
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
	digest := sha256.Sum256([]byte(strings.Join(rulesetDigestParts(redactor), "\n")))
	return RulesetMetadata{
		Version: RulesetVersion,
		SHA256:  fmt.Sprintf("%x", digest),
	}
}

func rulesetDigestParts(redactor *Redactor) []string {
	parts := []string{
		RulesetVersion,
		Replacement,
		sensitiveAssignmentKeyPattern,
		malformedURLUserinfoPattern.String(),
		textQueryAssignmentPattern.String(),
		apiKeySuffixPattern.String(),
		jsonAssignmentPrefixPattern.String(),
		fmt.Sprint(maxJSONKeyBytes),
		unquotedSensitiveAssignmentPattern.String(),
		fmt.Sprint(maxEncodedQueryKeyBytes),
	}
	keys := make([]string, 0, len(sensitiveKeys))
	for key := range sensitiveKeys {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts = append(parts, keys...)
	parts = append(parts, semanticURLFieldNames...)
	parts = append(parts, semanticURLFieldSeparators...)
	parts = append(parts, extraSensitiveURLQueryKeys...)
	for _, pattern := range redactor.patterns {
		parts = append(parts, pattern.expression.String(), pattern.replacement)
	}
	return parts
}

// IsSensitiveKey reports whether a field must be removed rather than inspected.
func IsSensitiveKey(key string) bool {
	if apiKeySuffixPattern.MatchString(key) {
		return true
	}
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
	result = redactUnquotedSensitiveAssignments(result)
	return redactTextQueryAssignments(result)
}

func redactUnquotedSensitiveAssignments(value string) string {
	return unquotedSensitiveAssignmentPattern.ReplaceAllStringFunc(
		value,
		func(assignment string) string {
			parts := unquotedSensitiveAssignmentPattern.FindStringSubmatch(assignment)
			if len(parts) != 3 {
				return Replacement
			}
			suffix := ""
			if strings.HasSuffix(parts[2], ",") {
				suffix = ","
			}
			return parts[1] + Replacement + suffix
		},
	)
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

// SanitizeSplitJSONURLValue sanitizes a complete JSON string value at line start.
func (redactor *Redactor) SanitizeSplitJSONURLValue(line string) (string, int, bool) {
	valueOffset := skipJSONSpace(line, 0)
	if valueOffset >= len(line) || line[valueOffset] != '"' {
		return "", 0, false
	}
	end, closed := skipJSONQuoted(line, valueOffset)
	if !closed {
		return "", 0, false
	}
	var value string
	if err := json.Unmarshal([]byte(line[valueOffset:end]), &value); err != nil {
		return "", 0, false
	}
	sanitized, err := json.Marshal(redactor.URL(value))
	if err != nil {
		return "", 0, false
	}
	return line[:valueOffset] + string(sanitized), end, true
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
	if IsSensitiveKey(key) {
		return true
	}
	for _, extra := range extraSensitiveURLQueryKeys {
		if strings.EqualFold(key, extra) {
			return true
		}
	}
	return false
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
	for _, semanticKey := range semanticURLFieldNames {
		if normalized == semanticKey {
			return true
		}
		for _, separator := range semanticURLFieldSeparators {
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
			prefix := line[:jsonStart]
			if assignment := jsonAssignmentPrefixPattern.FindStringSubmatch(prefix); assignment != nil &&
				IsSensitiveKey(assignment[1]) {
				return redactor.Text(prefix) + Replacement
			}
			var suffix any
			if suffixErr := json.Unmarshal([]byte(line[jsonStart:]), &suffix); suffixErr == nil {
				sanitized, marshalErr := json.Marshal(redactor.Value("", suffix))
				if marshalErr == nil {
					return redactor.Text(prefix) + string(sanitized)
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

// JSONObjectFragment sanitizes a bounded structured JSON continuation.
func (redactor *Redactor) JSONObjectFragment(line string) (string, bool) {
	trimmed := strings.TrimRight(line, " \t\r")
	trailingSpace := line[len(trimmed):]
	leadingLength := len(trimmed) - len(strings.TrimLeft(trimmed, " \t"))
	leadingSpace := trimmed[:leadingLength]
	fragment := strings.TrimSpace(trimmed)
	if fragment == "" {
		return redactor.Text(line), true
	}

	leadingComma := strings.HasPrefix(fragment, ",")
	if leadingComma {
		fragment = strings.TrimSpace(fragment[1:])
	}

	wrapObject := startsJSONObjectMember(fragment)
	if !wrapObject && (fragment == "" || (fragment[0] != '{' && fragment[0] != '[')) {
		return redactor.Text(line), true
	}

	continuationComma := strings.HasSuffix(fragment, ",")
	if continuationComma {
		fragment = strings.TrimSpace(strings.TrimSuffix(fragment, ","))
	}
	sanitized, ok := redactor.sanitizeStructuredJSONFragment(fragment, wrapObject)
	if !ok {
		return "", false
	}
	if continuationComma {
		sanitized += ","
	}
	if leadingComma {
		sanitized = "," + sanitized
	}
	return leadingSpace + sanitized + trailingSpace, true
}

func startsJSONObjectMember(fragment string) bool {
	if fragment == "" || fragment[0] != '"' {
		return false
	}
	_, next, complete, invalid := parseJSONQuotedString(fragment, 0)
	if invalid || !complete {
		return true
	}
	next = skipJSONSpace(fragment, next)
	return next < len(fragment) && fragment[next] == ':'
}

func (redactor *Redactor) sanitizeStructuredJSONFragment(
	fragment string,
	wrapObject bool,
) (string, bool) {
	for end := len(fragment); ; {
		if sanitized, ok := redactor.completeAndSanitizeJSONFragment(fragment[:end], wrapObject); ok {
			return sanitized + fragment[end:], true
		}
		cursor := end
		for cursor > 0 && jsonSpace(fragment[cursor-1]) {
			cursor--
		}
		if cursor == 0 || (fragment[cursor-1] != '}' && fragment[cursor-1] != ']') {
			break
		}
		end = cursor - 1
	}
	return "", false
}

func (redactor *Redactor) completeAndSanitizeJSONFragment(
	fragment string,
	wrapObject bool,
) (string, bool) {
	completed, syntheticClosers, ok := completeJSONFragment(fragment, wrapObject)
	if !ok {
		return "", false
	}
	sanitized, ok := redactor.sanitizeJSONPreservingOrder(completed)
	if !ok || len(sanitized) < 2 {
		return "", false
	}
	start := 0
	if wrapObject {
		if sanitized[0] != '{' {
			return "", false
		}
		start = 1
	}
	end := len(sanitized) - syntheticClosers
	if end < start {
		return "", false
	}
	return sanitized[start:end], true
}

func (redactor *Redactor) sanitizeJSONPreservingOrder(raw string) (string, bool) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var output strings.Builder
	if !redactor.writeSanitizedJSONValue(decoder, &output, "", 0) {
		return "", false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return "", false
	}
	return output.String(), true
}

func (redactor *Redactor) writeSanitizedJSONValue(
	decoder *json.Decoder,
	output *strings.Builder,
	key string,
	depth int,
) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		value := token
		if text, ok := token.(string); ok {
			if isURLKey(key) {
				value = redactor.URL(text)
			} else {
				value = redactor.Text(text)
			}
		}
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			return false
		}
		output.Write(encoded)
		return true
	}
	if depth >= maxJSONSkipperDepth {
		return false
	}

	switch delimiter {
	case '{':
		output.WriteByte('{')
		first := true
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			rawKey, keyOK := keyToken.(string)
			if keyErr != nil || !keyOK {
				return false
			}
			var value strings.Builder
			if IsSensitiveKey(rawKey) {
				if !skipJSONDecoderValue(decoder, depth+1) {
					return false
				}
				encoded, _ := json.Marshal(Replacement)
				value.Write(encoded)
			} else if !redactor.writeSanitizedJSONValue(decoder, &value, rawKey, depth+1) {
				return false
			}
			sanitizedKey := redactor.Text(rawKey)
			if sanitizedKey == "" {
				continue
			}
			encodedKey, marshalErr := json.Marshal(sanitizedKey)
			if marshalErr != nil {
				return false
			}
			if !first {
				output.WriteByte(',')
			}
			first = false
			output.Write(encodedKey)
			output.WriteByte(':')
			output.WriteString(value.String())
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return false
		}
		output.WriteByte('}')
		return true
	case '[':
		output.WriteByte('[')
		first := true
		for decoder.More() {
			if !first {
				output.WriteByte(',')
			}
			first = false
			if !redactor.writeSanitizedJSONValue(decoder, output, "", depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return false
		}
		output.WriteByte(']')
		return true
	default:
		return false
	}
}

func skipJSONDecoderValue(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return true
	}
	if depth >= maxJSONSkipperDepth {
		return false
	}
	switch delimiter {
	case '{':
		for decoder.More() {
			if _, keyErr := decoder.Token(); keyErr != nil {
				return false
			}
			if !skipJSONDecoderValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !skipJSONDecoderValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func completeJSONFragment(fragment string, wrapObject bool) (string, int, bool) {
	var stack [maxJSONSkipperDepth]byte
	depth := 0
	if wrapObject {
		stack[0] = '}'
		depth = 1
	}
	inString := false
	escaped := false
	for index := 0; index < len(fragment); index++ {
		character := fragment[index]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			switch character {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
			continue
		}
		switch character {
		case '"':
			inString = true
		case '{':
			if depth >= len(stack) {
				return "", 0, false
			}
			stack[depth] = '}'
			depth++
		case '[':
			if depth >= len(stack) {
				return "", 0, false
			}
			stack[depth] = ']'
			depth++
		case '}', ']':
			if depth == 0 || stack[depth-1] != character {
				return "", 0, false
			}
			depth--
		}
	}
	if inString || escaped {
		return "", 0, false
	}

	var completed strings.Builder
	if wrapObject {
		completed.WriteByte('{')
	}
	completed.WriteString(fragment)
	for index := depth - 1; index >= 0; index-- {
		completed.WriteByte(stack[index])
	}
	return completed.String(), depth, true
}

const maxJSONSkipperDepth = 64

const (
	jsonSkipNone byte = iota
	jsonSkipString
	jsonSkipNumber
	jsonSkipKeyword
	jsonSkipContainer
)

const (
	jsonExpectKeyOrEmpty byte = iota
	jsonExpectKey
	jsonExpectColon
	jsonExpectValue
	jsonExpectCommaOrClose
	jsonExpectValueOrEmpty
)

const (
	jsonNumNone byte = iota
	jsonNumMinus
	jsonNumZero
	jsonNumInt
	jsonNumDot
	jsonNumFrac
	jsonNumExp
	jsonNumExpSign
	jsonNumExpDigits
)

type jsonSkipFrame struct {
	array bool
	state byte
}

// JSONValueSkipper tracks an in-progress sensitive JSON value across log lines
// using constant-size state.
type JSONValueSkipper struct {
	pending         bool
	invalid         bool
	unreadDelimiter bool
	kind            byte
	inString        bool
	escaped         bool
	unicodeLeft     int
	stringIsKey     bool
	keyword         string
	keywordPos      int
	numState        byte
	numValid        bool
	depth           int
	stack           [maxJSONSkipperDepth]jsonSkipFrame
}

// Pending reports whether later lines belong to a sensitive JSON value.
func (skipper *JSONValueSkipper) Pending() bool {
	return skipper.pending
}

// Start begins fail-closed skipping of a sensitive JSON value.
func (skipper *JSONValueSkipper) Start() {
	*skipper = JSONValueSkipper{pending: true}
}

// FailClosed latches the skipper so remaining lines are not emitted.
func (skipper *JSONValueSkipper) FailClosed() {
	skipper.invalid = true
	skipper.pending = true
}

// Consume advances skipper state over one log line without retaining it.
func (skipper *JSONValueSkipper) Consume(line string) int {
	if !skipper.pending || skipper.invalid {
		return len(line)
	}
	for i := 0; i < len(line); i++ {
		if skipper.invalid {
			return len(line)
		}
		skipper.feed(line[i])
		if skipper.invalid {
			return len(line)
		}
		if !skipper.pending {
			offset := i + 1
			if skipper.unreadDelimiter {
				offset = i
				skipper.unreadDelimiter = false
			}
			return skipper.completeRemainder(line, offset)
		}
	}
	skipper.finishLine()
	if skipper.invalid || skipper.pending {
		return len(line)
	}
	return len(line)
}

func (skipper *JSONValueSkipper) completeRemainder(line string, offset int) int {
	if jsonContinuationValid(line[offset:]) {
		return offset
	}
	skipper.fail()
	return len(line)
}

func jsonContinuationValid(remainder string) bool {
	index := skipJSONSpace(remainder, 0)
	if index == len(remainder) {
		return true
	}
	for index < len(remainder) && (remainder[index] == '}' || remainder[index] == ']') {
		index = skipJSONSpace(remainder, index+1)
		if index == len(remainder) {
			return true
		}
	}
	if remainder[index] != ',' {
		return false
	}
	index++
	index = skipJSONSpace(remainder, index)
	if index == len(remainder) {
		return true
	}
	if remainder[index] != '"' {
		return false
	}
	_, next, closed, invalid := parseJSONQuotedString(remainder, index)
	if !closed || invalid {
		return false
	}
	index = skipJSONSpace(remainder, next)
	return index < len(remainder) && remainder[index] == ':'
}

func jsonSpace(character byte) bool {
	return character == ' ' || character == '\t' || character == '\r'
}

func (skipper *JSONValueSkipper) fail() {
	skipper.invalid = true
	skipper.pending = true
}

func (skipper *JSONValueSkipper) complete() {
	if skipper.invalid {
		return
	}
	skipper.pending = false
}

func (skipper *JSONValueSkipper) feed(character byte) {
	if skipper.invalid {
		return
	}
	if skipper.inString {
		skipper.feedString(character)
		return
	}
	if skipper.kind == jsonSkipNumber {
		skipper.feedNumber(character)
		return
	}
	if skipper.kind == jsonSkipKeyword {
		skipper.feedKeyword(character)
		return
	}
	if character == ' ' || character == '\t' || character == '\r' {
		return
	}
	if skipper.depth > 0 {
		skipper.feedContainer(character)
		return
	}
	skipper.startValue(character)
}

func (skipper *JSONValueSkipper) startValue(character byte) {
	switch character {
	case '"':
		skipper.kind = jsonSkipString
		skipper.inString = true
		skipper.stringIsKey = false
	case '{':
		skipper.push(false)
	case '[':
		skipper.push(true)
	case 't':
		skipper.startKeyword("true")
	case 'f':
		skipper.startKeyword("false")
	case 'n':
		skipper.startKeyword("null")
	case '-':
		skipper.kind = jsonSkipNumber
		skipper.numState = jsonNumMinus
		skipper.numValid = false
	case '0':
		skipper.kind = jsonSkipNumber
		skipper.numState = jsonNumZero
		skipper.numValid = true
	case '1', '2', '3', '4', '5', '6', '7', '8', '9':
		skipper.kind = jsonSkipNumber
		skipper.numState = jsonNumInt
		skipper.numValid = true
	default:
		skipper.fail()
	}
}

func (skipper *JSONValueSkipper) startKeyword(word string) {
	skipper.kind = jsonSkipKeyword
	skipper.keyword = word
	skipper.keywordPos = 1
}

func (skipper *JSONValueSkipper) push(array bool) {
	if skipper.depth >= maxJSONSkipperDepth {
		skipper.fail()
		return
	}
	state := jsonExpectKeyOrEmpty
	if array {
		state = jsonExpectValueOrEmpty
	}
	skipper.stack[skipper.depth] = jsonSkipFrame{array: array, state: state}
	skipper.depth++
	skipper.kind = jsonSkipContainer
}

func (skipper *JSONValueSkipper) pop() {
	if skipper.depth == 0 {
		skipper.fail()
		return
	}
	skipper.depth--
	if skipper.depth == 0 {
		skipper.complete()
		return
	}
	skipper.afterValue()
}

func (skipper *JSONValueSkipper) afterValue() {
	if skipper.depth == 0 {
		skipper.complete()
		return
	}
	skipper.kind = jsonSkipContainer
	skipper.stack[skipper.depth-1].state = jsonExpectCommaOrClose
}

func (skipper *JSONValueSkipper) feedString(character byte) {
	if skipper.unicodeLeft > 0 {
		if !isJSONHex(character) {
			skipper.fail()
			return
		}
		skipper.unicodeLeft--
		return
	}
	if skipper.escaped {
		skipper.escaped = false
		switch character {
		case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
			return
		case 'u':
			skipper.unicodeLeft = 4
			return
		default:
			skipper.fail()
			return
		}
	}
	if character == '\\' {
		skipper.escaped = true
		return
	}
	if character == '"' {
		skipper.inString = false
		if skipper.depth == 0 {
			skipper.complete()
			return
		}
		if skipper.stringIsKey {
			skipper.kind = jsonSkipContainer
			skipper.stack[skipper.depth-1].state = jsonExpectColon
			return
		}
		skipper.afterValue()
		return
	}
	if character < 0x20 {
		skipper.fail()
	}
}

func (skipper *JSONValueSkipper) feedKeyword(character byte) {
	if skipper.keywordPos < len(skipper.keyword) {
		if character != skipper.keyword[skipper.keywordPos] {
			skipper.fail()
			return
		}
		skipper.keywordPos++
		if skipper.keywordPos == len(skipper.keyword) && skipper.depth == 0 {
			return
		}
		if skipper.keywordPos == len(skipper.keyword) {
			skipper.afterValue()
		}
		return
	}
	if jsonValueDelimiter(character) {
		if skipper.depth == 0 {
			skipper.unreadDelimiter = true
			skipper.complete()
			return
		}
		skipper.afterValue()
		skipper.feed(character)
		return
	}
	skipper.fail()
}

func (skipper *JSONValueSkipper) feedNumber(character byte) {
	if skipper.advanceNumber(character) {
		return
	}
	if jsonValueDelimiter(character) {
		if !skipper.numValid {
			skipper.fail()
			return
		}
		if skipper.depth == 0 {
			skipper.unreadDelimiter = true
			skipper.complete()
			return
		}
		skipper.afterValue()
		skipper.feed(character)
		return
	}
	skipper.fail()
}

func (skipper *JSONValueSkipper) advanceNumber(character byte) bool {
	switch skipper.numState {
	case jsonNumMinus:
		switch character {
		case '0':
			skipper.numState = jsonNumZero
			skipper.numValid = true
			return true
		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			skipper.numState = jsonNumInt
			skipper.numValid = true
			return true
		}
	case jsonNumZero:
		switch character {
		case '.':
			skipper.numState = jsonNumDot
			skipper.numValid = false
			return true
		case 'e', 'E':
			skipper.numState = jsonNumExp
			skipper.numValid = false
			return true
		}
	case jsonNumInt:
		switch character {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		case '.':
			skipper.numState = jsonNumDot
			skipper.numValid = false
			return true
		case 'e', 'E':
			skipper.numState = jsonNumExp
			skipper.numValid = false
			return true
		}
	case jsonNumDot:
		if character >= '0' && character <= '9' {
			skipper.numState = jsonNumFrac
			skipper.numValid = true
			return true
		}
	case jsonNumFrac:
		switch character {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		case 'e', 'E':
			skipper.numState = jsonNumExp
			skipper.numValid = false
			return true
		}
	case jsonNumExp:
		switch character {
		case '+', '-':
			skipper.numState = jsonNumExpSign
			return true
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			skipper.numState = jsonNumExpDigits
			skipper.numValid = true
			return true
		}
	case jsonNumExpSign:
		if character >= '0' && character <= '9' {
			skipper.numState = jsonNumExpDigits
			skipper.numValid = true
			return true
		}
	case jsonNumExpDigits:
		if character >= '0' && character <= '9' {
			return true
		}
	}
	return false
}

func (skipper *JSONValueSkipper) feedContainer(character byte) {
	frame := &skipper.stack[skipper.depth-1]
	switch frame.state {
	case jsonExpectKeyOrEmpty:
		if character == '}' && !frame.array {
			skipper.pop()
			return
		}
		if character == '"' {
			skipper.kind = jsonSkipString
			skipper.inString = true
			skipper.stringIsKey = true
			return
		}
		skipper.fail()
	case jsonExpectKey:
		if character == '"' {
			skipper.kind = jsonSkipString
			skipper.inString = true
			skipper.stringIsKey = true
			return
		}
		skipper.fail()
	case jsonExpectValueOrEmpty:
		if character == ']' && frame.array {
			skipper.pop()
			return
		}
		skipper.startValue(character)
	case jsonExpectColon:
		if character == ':' {
			frame.state = jsonExpectValue
			return
		}
		skipper.fail()
	case jsonExpectValue:
		skipper.startValue(character)
	case jsonExpectCommaOrClose:
		if character == ',' {
			if frame.array {
				frame.state = jsonExpectValue
			} else {
				frame.state = jsonExpectKey
			}
			return
		}
		if character == '}' && !frame.array {
			skipper.pop()
			return
		}
		if character == ']' && frame.array {
			skipper.pop()
			return
		}
		skipper.fail()
	default:
		skipper.fail()
	}
}

func (skipper *JSONValueSkipper) finishLine() {
	if skipper.invalid || !skipper.pending {
		return
	}
	if skipper.inString || skipper.escaped || skipper.unicodeLeft > 0 {
		skipper.fail()
		return
	}
	switch skipper.kind {
	case jsonSkipNumber:
		if skipper.numValid && skipper.depth == 0 {
			skipper.complete()
			return
		}
		if skipper.numValid {
			skipper.afterValue()
			return
		}
		skipper.fail()
	case jsonSkipKeyword:
		if skipper.keywordPos == len(skipper.keyword) && skipper.depth == 0 {
			skipper.complete()
			return
		}
		if skipper.keywordPos == len(skipper.keyword) {
			skipper.afterValue()
			return
		}
		skipper.fail()
	}
}

func jsonValueDelimiter(character byte) bool {
	switch character {
	case ' ', '\t', '\r', ',', '}', ']':
		return true
	default:
		return false
	}
}

func isJSONHex(character byte) bool {
	switch {
	case character >= '0' && character <= '9':
		return true
	case character >= 'a' && character <= 'f':
		return true
	case character >= 'A' && character <= 'F':
		return true
	default:
		return false
	}
}

type JSONAssignment struct {
	Key         string
	KeyOffset   int
	ValueOffset int
	Invalid     bool
}

type JSONAssignmentMode int

const (
	JSONAssignmentModeRaw JSONAssignmentMode = iota
	JSONAssignmentModeObjectFragment
)

// SensitiveJSONAssignment locates a sensitive JSON field on a raw log line.
func SensitiveJSONAssignment(line string) (JSONAssignment, bool) {
	return ScanSensitiveJSONAssignment(line, JSONAssignmentModeRaw)
}

// SensitiveJSONObjectAssignment locates a sensitive JSON field in a parent-object fragment.
func SensitiveJSONObjectAssignment(line string) (JSONAssignment, bool) {
	return ScanSensitiveJSONAssignment(line, JSONAssignmentModeObjectFragment)
}

// ScanSensitiveJSONAssignment locates a sensitive JSON field using an explicit scan mode.
func ScanSensitiveJSONAssignment(line string, mode JSONAssignmentMode) (JSONAssignment, bool) {
	if assignment, ok := scanStructuredJSONAssignment(line, mode, IsSensitiveKey); ok {
		return assignment, true
	}
	if mode == JSONAssignmentModeRaw {
		return JSONAssignment{}, false
	}
	trimmed := strings.TrimRight(line, " \t\r")
	assignment := jsonAssignmentPrefixPattern.FindStringSubmatch(trimmed)
	if assignment == nil || !IsSensitiveKey(assignment[1]) {
		return JSONAssignment{}, false
	}
	key := assignment[1]
	index := strings.LastIndex(trimmed, key)
	if index > 0 {
		quote := index - 1
		if (trimmed[quote] == '"' || trimmed[quote] == '\'') && jsonQuoteIsEscaped(trimmed, quote) {
			return JSONAssignment{}, false
		}
	}
	return JSONAssignment{Key: key, KeyOffset: index - 1, ValueOffset: len(trimmed)}, true
}

// ScanSemanticURLJSONAssignment locates a semantic URL field using an explicit scan mode.
func ScanSemanticURLJSONAssignment(line string, mode JSONAssignmentMode) (JSONAssignment, bool) {
	return scanStructuredJSONAssignment(line, mode, isURLKey)
}

func scanStructuredJSONAssignment(
	line string,
	mode JSONAssignmentMode,
	matchKey func(string) bool,
) (JSONAssignment, bool) {
	var stack [maxJSONSkipperDepth]jsonSkipFrame
	depth := 0
	fragment := mode == JSONAssignmentModeObjectFragment
	root := jsonSkipFrame{state: jsonExpectKey}
	sawNonSpace := false

	current := func() *jsonSkipFrame {
		if depth == 0 {
			return &root
		}
		return &stack[depth-1]
	}

	pop := func() {
		if depth == 0 {
			root.state = jsonExpectCommaOrClose
			return
		}
		depth--
		if depth == 0 {
			root.state = jsonExpectCommaOrClose
			return
		}
		stack[depth-1].state = jsonExpectCommaOrClose
	}

	for index := 0; index < len(line); index++ {
		character := line[index]
		if jsonSpace(character) {
			continue
		}
		if !fragment && depth == 0 {
			switch {
			case character == '{':
				if !pushJSONAssignmentFrame(&stack, &depth, false) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
				continue
			case character == '[' && !sawNonSpace:
				if !pushJSONAssignmentFrame(&stack, &depth, true) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
				continue
			case character == '"' && !sawNonSpace:
			case root.state == jsonExpectValue || root.state == jsonExpectColon || root.state == jsonExpectCommaOrClose:
			default:
				sawNonSpace = true
				continue
			}
		}
		frame := current()
		switch frame.state {
		case jsonExpectKeyOrEmpty:
			if character == '}' && !frame.array {
				pop()
				continue
			}
			fallthrough
		case jsonExpectKey:
			if character == '{' {
				if !pushJSONAssignmentFrame(&stack, &depth, false) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
				continue
			}
			if character == '[' {
				if !pushJSONAssignmentFrame(&stack, &depth, true) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
				continue
			}
			if character == ',' || character == '}' || character == ']' {
				continue
			}
			if character != '"' {
				continue
			}
			if jsonQuoteIsEscaped(line, index) {
				continue
			}
			assignment, next, matched, failClosed := readJSONAssignmentKey(line, index, matchKey)
			if failClosed {
				return assignment, true
			}
			if matched {
				return assignment, true
			}
			frame.state = jsonExpectValue
			if next > index {
				index = next - 1
			}
		case jsonExpectColon:
			if character == ':' || character == '=' {
				frame.state = jsonExpectValue
			}
		case jsonExpectValueOrEmpty:
			if character == ']' && frame.array {
				pop()
				continue
			}
			fallthrough
		case jsonExpectValue:
			switch character {
			case '"':
				if jsonQuoteIsEscaped(line, index) {
					continue
				}
				next, closed := skipJSONQuoted(line, index)
				if !closed {
					return JSONAssignment{}, false
				}
				frame.state = jsonExpectCommaOrClose
				index = next - 1
			case '{':
				if !pushJSONAssignmentFrame(&stack, &depth, false) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
			case '[':
				if !pushJSONAssignmentFrame(&stack, &depth, true) {
					return JSONAssignment{Invalid: true, ValueOffset: index}, true
				}
			case '}', ']':
				pop()
			default:
				index = skipJSONLiteral(line, index) - 1
				frame.state = jsonExpectCommaOrClose
			}
		case jsonExpectCommaOrClose:
			if character == ',' {
				if frame.array {
					frame.state = jsonExpectValue
				} else {
					frame.state = jsonExpectKey
				}
				continue
			}
			if (character == '}' && !frame.array) || (character == ']' && frame.array) {
				pop()
				continue
			}
			return JSONAssignment{Invalid: true, ValueOffset: index}, true
		}
	}
	return JSONAssignment{}, false
}

func pushJSONAssignmentFrame(stack *[maxJSONSkipperDepth]jsonSkipFrame, depth *int, array bool) bool {
	if *depth >= maxJSONSkipperDepth {
		return false
	}
	state := jsonExpectKeyOrEmpty
	if array {
		state = jsonExpectValueOrEmpty
	}
	stack[*depth] = jsonSkipFrame{array: array, state: state}
	*depth++
	return true
}

func readJSONAssignmentKey(
	line string,
	quoteIndex int,
	matchKey func(string) bool,
) (JSONAssignment, int, bool, bool) {
	key, next, closed, invalid := parseJSONQuotedString(line, quoteIndex)
	if !closed {
		return JSONAssignment{Invalid: true, ValueOffset: len(line)}, quoteIndex, false, true
	}
	cursor := skipJSONSpace(line, next)
	if cursor >= len(line) || (line[cursor] != ':' && line[cursor] != '=') {
		if invalid {
			return JSONAssignment{Invalid: true, ValueOffset: cursor}, next, false, true
		}
		return JSONAssignment{}, next, false, false
	}
	valueOffset := skipJSONSpace(line, cursor+1)
	if invalid {
		return JSONAssignment{Invalid: true, ValueOffset: valueOffset}, valueOffset, false, true
	}
	if matchKey(key) {
		return JSONAssignment{
			Key:         key,
			KeyOffset:   quoteIndex,
			ValueOffset: valueOffset,
		}, valueOffset, true, false
	}
	return JSONAssignment{}, valueOffset, false, false
}

func jsonQuoteIsEscaped(line string, quoteIndex int) bool {
	escapes := 0
	for quoteIndex-1-escapes >= 0 && line[quoteIndex-1-escapes] == '\\' {
		escapes++
	}
	return escapes%2 == 1
}

func skipJSONQuoted(line string, quoteIndex int) (int, bool) {
	escaped := false
	for index := quoteIndex + 1; index < len(line); index++ {
		if escaped {
			escaped = false
			continue
		}
		if line[index] == '\\' {
			escaped = true
			continue
		}
		if line[index] == '"' {
			return index + 1, true
		}
	}
	return quoteIndex, false
}

func skipJSONLiteral(line string, index int) int {
	if index >= len(line) {
		return index
	}
	switch line[index] {
	case 't':
		return consumeJSONKeyword(line, index, "true")
	case 'f':
		return consumeJSONKeyword(line, index, "false")
	case 'n':
		return consumeJSONKeyword(line, index, "null")
	case '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		index++
		for index < len(line) {
			character := line[index]
			if jsonSpace(character) || character == ',' || character == '}' || character == ']' {
				return index
			}
			index++
		}
		return index
	default:
		return index + 1
	}
}

func consumeJSONKeyword(line string, index int, word string) int {
	if strings.HasPrefix(line[index:], word) {
		return index + len(word)
	}
	return index + 1
}

func parseJSONQuotedString(line string, quoteIndex int) (string, int, bool, bool) {
	if quoteIndex >= len(line) || line[quoteIndex] != '"' {
		return "", quoteIndex, false, false
	}
	escaped := false
	overlong := false
	for index := quoteIndex + 1; index < len(line); index++ {
		if index-quoteIndex > maxJSONKeyBytes {
			overlong = true
		}
		character := line[index]
		if escaped {
			escaped = false
			continue
		}
		if character == '\\' {
			escaped = true
			continue
		}
		if character == '"' {
			if overlong {
				return "", index + 1, true, true
			}
			raw := line[quoteIndex : index+1]
			var decoded string
			if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
				return "", index + 1, true, true
			}
			return decoded, index + 1, true, false
		}
	}
	return "", quoteIndex, false, false
}

func skipJSONSpace(line string, index int) int {
	for index < len(line) && jsonSpace(line[index]) {
		index++
	}
	return index
}

// LineEndsWithSensitiveJSONAssignment reports a pretty-printed sensitive key
// whose value continues on a later line.
func LineEndsWithSensitiveJSONAssignment(line string) bool {
	assignment, ok := SensitiveJSONObjectAssignment(line)
	if !ok {
		return false
	}
	return assignment.ValueOffset >= len(strings.TrimRight(line, " \t\r"))
}

// JSONStructureTracker tracks bounded JSON object/array context across log lines.
type JSONStructureTracker struct {
	depth       int
	stack       [maxJSONSkipperDepth]bool
	inString    bool
	escaped     bool
	established bool
	invalid     bool
}

// Invalid reports whether structured context has latched fail-closed.
func (tracker *JSONStructureTracker) Invalid() bool {
	return tracker.invalid
}

// AssignmentMode is the scan mode implied by current nesting.
func (tracker *JSONStructureTracker) AssignmentMode() JSONAssignmentMode {
	if tracker.invalid || tracker.depth > 0 {
		return JSONAssignmentModeObjectFragment
	}
	return JSONAssignmentModeRaw
}

// Observe advances tracker state over a fragment without retaining it.
func (tracker *JSONStructureTracker) Observe(fragment string) {
	if tracker.invalid {
		return
	}
	for index := 0; index < len(fragment); index++ {
		if !tracker.established {
			if !plausibleJSONOpener(fragment, index) {
				continue
			}
			tracker.established = true
		}
		tracker.feed(fragment[index])
		if tracker.invalid {
			return
		}
	}
}

// EndLine records a raw newline. Newlines inside JSON strings fail closed.
func (tracker *JSONStructureTracker) EndLine() {
	if tracker.invalid {
		return
	}
	if tracker.inString || tracker.escaped {
		tracker.FailClosed()
		return
	}
	if tracker.depth == 0 {
		tracker.established = false
	}
}

// FailClosed latches invalid structured context.
func (tracker *JSONStructureTracker) FailClosed() {
	tracker.invalid = true
}

func (tracker *JSONStructureTracker) feed(character byte) {
	if tracker.inString {
		if tracker.escaped {
			tracker.escaped = false
			return
		}
		if character == '\\' {
			tracker.escaped = true
			return
		}
		if character == '"' {
			tracker.inString = false
		}
		return
	}
	if jsonSpace(character) {
		return
	}
	switch character {
	case '"':
		tracker.inString = true
	case '{':
		tracker.push(false)
	case '[':
		tracker.push(true)
	case '}':
		tracker.pop(false)
	case ']':
		tracker.pop(true)
	}
}

func plausibleJSONOpener(fragment string, index int) bool {
	if fragment[index] != '{' && fragment[index] != '[' {
		return false
	}
	prefixIsSpace := strings.TrimSpace(fragment[:index]) == ""
	if fragment[index] == '[' && !prefixIsSpace {
		return false
	}
	next := index + 1
	for next < len(fragment) && jsonSpace(fragment[next]) {
		next++
	}
	if next == len(fragment) {
		return prefixIsSpace
	}
	if fragment[index] == '{' {
		return fragment[next] == '"' || fragment[next] == '}'
	}
	switch fragment[next] {
	case '{', '[', '"', ']', '-', 't', 'f', 'n':
		return true
	default:
		return fragment[next] >= '0' && fragment[next] <= '9'
	}
}

func (tracker *JSONStructureTracker) push(array bool) {
	if tracker.depth >= maxJSONSkipperDepth {
		tracker.FailClosed()
		return
	}
	tracker.stack[tracker.depth] = array
	tracker.depth++
}

func (tracker *JSONStructureTracker) pop(array bool) {
	if tracker.depth == 0 || tracker.stack[tracker.depth-1] != array {
		tracker.FailClosed()
		return
	}
	tracker.depth--
}
