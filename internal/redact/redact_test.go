package redact

import (
	"strings"
	"testing"
)

func TestTextRemovesCredentialsAndEmail(t *testing.T) {
	t.Parallel()
	redactor := New()
	input := "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.abcdefghijklmno.signaturevalue " +
		"email=user@example.com&access_token=top-secret"

	output := redactor.Text(input)

	for _, forbidden := range []string{
		"eyJhbGciOiJSUzI1NiJ9",
		"user@example.com",
		"top-secret",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains sensitive value %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, Replacement) {
		t.Fatalf("output does not contain redaction marker: %s", output)
	}
}

func TestAuthorizationAssignmentRedactsAnySchemeInTextAndJSON(t *testing.T) {
	t.Parallel()
	const credential = "token abc123"
	redactor := New()

	for name, output := range map[string]string{
		"text": redactor.Text("Authorization: " + credential),
		"json": redactor.JSONLine(`{"message":"Authorization: ` + credential + `"}`),
	} {
		for _, forbidden := range []string{"token", "abc123"} {
			if strings.Contains(output, forbidden) {
				t.Errorf("%s output contains authorization value %q: %s", name, forbidden, output)
			}
		}
		if !strings.Contains(output, "Authorization: "+Replacement) {
			t.Errorf("%s output does not contain redacted authorization value: %s", name, output)
		}
	}
}

func TestShortPayloadJWTIsRedactedFromTextAndJSON(t *testing.T) {
	t.Parallel()
	const token = "eyJhbGciOiJIUzI1NiJ9.e30.abcdefghijklmnopqrstuvwxyz0123456789"
	redactor := New()

	for name, output := range map[string]string{
		"text": redactor.Text("standalone " + token + " token"),
		"json": redactor.JSONLine(`{"message":"standalone ` + token + ` token"}`),
	} {
		if strings.Contains(output, token) {
			t.Errorf("%s output contains short-payload JWT: %s", name, output)
		}
		if !strings.Contains(output, Replacement) {
			t.Errorf("%s output does not contain redaction marker: %s", name, output)
		}
	}
}

func TestTextRedactsAdditionalSensitiveAssignments(t *testing.T) {
	t.Parallel()
	redactor := New()
	tests := []string{
		`private_key=raw-private-key`,
		`client-assertion: "raw-client-assertion"`,
		`credential='raw-credential'`,
		`credentials=raw-credentials`,
		`Proxy_Authorization=raw-proxy-authorization`,
		`SAMLResponse=raw-saml-response`,
		`code_verifier=raw-code-verifier`,
		`session=raw-session`,
		`session_id: "raw-session-id"`,
		`session-id='raw-hyphenated-session-id'`,
		`AWS_SECRET_ACCESS_KEY=raw-aws-secret`,
		`AWS_ACCESS_KEY_ID=raw-aws-key-id`,
		`prefix AWS-SECRET-ACCESS-KEY : "raw-hyphenated-aws-secret"`,
	}

	for _, input := range tests {
		output := redactor.Text(input)
		if strings.Contains(output, "raw-") {
			t.Errorf("output contains sensitive value: %s", output)
		}
		if !strings.Contains(output, Replacement) {
			t.Errorf("output does not contain redaction marker: %s", output)
		}
	}
}

func TestTextRedactsCommaBearingPasswordAndPreservesNextField(t *testing.T) {
	t.Parallel()
	input := "password=first,second, request_id=req-123"

	output := New().Text(input)

	for _, forbidden := range []string{"first", "second"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains password fragment %q: %s", forbidden, output)
		}
	}
	expected := "password=" + Replacement + ", request_id=req-123"
	if output != expected {
		t.Fatalf("unexpected redacted assignment: got=%q want=%q", output, expected)
	}
}

func TestTextFailsClosedForUnterminatedQuotedSensitiveAssignment(t *testing.T) {
	t.Parallel()
	output := New().Text(`password="first second`)

	for _, fragment := range []string{"first", "second"} {
		if strings.Contains(output, fragment) {
			t.Fatalf("unterminated quoted password leaked %q: %s", fragment, output)
		}
	}
	if !strings.Contains(output, Replacement) {
		t.Fatalf("unterminated quoted password was not redacted: %s", output)
	}

	separated := New().Text(`password="complete-secret" request_id=req-123`)
	if strings.Contains(separated, "complete-secret") {
		t.Fatalf("complete quoted password leaked: %s", separated)
	}
	if !strings.Contains(separated, "request_id=req-123") {
		t.Fatalf("complete neighboring field was not preserved: %s", separated)
	}
}

func TestTextFailsClosedForFieldLikePasswordTail(t *testing.T) {
	t.Parallel()
	input := "password=first,request_id=credential-tail"

	output := New().Text(input)

	for _, forbidden := range []string{"first", "request_id", "credential-tail"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains password fragment %q: %s", forbidden, output)
		}
	}
	if output != "password="+Replacement {
		t.Fatalf("unexpected redacted assignment: %q", output)
	}
}

func TestTextRedactsEncodedSensitiveQueryParameterNames(t *testing.T) {
	t.Parallel()
	output := New().Text(
		`before https://example.test/resource?%61ccess_token=raw-access-token&k%65y=raw-firebase-key&request_id=req-1 after`,
	)
	for _, forbidden := range []string{"raw-access-token", "raw-firebase-key"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("encoded query key survived text redaction: %s", output)
		}
	}
	for _, expected := range []string{
		`?%61ccess_token=` + Replacement,
		`&k%65y=` + Replacement,
		`&request_id=req-1 after`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("encoded key or surrounding text changed: %s", output)
		}
	}
}

func TestTextFailsClosedForMalformedEncodedQueryKey(t *testing.T) {
	t.Parallel()
	output := New().Text(
		`before https://example.test/resource?%zz=raw-malformed&request_id=req-1 after`,
	)
	if strings.Contains(output, "raw-malformed") {
		t.Fatalf("malformed query key disclosed its value: %s", output)
	}
	if !strings.Contains(
		output,
		`before https://example.test/resource?%zz=`+Replacement+
			`&request_id=req-1 after`,
	) {
		t.Fatalf("malformed key or surrounding text changed: %s", output)
	}
}

func TestIsSensitiveKeyRejectsDecoratedCredentialNames(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		"prefix_AWS_ACCESS_KEY_ID_suffix",
		"customer_birth_date",
		"dateOfBirth",
		"dob",
		"oauth_code_verifier_value",
		"raw_saml_response_payload",
	} {
		if !IsSensitiveKey(key) {
			t.Errorf("decorated sensitive key was not classified: %s", key)
		}
	}
}

func TestJSONLineRedactsSensitiveFieldsRecursively(t *testing.T) {
	t.Parallel()
	redactor := New()
	input := `2026-09-15T06:00:00Z {"request_id":"req-123","user":{"email":"user@example.com"},"refreshToken":"abc123","password":"two words"}`

	output := redactor.JSONLine(input)

	if !strings.Contains(output, `"request_id":"req-123"`) {
		t.Fatalf("safe correlation field was removed: %s", output)
	}
	for _, forbidden := range []string{"user@example.com", "abc123", "two words"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains sensitive value %q: %s", forbidden, output)
		}
	}
}

func TestJSONLineRedactsPrefixedAPIKeyFields(t *testing.T) {
	t.Parallel()
	input := `{
		"DYNACONF_AUTH__QODO_PLATFORM__API_KEY":"opaque-platform-credential",
		"auth.qodo_platform.api_key":"opaque-config-credential",
		"request_id":"req-123"
	}`

	output := New().JSONLine(input)

	for _, forbidden := range []string{
		"opaque-platform-credential",
		"opaque-config-credential",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains API key %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, `"request_id":"req-123"`) {
		t.Fatalf("safe correlation field was removed: %s", output)
	}
}

func TestJSONLineRedactsEncodedQueryNamesInOrdinaryMessage(t *testing.T) {
	t.Parallel()
	input := `{"message":"before https://example.test/path?%61ccess_token=raw-access&k%65y=raw-key&request_id=req-2 after","component":"worker"}`

	output := New().JSONLine(input)

	for _, forbidden := range []string{"raw-access", "raw-key"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("ordinary JSON field disclosed %q: %s", forbidden, output)
		}
	}
	for _, expected := range []string{
		`%61ccess_token=` + Replacement,
		`k%65y=` + Replacement,
		`request_id=req-2 after`,
		`"component":"worker"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("ordinary JSON field lost safe text %q: %s", expected, output)
		}
	}
}

func TestJSONLineSanitizesSemanticURLFields(t *testing.T) {
	t.Parallel()
	input := `{
		"url":"https://url-user:url-pass@example.com/path?token=url-token&request_id=req-1",
		"request_url":"https://request-user:request-pass@example.com/path?code=request-code",
		"nested":{"uri":"https://uri-user:uri-pass@example.com/path?state=uri-state"},
		"redirect_location":"https://location-user:location-pass@example.com/path?password=location-password",
		"http-referer":"https://referer-user:referer-pass@example.com/path?api_key=referer-key",
		"firebase_url":"https://firebase.example/resource?key=raw-firebase-key&request_id=req-2"
	}`

	output := New().JSONLine(input)

	for _, forbidden := range []string{
		"url-user", "url-pass", "url-token",
		"request-user", "request-pass", "request-code",
		"uri-user", "uri-pass", "uri-state",
		"location-user", "location-pass", "location-password",
		"referer-user", "referer-pass", "referer-key",
		"raw-firebase-key",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains URL-sensitive value %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "request_id=req-1") {
		t.Fatalf("safe URL query value was removed: %s", output)
	}
	if !strings.Contains(output, "request_id=req-2") {
		t.Fatalf("safe Firebase URL query value was removed: %s", output)
	}
}

func TestJSONLineRedactsURLUserinfoInOrdinaryStringFields(t *testing.T) {
	t.Parallel()
	input := `{"curl":"https://user:plain@localhost/path","message":"https://other:visible@localhost/path","location_id":"rack-1"}`

	output := New().JSONLine(input)

	for _, forbidden := range []string{
		"user:plain",
		"other:visible",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("URL userinfo survived in ordinary field: %s", output)
		}
	}
	if !strings.Contains(output, `"location_id":"rack-1"`) {
		t.Fatalf("safe ordinary string was changed: %s", output)
	}
}

func TestTextRedactsURLUserinfoInCommandErrorsAndLogs(t *testing.T) {
	t.Parallel()
	output := New().Text(
		`kubectl: failed https://admin:stderr-secret@api.example/path; ` +
			`log=http://user:log-secret@service.local/status`,
	)
	for _, forbidden := range []string{
		"admin:stderr-secret",
		"user:log-secret",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("URL userinfo survived text redaction: %s", output)
		}
	}
}

func TestURLRedactsCredentialsCodeAndState(t *testing.T) {
	t.Parallel()
	redactor := New()
	input := "https://user:pass@example.com/callback?code=abc&state=xyz&request_id=req-123#token"

	output := redactor.URL(input)

	for _, forbidden := range []string{"pass", "abc", "xyz", "#token"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains sensitive value %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "request_id=req-123") {
		t.Fatalf("safe query parameter was removed: %s", output)
	}
}

func TestURLRedactsCodeVerifier(t *testing.T) {
	t.Parallel()
	output := New().URL(
		"https://example.com/authorize?code_verifier=raw-verifier&request_id=req-123",
	)

	if strings.Contains(output, "raw-verifier") {
		t.Fatalf("output contains OAuth verifier: %s", output)
	}
	if !strings.Contains(output, "request_id=req-123") {
		t.Fatalf("safe query parameter was removed: %s", output)
	}
}

func TestURLRedactsEncodedSensitiveQueryNames(t *testing.T) {
	t.Parallel()
	output := New().URL(
		"https://example.com/resource?%61ccess_token=raw-access&k%65y=raw-key&request_id=req-123",
	)

	for _, forbidden := range []string{"raw-access", "raw-key"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("parsed URL contains sensitive value %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "request_id=req-123") {
		t.Fatalf("safe parsed URL query parameter was removed: %s", output)
	}
}

func TestURLMalformedEscapesStillRedactUserinfo(t *testing.T) {
	t.Parallel()
	tests := []string{
		"https://user:password@example.com/path/%zz?request_id=req-123#secret",
		"https://user:p@ssword@example.com/%gh?code_verifier=raw-verifier",
		"https://example.com/%gh?session=raw-session&request_id=req-123",
		"https://example.com/%gh?%zz=raw-malformed&request_id=req-123",
	}

	for _, input := range tests {
		output := New().URL(input)
		for _, forbidden := range []string{
			"user:", "password", "p@ssword", "raw-verifier", "raw-session",
			"raw-malformed", "#secret",
		} {
			if strings.Contains(output, forbidden) {
				t.Errorf("output contains sensitive value %q: %s", forbidden, output)
			}
		}
		if !strings.Contains(output, "example.com") {
			t.Errorf("safe host was removed: %s", output)
		}
	}
}

func TestHeaderRecordsSensitiveHeaderWithoutValue(t *testing.T) {
	t.Parallel()
	redactor := New()

	if output := redactor.Header("X-CSRF-Token", "sensitive"); output != Replacement {
		t.Fatalf("unexpected sensitive header output: %s", output)
	}
	if output := redactor.Header("Content-Type", "application/json"); output != "application/json" {
		t.Fatalf("unexpected safe header output: %s", output)
	}
}

func TestValueRedactsPersonalDataInDynamicObjectKeys(t *testing.T) {
	t.Parallel()
	redactor := New()

	output := redactor.Value("", map[string]any{
		"user@example.com": "failed",
	}).(map[string]any)

	if _, leaked := output["user@example.com"]; leaked {
		t.Fatalf("dynamic object key was not redacted: %+v", output)
	}
	if output[Replacement] != "failed" {
		t.Fatalf("unexpected redacted object: %+v", output)
	}
}

func TestJSONValueSkipperTable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		lines        []string
		wantPending  bool
		reuse        []string
		reusePending bool
	}{
		{
			name:        "string primitive",
			lines:       []string{`  "super-secret"`},
			wantPending: false,
		},
		{
			name:        "escaped string",
			lines:       []string{`"say \"hi\"\n\u0021"`},
			wantPending: false,
		},
		{
			name:        "number primitive",
			lines:       []string{"  -12.50e+3"},
			wantPending: false,
		},
		{
			name:        "true primitive",
			lines:       []string{"true"},
			wantPending: false,
		},
		{
			name:        "false primitive",
			lines:       []string{"false"},
			wantPending: false,
		},
		{
			name:        "null primitive",
			lines:       []string{"null"},
			wantPending: false,
		},
		{
			name:        "object trailing comma",
			lines:       []string{`{"a":1,}`},
			wantPending: true,
		},
		{
			name:        "array trailing comma",
			lines:       []string{`[1,]`},
			wantPending: true,
		},
		{
			name:        "unterminated string then later quote",
			lines:       []string{`"unterminated-secret`, `"closes-on-next-line"`, `"later-secret"`},
			wantPending: true,
		},
		{
			name:        "trailing backslash at EOL",
			lines:       []string{`"abc\`, `"later-secret"`},
			wantPending: true,
		},
		{
			name:        "incomplete unicode at EOL",
			lines:       []string{`"\u12`, `"later-secret"`},
			wantPending: true,
		},
		{
			name: "nested mixed containers",
			lines: []string{
				`{`,
				`  "a": [true, {"b": null, "c": [1, 2]}]`,
				`}`,
			},
			wantPending: false,
		},
		{
			name:        "truncated string",
			lines:       []string{`"unterminated-secret`},
			wantPending: true,
		},
		{
			name: "truncated object",
			lines: []string{
				`{`,
				`  "nested": "secret-value"`,
			},
			wantPending: true,
		},
		{
			name:        "malformed leading token",
			lines:       []string{"x-not-json"},
			wantPending: true,
		},
		{
			name:        "malformed leading terminator",
			lines:       []string{"]"},
			wantPending: true,
		},
		{
			name:        "mismatched object closer",
			lines:       []string{"{]", `"later":"secret"`},
			wantPending: true,
		},
		{
			name:        "mismatched array closer",
			lines:       []string{"[}"},
			wantPending: true,
		},
		{
			name:        "valid completion after whitespace",
			lines:       []string{"   ", `"ok"`},
			wantPending: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var skipper JSONValueSkipper
			skipper.Start()
			if !skipper.Pending() {
				t.Fatal("skipper was not pending after Start")
			}
			for _, line := range test.lines {
				skipper.Consume(line)
			}
			if skipper.Pending() != test.wantPending {
				t.Fatalf("pending=%v want=%v after %q", skipper.Pending(), test.wantPending, test.lines)
			}
			if test.reuse == nil {
				return
			}
			skipper.Start()
			for _, line := range test.reuse {
				skipper.Consume(line)
			}
			if skipper.Pending() != test.reusePending {
				t.Fatalf("reuse pending=%v want=%v", skipper.Pending(), test.reusePending)
			}
		})
	}
}

func TestJSONValueSkipperMaxArrayDepth(t *testing.T) {
	t.Parallel()
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + strings.Repeat("]", depth)
	}

	var complete JSONValueSkipper
	complete.Start()
	complete.Consume(nested(64))
	if complete.Pending() {
		t.Fatal("exactly 64 nested arrays did not complete")
	}

	var overflow JSONValueSkipper
	overflow.Start()
	overflow.Consume(nested(65))
	if !overflow.Pending() {
		t.Fatal("65 nested arrays completed instead of failing closed")
	}
	overflow.Consume(`"later-secret"`)
	if !overflow.Pending() {
		t.Fatal("overflow skipper resumed after a later quoted line")
	}
}

func TestSensitiveJSONAssignmentDetectsUnicodeKey(t *testing.T) {
	t.Parallel()
	assignment, ok := SensitiveJSONAssignment(`  "pass\u0077ord":`)
	if !ok {
		t.Fatal("escaped password key was not detected")
	}
	if assignment.Key != "password" {
		t.Fatalf("decoded key=%q", assignment.Key)
	}
	if assignment.ValueOffset != len(`  "pass\u0077ord":`) {
		t.Fatalf("value offset=%d", assignment.ValueOffset)
	}

	opening, ok := SensitiveJSONAssignment(`  "password": {`)
	if !ok || opening.ValueOffset >= len(`  "password": {`) {
		t.Fatalf("same-line object opener was not detected: ok=%v offset=%d", ok, opening.ValueOffset)
	}
	if `  "password": {`[opening.ValueOffset] != '{' {
		t.Fatalf("value fragment does not start at opener: %q", `  "password": {`[opening.ValueOffset:])
	}

	first, ok := SensitiveJSONAssignment(`{"password":{"note":"child-secret"},"token":"t"}`)
	if !ok || first.Invalid {
		t.Fatal("compact password object was not detected")
	}
	if first.Key != "password" {
		t.Fatalf("first sensitive key=%q", first.Key)
	}
	line := `{"password":{"note":"child-secret"},"token":"t"}`
	if first.ValueOffset >= len(line) || line[first.ValueOffset] != '{' {
		t.Fatalf("first assignment did not start at password value: offset=%d", first.ValueOffset)
	}
}

func TestJSONValueSkipperPrimitivePreservesDelimiterSuffix(t *testing.T) {
	t.Parallel()
	for _, fragment := range []string{
		`1, "request_id":"req-123"`,
		`true, "request_id":"req-123"`,
		`false, "request_id":"req-123"`,
		`null, "request_id":"req-123"`,
	} {
		fragment := fragment
		t.Run(fragment, func(t *testing.T) {
			t.Parallel()
			var skipper JSONValueSkipper
			skipper.Start()
			consumed := skipper.Consume(fragment)
			if skipper.Pending() {
				t.Fatalf("primitive did not complete: %q", fragment)
			}
			suffix := fragment[consumed:]
			if !strings.HasPrefix(strings.TrimLeft(suffix, " \t"), ",") {
				t.Fatalf("delimiter was not preserved in suffix: consumed=%d suffix=%q", consumed, suffix)
			}
			if !strings.Contains(suffix, "request_id") || !strings.Contains(suffix, "req-123") {
				t.Fatalf("safe sibling missing from suffix: %q", suffix)
			}
		})
	}
}

func TestJSONValueSkipperMalformedContinuationStaysPending(t *testing.T) {
	t.Parallel()
	tests := []string{
		`"first",}`,
		`"first",]`,
		`"first",{`,
		`"first",[`,
		`"first","value"`,
		`"first" garbage`,
		`"first", garbage`,
	}
	for _, line := range tests {
		line := line
		t.Run(line, func(t *testing.T) {
			t.Parallel()
			var skipper JSONValueSkipper
			skipper.Start()
			skipper.Consume(line)
			if !skipper.Pending() {
				t.Fatalf("malformed continuation completed: %q", line)
			}
			skipper.Consume(`"later-secret"`)
			if !skipper.Pending() {
				t.Fatalf("later canary was not suppressed after %q", line)
			}
		})
	}
}

func TestSensitiveJSONAssignmentRejectsOverlongAndMalformedKeys(t *testing.T) {
	t.Parallel()
	overlong := `"` + strings.Repeat("a", maxJSONKeyBytes+8) + `": "secret-value"`
	assignment, ok := SensitiveJSONAssignment(overlong)
	if !ok || !assignment.Invalid {
		t.Fatalf("overlong key should be fail-closed: ok=%v invalid=%v", ok, assignment.Invalid)
	}

	malformed := `"pass\zword": "secret-value"`
	assignment, ok = SensitiveJSONAssignment(malformed)
	if !ok || !assignment.Invalid {
		t.Fatalf("malformed escaped key should be fail-closed: ok=%v invalid=%v", ok, assignment.Invalid)
	}

	valueOnly := `{"request_id":"not-a-key"}`
	assignment, ok = SensitiveJSONAssignment(valueOnly)
	if ok {
		t.Fatalf("value string was classified as a key: %+v", assignment)
	}
}

func TestJSONValueSkipperGarbageAfterValueStaysPending(t *testing.T) {
	t.Parallel()
	var skipper JSONValueSkipper
	skipper.Start()
	consumed := skipper.Consume(`"first" garbage`)
	if !skipper.Pending() {
		t.Fatal("garbage after a complete string resumed the skipper")
	}
	if consumed != len(`"first" garbage`) {
		t.Fatalf("consumed=%d", consumed)
	}
	skipper.Consume(`"later-secret"`)
	if !skipper.Pending() {
		t.Fatal("later secret line was not fail-closed after garbage")
	}
}

func TestJSONValueSkipperReturnsSuffixAfterContainerClose(t *testing.T) {
	t.Parallel()
	var skipper JSONValueSkipper
	skipper.Start()
	if skipper.Consume(`{`) != 1 || !skipper.Pending() {
		t.Fatal("object opener should stay pending")
	}
	line := `  }, "request_id": "req-123"`
	consumed := skipper.Consume(line)
	if skipper.Pending() {
		t.Fatal("closed object did not complete")
	}
	suffix := line[consumed:]
	if !strings.Contains(suffix, "request_id") || !strings.Contains(suffix, "req-123") {
		t.Fatalf("safe suffix was not returned: consumed=%d suffix=%q", consumed, suffix)
	}
}

func TestJSONValueSkipperResetBetweenValues(t *testing.T) {
	t.Parallel()
	var skipper JSONValueSkipper
	skipper.Start()
	skipper.Consume(`"first"`)
	if skipper.Pending() {
		t.Fatal("first value did not complete")
	}
	skipper.Start()
	skipper.Consume(`{"ok":true}`)
	if skipper.Pending() {
		t.Fatal("reused skipper did not complete a valid object")
	}
	skipper.Start()
	skipper.Consume("{")
	if !skipper.Pending() {
		t.Fatal("truncated object after reset completed early")
	}
}
