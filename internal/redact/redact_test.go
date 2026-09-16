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

func TestJSONLineSanitizesSemanticURLFields(t *testing.T) {
	t.Parallel()
	input := `{
		"url":"https://url-user:url-pass@example.com/path?token=url-token&request_id=req-1",
		"request_url":"https://request-user:request-pass@example.com/path?code=request-code",
		"nested":{"uri":"https://uri-user:uri-pass@example.com/path?state=uri-state"},
		"redirect_location":"https://location-user:location-pass@example.com/path?password=location-password",
		"http-referer":"https://referer-user:referer-pass@example.com/path?api_key=referer-key"
	}`

	output := New().JSONLine(input)

	for _, forbidden := range []string{
		"url-user", "url-pass", "url-token",
		"request-user", "request-pass", "request-code",
		"uri-user", "uri-pass", "uri-state",
		"location-user", "location-pass", "location-password",
		"referer-user", "referer-pass", "referer-key",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("output contains URL-sensitive value %q: %s", forbidden, output)
		}
	}
	if !strings.Contains(output, "request_id=req-1") {
		t.Fatalf("safe URL query value was removed: %s", output)
	}
}

func TestJSONLineDoesNotTreatOrdinaryStringKeysAsURLs(t *testing.T) {
	t.Parallel()
	input := `{"curl":"https://user:plain@localhost/path","message":"https://other:visible@localhost/path","location_id":"rack-1"}`

	output := New().JSONLine(input)

	for _, expected := range []string{
		`"curl":"https://user:plain@localhost/path"`,
		`"message":"https://other:visible@localhost/path"`,
		`"location_id":"rack-1"`,
	} {
		if !strings.Contains(output, expected) {
			t.Fatalf("ordinary string was treated as a URL field: %s", output)
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

func TestURLMalformedEscapesStillRedactUserinfo(t *testing.T) {
	t.Parallel()
	tests := []string{
		"https://user:password@example.com/path/%zz?request_id=req-123#secret",
		"https://user:p@ssword@example.com/%gh?code_verifier=raw-verifier",
		"https://example.com/%gh?session=raw-session&request_id=req-123",
	}

	for _, input := range tests {
		output := New().URL(input)
		for _, forbidden := range []string{
			"user:", "password", "p@ssword", "raw-verifier", "raw-session", "#secret",
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
