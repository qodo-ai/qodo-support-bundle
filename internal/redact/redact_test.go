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
