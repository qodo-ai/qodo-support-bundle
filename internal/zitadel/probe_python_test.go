package zitadel

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEmbeddedPythonProbeHTTPBehavior(t *testing.T) {
	python := pythonWithHTTPX(t)
	directory := pythonSettingsDirectory(t)
	type response struct {
		status  int
		body    []byte
		headers map[string]string
		delay   time.Duration
	}
	var mutex sync.Mutex
	responses := map[string]response{}
	observedHeaders := make([]http.Header, 0)
	server := httptest.NewServer(http.HandlerFunc(func(
		writer http.ResponseWriter,
		request *http.Request,
	) {
		mutex.Lock()
		current := responses[request.URL.Path]
		observedHeaders = append(observedHeaders, request.Header.Clone())
		mutex.Unlock()
		if current.delay > 0 {
			time.Sleep(current.delay)
		}
		for name, value := range current.headers {
			writer.Header().Set(name, value)
		}
		writer.WriteHeader(current.status)
		_, _ = writer.Write(current.body)
	}))
	defer server.Close()
	validDiscovery := func(issuer string) []byte {
		data, _ := json.Marshal(map[string]string{
			"issuer":   issuer,
			"jwks_uri": strings.TrimRight(issuer, "/") + "/oauth/v2/keys",
		})
		return data
	}
	validJWKS := []byte(`{"keys":[{"kty":"RSA","n":"synthetic","e":"AQAB"}]}`)
	reset := func() {
		responses = map[string]response{
			"/.well-known/openid-configuration": {
				status: 200,
				body:   validDiscovery(server.URL),
			},
			"/oauth/v2/keys": {status: 200, body: validJWKS},
		}
		observedHeaders = nil
	}

	t.Run("success has no auth or cookie forwarding", func(t *testing.T) {
		reset()
		current := responses["/.well-known/openid-configuration"]
		current.headers = map[string]string{"Set-Cookie": "session=private-canary"}
		responses["/.well-known/openid-configuration"] = current
		report := runPythonProbe(t, python, directory, server.URL, 3, nil)
		if report.Checks[0].Status != StatusPassed ||
			report.Checks[1].Status != StatusPassed {
			t.Fatalf("checks=%+v", report.Checks)
		}
		mutex.Lock()
		defer mutex.Unlock()
		for _, headers := range observedHeaders {
			if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
				t.Fatalf("sensitive request headers: %+v", headers)
			}
			if headers.Get("Accept-Encoding") != "identity" {
				t.Fatalf("encoding=%q", headers.Get("Accept-Encoding"))
			}
		}
	})

	tests := []struct {
		name        string
		path        string
		replacement response
		checkIndex  int
		reason      string
	}{
		{
			name: "redirect rejected",
			path: "/.well-known/openid-configuration",
			replacement: response{
				status:  302,
				body:    []byte("private body"),
				headers: map[string]string{"Location": "/unexpected"},
			},
			reason: "redirect_rejected",
		},
		{
			name: "issuer mismatch",
			path: "/.well-known/openid-configuration",
			replacement: response{
				status: 200,
				body: []byte(
					`{"issuer":"https://wrong.example","jwks_uri":"` +
						server.URL + `/oauth/v2/keys"}`,
				),
			},
			reason: "issuer_mismatch",
		},
		{
			name: "JWKS URI mismatch",
			path: "/.well-known/openid-configuration",
			replacement: response{
				status: 200,
				body: []byte(
					`{"issuer":"` + server.URL +
						`","jwks_uri":"https://wrong.example/keys"}`,
				),
			},
			reason: "jwks_uri_mismatch",
		},
		{
			name:        "malformed JSON",
			path:        "/oauth/v2/keys",
			replacement: response{status: 200, body: []byte("{")},
			checkIndex:  1,
			reason:      "invalid_json",
		},
		{
			name:        "oversized response",
			path:        "/oauth/v2/keys",
			replacement: response{status: 200, body: []byte(strings.Repeat("x", 256*1024+1))},
			checkIndex:  1,
			reason:      "response_too_large",
		},
		{
			name: "compressed response",
			path: "/oauth/v2/keys",
			replacement: response{
				status:  200,
				body:    []byte("compressed"),
				headers: map[string]string{"Content-Encoding": "gzip"},
			},
			checkIndex: 1,
			reason:     "unsupported_encoding",
		},
		{
			name:        "invalid JWKS",
			path:        "/oauth/v2/keys",
			replacement: response{status: 200, body: []byte(`{"keys":[]}`)},
			checkIndex:  1,
			reason:      "invalid_jwks",
		},
		{
			name: "request timeout",
			path: "/oauth/v2/keys",
			replacement: response{
				status: 200,
				body:   validJWKS,
				delay:  500 * time.Millisecond,
			},
			checkIndex: 1,
			reason:     "timeout",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			reset()
			responses[test.path] = test.replacement
			probeTimeout := 3.0
			if test.reason == "timeout" {
				probeTimeout = 1.0
			}
			report := runPythonProbe(
				t,
				python,
				directory,
				server.URL,
				probeTimeout,
				nil,
			)
			if report.Checks[test.checkIndex].Reason != test.reason {
				t.Fatalf("checks=%+v", report.Checks)
			}
		})
	}
}

func TestEmbeddedPythonProbeUsesProxyAndCAEnvironment(t *testing.T) {
	python := pythonWithHTTPX(t)
	directory := pythonSettingsDirectory(t)

	t.Run("HTTP proxy", func(t *testing.T) {
		issuer := "http://zitadel.invalid"
		proxy := httptest.NewServer(http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			writer.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(
				request.RequestURI,
				"/.well-known/openid-configuration",
			):
				_, _ = fmt.Fprintf(
					writer,
					`{"issuer":%q,"jwks_uri":%q}`,
					issuer,
					issuer+"/oauth/v2/keys",
				)
			case strings.HasSuffix(request.RequestURI, "/oauth/v2/keys"):
				_, _ = writer.Write(
					[]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"key"}]}`),
				)
			default:
				http.NotFound(writer, request)
			}
		}))
		defer proxy.Close()
		report := runPythonProbe(t, python, directory, issuer, 3, map[string]string{
			"HTTP_PROXY": proxy.URL,
			"NO_PROXY":   "",
		})
		if report.FailedChecks() != 0 {
			t.Fatalf("checks=%+v", report.Checks)
		}
	})

	t.Run("TLS CA override", func(t *testing.T) {
		var issuer string
		server := httptest.NewTLSServer(http.HandlerFunc(func(
			writer http.ResponseWriter,
			request *http.Request,
		) {
			writer.Header().Set("Content-Type", "application/json")
			if request.URL.Path == "/.well-known/openid-configuration" {
				_, _ = fmt.Fprintf(
					writer,
					`{"issuer":%q,"jwks_uri":%q}`,
					issuer,
					issuer+"/oauth/v2/keys",
				)
				return
			}
			_, _ = writer.Write(
				[]byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y"}]}`),
			)
		}))
		defer server.Close()
		issuer = server.URL

		untrusted := runPythonProbe(t, python, directory, issuer, 3, nil)
		if untrusted.Checks[0].Reason != "tls_error" {
			t.Fatalf("untrusted checks=%+v", untrusted.Checks)
		}
		certificate, err := x509.ParseCertificate(server.Certificate().Raw)
		if err != nil {
			t.Fatal(err)
		}
		caPath := filepath.Join(directory, "ca.pem")
		if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		}), 0o600); err != nil {
			t.Fatal(err)
		}
		trusted := runPythonProbe(t, python, directory, issuer, 3, map[string]string{
			"SSL_CERT_FILE": caPath,
		})
		if trusted.FailedChecks() != 0 {
			t.Fatalf("trusted checks=%+v", trusted.Checks)
		}
	})
}

func pythonWithHTTPX(t *testing.T) string {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("python3 is unavailable; run make test-python-deps")
	}
	if err := exec.Command(python, "-c", "import httpx").Run(); err != nil {
		t.Fatal("Python HTTPX is unavailable; run make test-python-deps")
	}
	return python
}

func pythonSettingsDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	config := filepath.Join(directory, "common", "config")
	if err := os.MkdirAll(config, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		filepath.Join(directory, "common", "__init__.py"),
		filepath.Join(config, "__init__.py"),
	} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func runPythonProbe(
	t *testing.T,
	python string,
	directory string,
	issuer string,
	timeout float64,
	extraEnvironment map[string]string,
) Report {
	t.Helper()
	settings := fmt.Sprintf(
		"import os\n"+
			"print('private-settings-canary')\n"+
			"os.write(2, b'private-settings-canary')\n"+
			"simple_settings = %s\n",
		fmt.Sprintf(
			`{"auth.client_type": "oidc", "auth.zitadel_issuer": %q}`,
			issuer,
		),
	)
	path := filepath.Join(directory, "common", "config", "simple_settings.py")
	if err := os.WriteFile(path, []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(timeout*float64(time.Second))+3*time.Second,
	)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		python,
		"-B",
		"-c",
		Source,
		fmt.Sprintf("%.3f", timeout),
	)
	command.Dir = directory
	environment := make([]string, 0, len(os.Environ())+4)
	for _, value := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(value, "=", 2)[0])
		switch name {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
			"SSL_CERT_FILE", "SSL_CERT_DIR":
			continue
		}
		environment = append(environment, value)
	}
	noProxy := "*"
	if value, exists := extraEnvironment["NO_PROXY"]; exists {
		noProxy = value
	}
	environment = append(environment, "PYTHONPATH="+directory, "NO_PROXY="+noProxy)
	for name, value := range extraEnvironment {
		if name == "NO_PROXY" {
			continue
		}
		environment = append(environment, name+"="+value)
	}
	command.Env = environment
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("run embedded probe: %v stderr=%q", err, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("probe emitted stderr: %q", stderr.String())
	}
	output := stdout.Bytes()
	if int64(len(output)) > MaxOutputBytes {
		t.Fatalf("probe output exceeded bound: %d", len(output))
	}
	if bytes.Contains(output, []byte("private-settings-canary")) ||
		bytes.Contains(output, []byte("private body")) {
		t.Fatalf("probe leaked private data: %q", output)
	}
	var report Report
	if err := json.Unmarshal(output, &report); err != nil {
		t.Fatalf("decode report %q: %v", output, err)
	}
	return report
}
