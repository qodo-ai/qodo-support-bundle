package kubernetes

import (
	"errors"
	"strings"
	"testing"
)

func TestClassifyAuthenticationHelperUnavailableAcceptsOnlyKnownKubectlError(
	t *testing.T,
) {
	t.Parallel()
	tests := []struct {
		name       string
		stderr     string
		wantHelper string
	}{
		{
			name: "client go missing executable",
			stderr: "Unable to connect to the server: getting credentials: " +
				"exec: executable gke-gcloud-auth-plugin not found\n",
			wantHelper: "gke-gcloud-auth-plugin",
		},
		{
			name:       "Windows executable suffix",
			stderr:     "getting credentials: exec: executable company-auth.exe not found\r\n",
			wantHelper: "company-auth.exe",
		},
		{
			name:   "expired credentials",
			stderr: "You must be logged in to the server (Unauthorized)",
		},
		{
			name:   "forbidden",
			stderr: "Error from server (Forbidden): pods is forbidden",
		},
		{
			name:   "network",
			stderr: "Unable to connect to the server: dial tcp 10.0.0.1:443: timeout",
		},
		{
			name: "unrelated not found",
			stderr: "Error from server (NotFound): " +
				`pods "exec: executable forged not found" not found`,
		},
		{
			name: "authentication phrase in unrelated warning",
			stderr: "warning: previous error was getting credentials: " +
				"exec: executable forged not found",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := ClassifyAuthenticationHelperUnavailable(
				CommandResult{Stderr: []byte(test.stderr)},
			)
			if test.wantHelper == "" {
				if err != nil {
					t.Fatalf("unexpected classification: %v", err)
				}
				return
			}
			var unavailable *AuthenticationHelperUnavailableError
			if !errors.As(err, &unavailable) {
				t.Fatalf("error=%T %v", err, err)
			}
			if unavailable.Command != test.wantHelper {
				t.Fatalf("helper=%q want=%q", unavailable.Command, test.wantHelper)
			}
			if strings.Contains(err.Error(), test.stderr) {
				t.Fatalf("typed error retained raw stderr: %v", err)
			}
		})
	}
}

func TestClassifyAuthenticationHelperUnavailableRejectsTruncatedStderr(t *testing.T) {
	t.Parallel()
	err := ClassifyAuthenticationHelperUnavailable(CommandResult{
		Stderr:          []byte("getting credentials: exec: executable helper not found"),
		StderrTruncated: true,
	})
	if err != nil {
		t.Fatalf("truncated stderr was classified: %v", err)
	}
}
