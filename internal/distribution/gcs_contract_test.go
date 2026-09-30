package distribution

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var releaseBinaries = []string{
	"qodo-support-bundle-darwin-amd64",
	"qodo-support-bundle-darwin-arm64",
	"qodo-support-bundle-linux-amd64",
	"qodo-support-bundle-linux-arm64",
	"qodo-support-bundle-windows-amd64.exe",
}

func TestGCSScriptsUseVersionedImmutableSupportBundlePrefix(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	for _, script := range []string{
		"scripts/publish-gcs.sh",
		"scripts/promote-gcs.sh",
	} {
		script := script
		t.Run(filepath.Base(script), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join(root, script))
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			for _, required := range []string{
				"QODO_SUPPORT_BUNDLE_PREFIX",
				"support-bundle",
				"releases/${VERSION}",
				"--if-generation-match=0",
				"max-age=31536000, immutable",
				"gcloud storage",
				"manifest_files=",
				"checksum manifest inventory does not match the five binaries",
				"sha256sum",
			} {
				if !strings.Contains(text, required) {
					t.Fatalf("%s does not contain %q", script, required)
				}
			}
			if strings.Contains(text, "/version.json") ||
				strings.Contains(text, " latest") {
				t.Fatalf("%s writes mutable distribution metadata", script)
			}
			binaryUpload := strings.Index(
				text,
				`printf '%s\n' "$expected_binaries" | while`,
			)
			checksumUpload := strings.LastIndex(text, "filename=checksums.sha256")
			if binaryUpload < 0 || checksumUpload < binaryUpload {
				t.Fatalf("%s does not publish checksums after all binaries", script)
			}
			command := exec.Command("sh", "-n", filepath.Join(root, script))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s is not valid POSIX shell: %v\n%s", script, err, output)
			}
		})
	}
}

func TestPublishRejectsIncompleteDuplicateAndUnexpectedChecksumEntries(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	tests := []struct {
		name   string
		mutate func([]string) []string
	}{
		{
			name: "omitted binary",
			mutate: func(lines []string) []string {
				return lines[1:]
			},
		},
		{
			name: "duplicate binary",
			mutate: func(lines []string) []string {
				return append(lines, lines[0])
			},
		},
		{
			name: "unexpected binary",
			mutate: func(lines []string) []string {
				return append(lines, fmt.Sprintf("%064x  unexpected", 1))
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			dist := t.TempDir()
			lines := make([]string, 0, len(releaseBinaries))
			for _, filename := range releaseBinaries {
				data := []byte("fixture:" + filename)
				if err := os.WriteFile(filepath.Join(dist, filename), data, 0o600); err != nil {
					t.Fatal(err)
				}
				lines = append(lines, fmt.Sprintf("%x  %s", sha256.Sum256(data), filename))
			}
			manifest := strings.Join(test.mutate(lines), "\n") + "\n"
			if err := os.WriteFile(
				filepath.Join(dist, "checksums.sha256"),
				[]byte(manifest),
				0o600,
			); err != nil {
				t.Fatal(err)
			}

			command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
			command.Env = append(
				os.Environ(),
				"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
				"QODO_SUPPORT_BUNDLE_DIST="+dist,
			)
			output, err := command.CombinedOutput()

			if err == nil {
				t.Fatalf("publish accepted %s checksum manifest", test.name)
			}
			if !strings.Contains(string(output), "checksum manifest inventory") {
				t.Fatalf("unexpected error for %s:\n%s", test.name, output)
			}
		})
	}
}

func TestGCSWorkflowsUseOIDCAndSeparateDevFromProduction(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	publication := readText(t, filepath.Join(
		root,
		".github/workflows/publish-support-bundle.yaml",
	))
	promotion := readText(t, filepath.Join(
		root,
		".github/workflows/promote-support-bundle.yaml",
	))

	for _, required := range []string{
		"id-token: write",
		"qodo-cli-public-dev",
		"google-github-actions/auth@",
		"./scripts/publish-gcs.sh",
		"qodo-support-bundle-publisher@codium-development",
		"github.ref == 'refs/heads/main'",
	} {
		if !strings.Contains(publication, required) {
			t.Fatalf("publication workflow does not contain %q", required)
		}
	}
	for _, required := range []string{
		"environment: production",
		"qodo-cli-public-dev",
		"qodo-cli-public",
		"google-github-actions/auth@",
		"./scripts/promote-gcs.sh",
		"qodo-support-bundle-publisher@codium-production",
		"github.ref == 'refs/heads/main'",
	} {
		if !strings.Contains(promotion, required) {
			t.Fatalf("promotion workflow does not contain %q", required)
		}
	}
	if strings.Contains(publication, "qodo-cli-public\n") {
		t.Fatal("publication workflow can write the production bucket directly")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
