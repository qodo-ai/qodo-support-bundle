package distribution

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
				"x-goog-if-generation-match:0",
				"max-age=31536000, immutable",
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
			command := exec.Command("sh", "-n", filepath.Join(root, script))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("%s is not valid POSIX shell: %v\n%s", script, err, output)
			}
		})
	}
}

func TestGCSWorkflowsUseOIDCAndSeparateDevFromProduction(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	release := readText(t, filepath.Join(
		root,
		".github/workflows/release-support-bundle.yaml",
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
	} {
		if !strings.Contains(release, required) {
			t.Fatalf("release workflow does not contain %q", required)
		}
	}
	for _, required := range []string{
		"environment: production",
		"qodo-cli-public-dev",
		"qodo-cli-public",
		"google-github-actions/auth@",
		"./scripts/promote-gcs.sh",
	} {
		if !strings.Contains(promotion, required) {
			t.Fatalf("promotion workflow does not contain %q", required)
		}
	}
	if strings.Contains(release, "qodo-cli-public\n") {
		t.Fatal("release workflow can write the production bucket directly")
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
