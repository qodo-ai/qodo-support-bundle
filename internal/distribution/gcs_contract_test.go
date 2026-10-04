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
				"gcs-exact-object.sh",
				"gcs_upload_immutable",
				"gcloud auth print-access-token",
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

	helper := readText(t, filepath.Join(root, "scripts/gcs-exact-object.sh"))
	for _, required := range []string{
		"https://storage.googleapis.com/${bucket}/${object}",
		"--request PUT",
		"--request GET",
		"x-goog-if-generation-match: 0",
		"Cache-Control: public, max-age=31536000, immutable",
		"refusing to overwrite",
	} {
		if !strings.Contains(helper, required) {
			t.Fatalf("exact-object helper does not contain %q", required)
		}
	}
	for _, forbidden := range []string{"gcloud storage", "--request DELETE"} {
		if strings.Contains(helper, forbidden) {
			t.Fatalf("exact-object helper contains forbidden operation %q", forbidden)
		}
	}
}

func TestPublishUsesExactObjectRequestsWithoutListing(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "release")

	runDistributionScript(t, filepath.Join(root, "scripts/publish-gcs.sh"), bin, []string{
		"FAKE_GCS_ROOT=" + fakeGCS,
		"FAKE_REQUESTS=" + requests,
		"QODO_SUPPORT_BUNDLE_DIST=" + dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	})
	runDistributionScript(t, filepath.Join(root, "scripts/publish-gcs.sh"), bin, []string{
		"FAKE_GCS_ROOT=" + fakeGCS,
		"FAKE_REQUESTS=" + requests,
		"QODO_SUPPORT_BUNDLE_DIST=" + dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	})

	assertExactObjectRequests(t, requests, "qodo-cli-public-dev")
	assertPublishedRelease(t, fakeGCS, "qodo-cli-public-dev", dist, "1.2.3")
}

func TestPromotionUsesExactObjectRequestsWithoutListing(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	release := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, release, "release")
	copyReleaseFixture(t, release, filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"releases",
		"1.2.3",
	))

	runDistributionScript(t, filepath.Join(root, "scripts/promote-gcs.sh"), bin, []string{
		"FAKE_GCS_ROOT=" + fakeGCS,
		"FAKE_REQUESTS=" + requests,
		"QODO_SUPPORT_BUNDLE_RELEASE_DIR=" + release,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	})
	runDistributionScript(t, filepath.Join(root, "scripts/promote-gcs.sh"), bin, []string{
		"FAKE_GCS_ROOT=" + fakeGCS,
		"FAKE_REQUESTS=" + requests,
		"QODO_SUPPORT_BUNDLE_RELEASE_DIR=" + release,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	})

	assertExactObjectRequests(t, requests, "qodo-cli-public")
	assertPublishedRelease(t, fakeGCS, "qodo-cli-public", release, "1.2.3")
}

func TestExactObjectPublishingRefusesDifferentExistingBytes(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "release")
	object := filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"releases",
		"1.2.3",
		releaseBinaries[0],
	)
	if err := os.MkdirAll(filepath.Dir(object), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(object, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GCS_ROOT="+fakeGCS,
		"FAKE_REQUESTS="+requests,
		"QODO_SUPPORT_BUNDLE_DIST="+dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()

	if err == nil {
		t.Fatal("publish overwrote or accepted different existing bytes")
	}
	if !strings.Contains(string(output), "refusing to overwrite") {
		t.Fatalf("unexpected publish failure:\n%s", output)
	}
	data, readErr := os.ReadFile(object)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "different" {
		t.Fatalf("existing object was changed: %q", data)
	}
}

func TestPublishRejectsIncompleteDuplicateAndUnexpectedChecksumEntries(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	tests := []struct {
		name          string
		errorContains string
		mutate        func([]string) []string
	}{
		{
			name:          "omitted binary",
			errorContains: "checksum manifest inventory",
			mutate: func(lines []string) []string {
				return lines[1:]
			},
		},
		{
			name:          "duplicate binary",
			errorContains: "checksum manifest inventory",
			mutate: func(lines []string) []string {
				return append(lines, lines[0])
			},
		},
		{
			name:          "unexpected binary",
			errorContains: "checksum manifest inventory",
			mutate: func(lines []string) []string {
				return append(lines, fmt.Sprintf("%064x  unexpected", 1))
			},
		},
		{
			name:          "malformed trailing line",
			errorContains: "checksum manifest is malformed",
			mutate: func(lines []string) []string {
				return append(lines, "malformed")
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
			if !strings.Contains(string(output), test.errorContains) {
				t.Fatalf("unexpected error for %s:\n%s", test.name, output)
			}
		})
	}
}

func TestPromotionRejectsSelfConsistentCanaryThatDiffersFromAuthenticatedRelease(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	release := t.TempDir()
	canary := t.TempDir()
	bin := t.TempDir()
	uploads := filepath.Join(t.TempDir(), "uploads.log")
	writeReleaseFixture(t, release, "release")
	writeReleaseFixture(t, canary, "different-canary")

	gcloud := `#!/bin/sh
set -eu
previous=
last=
for argument in "$@"; do
  previous=$last
  last=$argument
done
case "$previous" in
  gs://qodo-cli-public-dev/*)
    cp "$FAKE_CANARY/$(basename "$previous")" "$last"
    ;;
  *)
    printf '%s\n' "$*" >> "$FAKE_UPLOADS"
    ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "gcloud"), []byte(gcloud), 0o700); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts/promote-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_CANARY="+canary,
		"FAKE_UPLOADS="+uploads,
		"QODO_SUPPORT_BUNDLE_RELEASE_DIR="+release,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()

	if err == nil {
		t.Fatalf("promotion accepted a canary that differs from the authenticated release")
	}
	if !strings.Contains(string(output), "authenticated release") {
		t.Fatalf("unexpected promotion error:\n%s", output)
	}
	if data, readErr := os.ReadFile(uploads); readErr == nil && len(data) != 0 {
		t.Fatalf("promotion uploaded before provenance verification:\n%s", data)
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
		`gh release view "$candidate"`,
		`gh api "repos/$GITHUB_REPOSITORY/commits/$release_tag" --jq .sha`,
		`for asset in dist/*`,
		`gh attestation verify "$asset"`,
		`--source-digest "$RELEASE_SHA"`,
		`--source-ref "refs/tags/$RELEASE_TAG"`,
		`--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-support-bundle.yaml"`,
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
		"attestations: read",
		"gh release download",
		"gh attestation verify",
		"QODO_SUPPORT_BUNDLE_RELEASE_DIR",
		`gh release view "$candidate"`,
		`gh api "repos/$GITHUB_REPOSITORY/commits/$release_tag" --jq .sha`,
		`for asset in release/*`,
		`gh attestation verify "$asset"`,
		`--source-digest "$RELEASE_SHA"`,
		`--source-ref "refs/tags/$RELEASE_TAG"`,
		`--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-support-bundle.yaml"`,
	} {
		if !strings.Contains(promotion, required) {
			t.Fatalf("promotion workflow does not contain %q", required)
		}
	}
	if strings.Contains(publication, "qodo-cli-public\n") {
		t.Fatal("publication workflow can write the production bucket directly")
	}
}

func writeReleaseFixture(t *testing.T, directory, contentPrefix string) {
	t.Helper()
	lines := make([]string, 0, len(releaseBinaries))
	for _, filename := range releaseBinaries {
		data := []byte(contentPrefix + ":" + filename)
		if err := os.WriteFile(filepath.Join(directory, filename), data, 0o600); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, fmt.Sprintf("%x  %s", sha256.Sum256(data), filename))
	}
	if err := os.WriteFile(
		filepath.Join(directory, "checksums.sha256"),
		[]byte(strings.Join(lines, "\n")+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
}

func copyReleaseFixture(t *testing.T, source, destination string) {
	t.Helper()
	if err := os.MkdirAll(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, filename := range append([]string{"checksums.sha256"}, releaseBinaries...) {
		data, err := os.ReadFile(filepath.Join(source, filename))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, filename), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func installFakeGCSCommands(t *testing.T) string {
	t.Helper()
	bin := t.TempDir()
	gcloud := `#!/bin/sh
set -eu
if [ "$1 $2" = "auth print-access-token" ]; then
  printf '%s\n' fake-access-token
  exit 0
fi
if [ "$1 $2" = "storage cp" ]; then
  source=$3
  destination=$4
  case "$source" in
    gs://qodo-cli-public-dev/*)
      relative=${source#gs://}
      cp "$FAKE_GCS_ROOT/$relative" "$destination"
      exit 0
      ;;
  esac
fi
echo "fake gcloud: forbidden command: $*" >&2
exit 90
`
	curl := `#!/bin/sh
set -eu
method=
upload=
output=
content_type=
cache_control=
generation=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --request) method=$2; shift 2 ;;
    --upload-file) upload=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --header)
      case "$2" in
        "Content-Type: "*) content_type=${2#Content-Type: } ;;
        "Cache-Control: "*) cache_control=${2#Cache-Control: } ;;
        "x-goog-if-generation-match: "*) generation=${2#x-goog-if-generation-match: } ;;
      esac
      shift 2
      ;;
    --fail|--fail-with-body|--silent|--show-error) shift ;;
    http*) url=$1; shift ;;
    *) echo "fake curl: unsupported argument: $1" >&2; exit 91 ;;
  esac
done
relative=${url#https://storage.googleapis.com/}
path=$FAKE_GCS_ROOT/$relative
printf '%s|%s|%s|%s|%s\n' \
  "$method" "$url" "$content_type" "$cache_control" "$generation" >> "$FAKE_REQUESTS"
case "$method" in
  PUT)
    [ "$generation" = 0 ] || exit 92
    [ ! -e "$path" ] || exit 22
    mkdir -p "$(dirname "$path")"
    cp "$upload" "$path"
    ;;
  GET)
    [ -f "$path" ] || exit 22
    cp "$path" "$output"
    ;;
  *) exit 93 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "gcloud"), []byte(gcloud), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin
}

func runDistributionScript(t *testing.T, script, bin string, environment []string) {
	t.Helper()
	command := exec.Command(script)
	command.Env = append(
		append(
			os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		),
		environment...,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s failed: %v\n%s", filepath.Base(script), err, output)
	}
}

func assertExactObjectRequests(t *testing.T, requests, bucket string) {
	t.Helper()
	data, err := os.ReadFile(requests)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 18 {
		t.Fatalf("expected 12 create attempts and 6 exact reads, got %d:\n%s", len(lines), data)
	}
	base := "https://storage.googleapis.com/" + bucket + "/support-bundle/releases/1.2.3/"
	for index, filename := range append(releaseBinaries, "checksums.sha256") {
		fields := strings.Split(lines[index], "|")
		if len(fields) != 5 {
			t.Fatalf("malformed request log line: %q", lines[index])
		}
		contentType := "application/octet-stream"
		if filename == "checksums.sha256" {
			contentType = "text/plain"
		}
		expected := []string{
			"PUT",
			base + filename,
			contentType,
			"public, max-age=31536000, immutable",
			"0",
		}
		if strings.Join(fields, "|") != strings.Join(expected, "|") {
			t.Fatalf("unexpected create request:\nwant %q\ngot  %q", expected, fields)
		}
	}
	if !strings.Contains(lines[5], "/checksums.sha256|") {
		t.Fatalf("checksum was not the final completion-marker upload: %q", lines[5])
	}
	for index, filename := range append(releaseBinaries, "checksums.sha256") {
		put := strings.Split(lines[6+index*2], "|")
		get := strings.Split(lines[7+index*2], "|")
		if len(put) != 5 || len(get) != 5 {
			t.Fatalf("malformed idempotence request pair:\n%s\n%s", lines[6+index*2], lines[7+index*2])
		}
		expectedURL := base + filename
		if put[0] != "PUT" || put[1] != expectedURL ||
			get[0] != "GET" || get[1] != expectedURL {
			t.Fatalf("idempotence did not compare the exact object:\n%s\n%s", lines[6+index*2], lines[7+index*2])
		}
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "DELETE|") || strings.Contains(line, "storage.objects.list") {
			t.Fatalf("broad or destructive request logged: %q", line)
		}
	}
}

func assertPublishedRelease(
	t *testing.T,
	fakeGCS, bucket, source, version string,
) {
	t.Helper()
	for _, filename := range append([]string{"checksums.sha256"}, releaseBinaries...) {
		expected, err := os.ReadFile(filepath.Join(source, filename))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := os.ReadFile(filepath.Join(
			fakeGCS,
			bucket,
			"support-bundle",
			"releases",
			version,
			filename,
		))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("published %s differs from source", filename)
		}
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
