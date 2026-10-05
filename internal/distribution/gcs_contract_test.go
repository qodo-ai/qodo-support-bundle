package distribution

import (
	"crypto/sha256"
	"debug/pe"
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
	"qodo-support-bundle-windows-arm64.exe",
}

var releaseInstallers = []string{
	"install.sh",
	"install.ps1",
}

func releaseFiles() []string {
	files := append([]string{}, releaseBinaries...)
	files = append(files, "checksums.sha256")
	files = append(files, releaseInstallers...)
	return append(files, "installer-checksums.sha256")
}

func TestWindowsARM64ReleaseCrossCompilesToNativePE(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	executable := filepath.Join(t.TempDir(), "qodo-support-bundle-windows-arm64.exe")
	command := exec.Command(
		"go",
		"build",
		"-trimpath",
		"-o",
		executable,
		"./cmd/qodo-support-bundle",
	)
	command.Dir = root
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=windows", "GOARCH=arm64")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cross-compile Windows ARM64 release: %v\n%s", err, output)
	}

	file, err := pe.Open(executable)
	if err != nil {
		t.Fatalf("open Windows ARM64 PE: %v", err)
	}
	defer file.Close()
	if file.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_ARM64 {
		t.Fatalf(
			"Windows ARM64 release machine = %#x, want %#x",
			file.FileHeader.Machine,
			pe.IMAGE_FILE_MACHINE_ARM64,
		)
	}
}

func TestVersionContractRendersStrictMetadataAndOrdersSemantically(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	script := filepath.Join(root, "scripts/version-contract.py")
	render := exec.Command("python3", script, "render", "1.2.3")
	output, err := render.CombinedOutput()
	if err != nil {
		t.Fatalf("render version metadata: %v\n%s", err, output)
	}
	if string(output) != "{\"version\": \"1.2.3\"}\n" {
		t.Fatalf("unexpected version metadata: %q", output)
	}

	current := filepath.Join(t.TempDir(), "version.json")
	if err := os.WriteFile(current, output, 0o600); err != nil {
		t.Fatal(err)
	}
	read := exec.Command("python3", script, "read", current)
	readOutput, err := read.CombinedOutput()
	if err != nil || string(readOutput) != "1.2.3\n" {
		t.Fatalf("read version metadata: %v\n%s", err, readOutput)
	}
	for _, candidate := range []string{"1.2.3", "1.2.4", "2.0.0"} {
		command := exec.Command("python3", script, "allow-update", current, candidate)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("allow update to %s: %v\n%s", candidate, err, output)
		}
	}
	command := exec.Command("python3", script, "allow-update", current, "1.2.2")
	if output, err := command.CombinedOutput(); err == nil ||
		!strings.Contains(string(output), "refusing version downgrade") {
		t.Fatalf("downgrade result = %v\n%s", err, output)
	}

	duplicate := filepath.Join(t.TempDir(), "duplicate-version.json")
	if err := os.WriteFile(
		duplicate,
		[]byte(`{"version":"1.2.3","version":"1.2.4"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, arguments := range [][]string{
		{"read", duplicate},
		{"allow-update", duplicate, "1.2.5"},
	} {
		command := exec.Command("python3", append([]string{script}, arguments...)...)
		if output, err := command.CombinedOutput(); err == nil ||
			!strings.Contains(string(output), "duplicate JSON property") {
			t.Fatalf("duplicate metadata result = %v\n%s", err, output)
		}
	}
	invalid := exec.Command("python3", script, "render", "1.2.3--")
	if output, err := invalid.CombinedOutput(); err == nil ||
		!strings.Contains(string(output), "invalid version") {
		t.Fatalf("punctuation-leading suffix result = %v\n%s", err, output)
	}
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
				"gcs_upload_mutable",
				"gcloud auth print-access-token",
				"release_installers",
				"version.json",
				"no-cache, max-age=0, must-revalidate",
			} {
				if !strings.Contains(text, required) {
					t.Fatalf("%s does not contain %q", script, required)
				}
			}
			immutableUpload := strings.LastIndex(text, "upload_immutable_release")
			stableUpload := strings.LastIndex(text, "release_installers | while")
			metadataUpload := strings.LastIndex(text, `"${PREFIX}/version.json"`)
			if immutableUpload < 0 || stableUpload < immutableUpload ||
				metadataUpload < stableUpload {
				t.Fatalf("%s does not publish immutable, stable, then metadata", script)
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
		"x-goog-if-generation-match: ${generation}",
		"--dump-header",
		"public, max-age=31536000, immutable",
		"refusing to overwrite",
	} {
		if !strings.Contains(helper, required) {
			t.Fatalf("exact-object helper does not contain %q", required)
		}
	}
	releaseContract := readText(t, filepath.Join(root, "scripts/release-contract.sh"))
	for _, required := range []string{
		"gcs_upload_immutable",
		"install.sh",
		"install.ps1",
		"checksum manifest inventory does not match the six binaries",
		"installer checksum inventory does not match both installers",
		"acquire_publication_lock",
		"release_publication_lock",
		"control/publication-lock.json",
	} {
		if !strings.Contains(releaseContract, required) {
			t.Fatalf("release contract does not contain %q", required)
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
		"FAKE_LOCK_VERIFY_FAILURE=1",
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

func TestPublishReleasesOwnedLockWhenVerificationReadsFail(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "release")

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GCS_ROOT="+fakeGCS,
		"FAKE_REQUESTS="+requests,
		"FAKE_LOCK_VERIFY_ALWAYS=1",
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=failed-verification-test",
		"QODO_SUPPORT_BUNDLE_DIST="+dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()
	if err == nil ||
		!strings.Contains(string(output), "publication lock verification failed") {
		t.Fatalf("lock verification result = %v\n%s", err, output)
	}
	lock, readErr := os.ReadFile(filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"control",
		"publication-lock.json",
	))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(lock) != "{\"owner\":\"\"}\n" {
		t.Fatalf("failed verification stranded publication lock: %s", lock)
	}
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
	seedActivatedRelease(t, fakeGCS, "qodo-cli-public-dev", release, "1.2.3")

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
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=different-bytes-test",
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

func TestPublishRejectsVersionDowngradeBeforeAnyWrite(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "candidate")
	seedActivatedRelease(t, fakeGCS, "qodo-cli-public-dev", dist, "2.0.0")

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GCS_ROOT="+fakeGCS,
		"FAKE_REQUESTS="+requests,
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=downgrade-test",
		"QODO_SUPPORT_BUNDLE_DIST="+dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("publish accepted a stale version downgrade")
	}
	if !strings.Contains(string(output), "refusing version downgrade") {
		t.Fatalf("unexpected downgrade failure:\n%s", output)
	}
	requestData, readErr := os.ReadFile(requests)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(requestData), "PUT|") {
		t.Fatalf("downgrade wrote objects before rejection:\n%s", requestData)
	}
}

func TestPublishRejectsConcurrentVersionCASConflict(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "candidate")
	winner := t.TempDir()
	writeReleaseFixture(t, winner, "winner")
	copyReleaseFixture(t, winner, filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"releases",
		"1.0.0",
	))
	seedActivatedRelease(t, fakeGCS, "qodo-cli-public-dev", winner, "1.0.0")

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GCS_ROOT="+fakeGCS,
		"FAKE_REQUESTS="+requests,
		"FAKE_CONFLICT_OBJECT=/support-bundle/version.json",
		"FAKE_CONFLICT_VERSION=1.0.0",
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=conflict-test",
		"QODO_SUPPORT_BUNDLE_DIST="+dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("publish accepted a concurrent version pointer change")
	}
	if !strings.Contains(string(output), "conditional write conflict") {
		t.Fatalf("unexpected CAS failure:\n%s", output)
	}
	metadata, readErr := os.ReadFile(filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"version.json",
	))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(metadata), "1.0.0") {
		t.Fatalf("concurrent pointer was overwritten: %s", metadata)
	}
	for _, filename := range releaseInstallers {
		expected, readErr := os.ReadFile(filepath.Join(winner, filename))
		if readErr != nil {
			t.Fatal(readErr)
		}
		actual, readErr := os.ReadFile(filepath.Join(
			fakeGCS,
			"qodo-cli-public-dev",
			"support-bundle",
			filename,
		))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(actual) != string(expected) {
			t.Fatalf("stable %s was not repaired to the winning version", filename)
		}
	}
	if !strings.Contains(string(output), "stable installers were reconciled") {
		t.Fatalf("CAS failure did not report reconciliation:\n%s", output)
	}
}

func TestPublicationRepairsStableInstallersAfterPartialUploadFailure(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	for _, test := range []struct {
		name   string
		script string
		bucket string
	}{
		{
			name:   "publish",
			script: "scripts/publish-gcs.sh",
			bucket: "qodo-cli-public-dev",
		},
		{
			name:   "promote",
			script: "scripts/promote-gcs.sh",
			bucket: "qodo-cli-public",
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := t.TempDir()
			active := t.TempDir()
			fakeGCS := t.TempDir()
			requests := filepath.Join(t.TempDir(), "requests.log")
			bin := installFakeGCSCommands(t)
			writeReleaseFixture(t, candidate, "candidate")
			writeReleaseFixture(t, active, "active")
			copyReleaseFixture(t, active, filepath.Join(
				fakeGCS,
				test.bucket,
				"support-bundle",
				"releases",
				"1.0.0",
			))
			seedActivatedRelease(t, fakeGCS, test.bucket, active, "1.0.0")

			environment := []string{
				"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
				"FAKE_GCS_ROOT=" + fakeGCS,
				"FAKE_REQUESTS=" + requests,
				"FAKE_FAIL_PUT_OBJECT=/support-bundle/install.ps1",
				"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=partial-upload-test",
				"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
			}
			if test.name == "publish" {
				environment = append(
					environment,
					"QODO_SUPPORT_BUNDLE_DIST="+candidate,
				)
			} else {
				copyReleaseFixture(t, candidate, filepath.Join(
					fakeGCS,
					"qodo-cli-public-dev",
					"support-bundle",
					"releases",
					"1.2.3",
				))
				seedActivatedRelease(
					t,
					fakeGCS,
					"qodo-cli-public-dev",
					candidate,
					"1.2.3",
				)
				environment = append(
					environment,
					"QODO_SUPPORT_BUNDLE_RELEASE_DIR="+candidate,
				)
			}

			command := exec.Command(filepath.Join(root, test.script))
			command.Env = append(os.Environ(), environment...)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("publication accepted a failed stable installer upload")
			}
			if !strings.Contains(string(output), "stable installers were reconciled") {
				t.Fatalf("failure did not report reconciliation:\n%s", output)
			}

			for _, filename := range releaseInstallers {
				expected, readErr := os.ReadFile(filepath.Join(active, filename))
				if readErr != nil {
					t.Fatal(readErr)
				}
				actual, readErr := os.ReadFile(filepath.Join(
					fakeGCS,
					test.bucket,
					"support-bundle",
					filename,
				))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(actual) != string(expected) {
					t.Fatalf("stable %s was not restored to the active version", filename)
				}
			}

			metadata, readErr := os.ReadFile(filepath.Join(
				fakeGCS,
				test.bucket,
				"support-bundle",
				"version.json",
			))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(metadata), "1.0.0") {
				t.Fatalf("failed activation changed the version pointer: %s", metadata)
			}
			lock, readErr := os.ReadFile(filepath.Join(
				fakeGCS,
				test.bucket,
				"support-bundle",
				"control",
				"publication-lock.json",
			))
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(lock) != "{\"owner\":\"\"}\n" {
				t.Fatalf("reconciled failure did not release the lock: %s", lock)
			}
		})
	}
}

func TestPublishRejectsIdenticalVersionRewrite(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "candidate")
	environment := []string{
		"FAKE_GCS_ROOT=" + fakeGCS,
		"FAKE_REQUESTS=" + requests,
		"QODO_SUPPORT_BUNDLE_DIST=" + dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	}
	runDistributionScript(
		t,
		filepath.Join(root, "scripts/publish-gcs.sh"),
		bin,
		environment,
	)

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		append(
			os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=rewrite-test",
			"FAKE_IDENTICAL_REWRITE_OBJECT=/support-bundle/version.json",
		),
		environment...,
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "generation changed") {
		t.Fatalf("identical rewrite result = %v\n%s", err, output)
	}
}

func TestPublishRefusesAnotherPublicationOwner(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	dist := t.TempDir()
	fakeGCS := t.TempDir()
	requests := filepath.Join(t.TempDir(), "requests.log")
	bin := installFakeGCSCommands(t)
	writeReleaseFixture(t, dist, "candidate")
	lock := filepath.Join(
		fakeGCS,
		"qodo-cli-public-dev",
		"support-bundle",
		"control",
		"publication-lock.json",
	)
	if err := os.MkdirAll(filepath.Dir(lock), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte("{\"owner\":\"other-run\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	command := exec.Command(filepath.Join(root, "scripts/publish-gcs.sh"))
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_GCS_ROOT="+fakeGCS,
		"FAKE_REQUESTS="+requests,
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=this-run",
		"QODO_SUPPORT_BUNDLE_DIST="+dist,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "lock is held by another publisher") {
		t.Fatalf("held publication lock result = %v\n%s", err, output)
	}
	for _, filename := range releaseInstallers {
		if _, statErr := os.Stat(filepath.Join(
			fakeGCS,
			"qodo-cli-public-dev",
			"support-bundle",
			filename,
		)); !os.IsNotExist(statErr) {
			t.Fatalf("held lock allowed stable %s to be written", filename)
		}
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
			writeReleaseFixture(t, dist, "fixture")
			data, err := os.ReadFile(filepath.Join(dist, "checksums.sha256"))
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
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
				"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=manifest-test",
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
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=identity-test",
		"QODO_SUPPORT_BUNDLE_RELEASE_DIR="+release,
		"QODO_SUPPORT_BUNDLE_VERSION=1.2.3",
	)
	output, err := command.CombinedOutput()

	if err == nil {
		t.Fatalf("promotion accepted a canary that differs from the authenticated release")
	}
	if !strings.Contains(string(output), "release bytes differ") {
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
	versionPattern := `^v?[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$`
	if !strings.Contains(publication, versionPattern) ||
		!strings.Contains(promotion, versionPattern) {
		t.Fatal("publication workflows do not use the installer version grammar")
	}

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
		"installer-checksums.sha256",
		"canary-dev-installers.sh",
		"windows-11-arm",
		"qodo-scout.exe\" version",
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER",
		"group: support-bundle-dev-publication",
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
		"installer-checksums.sha256",
		"canary-production-installers.sh",
		"verify-production-cdn.sh",
		"https://get.qodo.ai/support-bundle",
		"windows-11-arm",
		"qodo-scout.exe\" version",
		"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER",
		"group: support-bundle-production-promotion",
	} {
		if !strings.Contains(promotion, required) {
			t.Fatalf("promotion workflow does not contain %q", required)
		}
	}
	if strings.Contains(publication, "qodo-cli-public\n") {
		t.Fatal("publication workflow can write the production bucket directly")
	}
}

func TestReleaseWorkflowUploadsAssetsWithoutClobber(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	workflow := readText(t, filepath.Join(
		root,
		".github/workflows/release-support-bundle.yaml",
	))
	versionPattern := `^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$`
	if strings.Count(workflow, versionPattern) != 2 {
		t.Fatal("release workflow does not consistently use the installer version grammar")
	}
	for _, required := range []string{
		"installer-checksums.sha256",
		"scripts/upload-github-release.sh",
		"subject-path: dist/*",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("release workflow does not contain %q", required)
		}
	}
	if strings.Contains(workflow, "--clobber") {
		t.Fatal("release workflow can overwrite existing release assets")
	}
}

func TestCanariesRunVersionOnlyAndReleaseHasTenAssets(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	for _, path := range []string{
		"scripts/canary-dev-installers.sh",
		"scripts/canary-production-installers.sh",
	} {
		text := readText(t, filepath.Join(root, path))
		if !strings.Contains(text, " version") {
			t.Fatalf("%s does not run a version smoke check", path)
		}
		if strings.Contains(text, " collect") {
			t.Fatalf("%s can start cluster collection", path)
		}
		for _, required := range []string{
			`= "$EXPECTED_VERSION"`,
			"metadata-selected binary reports",
			"pinned binary reports",
		} {
			if !strings.Contains(text, required) {
				t.Fatalf("%s does not contain %q", path, required)
			}
		}
	}
	dev := readText(t, filepath.Join(root, "scripts/canary-dev-installers.sh"))
	if !strings.Contains(dev, `PATH="${work}/bin:${PATH}" sh "${work}/install.sh" \`) ||
		!strings.Contains(dev, `gcloud storage cp \`) {
		t.Fatal("dev canary does not exercise unpinned network installer resolution")
	}
	makefile := readText(t, filepath.Join(root, "Makefile"))
	for _, required := range []string{
		"cp install.sh install.ps1 dist/",
		"sha256sum qodo-support-bundle-* > checksums.sha256",
		"sha256sum install.sh install.ps1 > installer-checksums.sha256",
	} {
		if !strings.Contains(makefile, required) {
			t.Fatalf("Makefile does not contain %q", required)
		}
	}
}

func TestGitHubReleaseUploadIsByteSafeAndIdempotent(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	directory := t.TempDir()
	state := t.TempDir()
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "uploads.log")
	for name, content := range map[string]string{
		"install.sh":  "unix-installer\n",
		"install.ps1": "windows-installer\n",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(directory, "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "install.sh"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	gh := `#!/bin/sh
set -eu
case "$1 $2" in
  "release view")
    for path in "$FAKE_RELEASE_STATE"/*; do
      [ -f "$path" ] || continue
      basename "$path"
    done
    ;;
  "release download")
    pattern=
    destination=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --pattern) pattern=$2; shift 2 ;;
        --dir) destination=$2; shift 2 ;;
        *) shift ;;
      esac
    done
    cp "$FAKE_RELEASE_STATE/$pattern" "$destination/$pattern"
    ;;
  "release upload")
    source=$4
    name=$(basename "$source")
    [ ! -e "$FAKE_RELEASE_STATE/$name" ] || exit 1
    cp "$source" "$FAKE_RELEASE_STATE/$name"
    printf '%s\n' "$name" >> "$FAKE_RELEASE_UPLOADS"
    ;;
  *) exit 91 ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(gh), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(root, "scripts/upload-github-release.sh")
	for range 2 {
		command := exec.Command("sh", script, "v1.2.3", directory)
		command.Env = append(
			os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"FAKE_RELEASE_STATE="+state,
			"FAKE_RELEASE_UPLOADS="+logPath,
		)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("safe upload failed: %v\n%s", err, output)
		}
	}
	uploads, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(uploads) != "install.ps1\n" {
		t.Fatalf("unexpected uploads:\n%s", uploads)
	}

	if err := os.WriteFile(
		filepath.Join(state, "install.sh"),
		[]byte("different\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", script, "v1.2.3", directory)
	command.Env = append(
		os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FAKE_RELEASE_STATE="+state,
		"FAKE_RELEASE_UPLOADS="+logPath,
	)
	if output, err := command.CombinedOutput(); err == nil ||
		!strings.Contains(string(output), "existing asset differs") {
		t.Fatalf("different existing asset result = %v\n%s", err, output)
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
	installerLines := make([]string, 0, len(releaseInstallers))
	for _, filename := range releaseInstallers {
		data := []byte(contentPrefix + ":" + filename + "\n")
		if err := os.WriteFile(filepath.Join(directory, filename), data, 0o700); err != nil {
			t.Fatal(err)
		}
		installerLines = append(
			installerLines,
			fmt.Sprintf("%x  %s", sha256.Sum256(data), filename),
		)
	}
	if err := os.WriteFile(
		filepath.Join(directory, "installer-checksums.sha256"),
		[]byte(strings.Join(installerLines, "\n")+"\n"),
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
	for _, filename := range releaseFiles() {
		data, err := os.ReadFile(filepath.Join(source, filename))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(destination, filename), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func seedActivatedRelease(
	t *testing.T,
	fakeGCS, bucket, source, version string,
) {
	t.Helper()
	root := filepath.Join(fakeGCS, bucket, "support-bundle")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, filename := range releaseInstallers {
		data, err := os.ReadFile(filepath.Join(source, filename))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filename), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	metadata := fmt.Sprintf("{\"version\": \"%s\"}\n", version)
	if err := os.WriteFile(
		filepath.Join(root, "version.json"),
		[]byte(metadata),
		0o600,
	); err != nil {
		t.Fatal(err)
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
dump_headers=
content_type=
cache_control=
generation=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --request) method=$2; shift 2 ;;
    --upload-file) upload=$2; shift 2 ;;
    --output) output=$2; shift 2 ;;
    --dump-header) dump_headers=$2; shift 2 ;;
    --write-out) shift 2 ;;
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
metadata=$path.metadata
printf '%s|%s|%s|%s|%s\n' \
  "$method" "$url" "$content_type" "$cache_control" "$generation" >> "$FAKE_REQUESTS"
case "$method" in
  PUT)
    if [ -n "${FAKE_FAIL_PUT_OBJECT:-}" ] &&
      [ "${url%$FAKE_FAIL_PUT_OBJECT}" != "$url" ] &&
      [ ! -f "$FAKE_GCS_ROOT/.put-failure-injected" ]; then
      : > "$FAKE_GCS_ROOT/.put-failure-injected"
      exit 22
    fi
    if [ -n "${FAKE_CONFLICT_OBJECT:-}" ] &&
      [ "${url%$FAKE_CONFLICT_OBJECT}" != "$url" ] &&
      [ ! -f "$FAKE_GCS_ROOT/.conflict-injected" ]; then
      : > "$FAKE_GCS_ROOT/.conflict-injected"
      mkdir -p "$(dirname "$path")"
      if [ -n "${FAKE_CONFLICT_VERSION:-}" ]; then
        printf '{"version": "%s"}\n' "$FAKE_CONFLICT_VERSION" > "$path"
      else
        [ -f "$path" ] || printf '%s\n' '{"version": "9.9.9"}' > "$path"
      fi
      {
        printf 'generation=999\n'
        printf 'content_type=application/json\n'
        printf 'cache_control=no-cache, max-age=0, must-revalidate\n'
      } > "$metadata"
      exit 22
    fi
    if [ -f "$path" ]; then
      current_generation=1
      [ ! -f "$metadata" ] || current_generation=$(awk -F= '$1 == "generation" { print $2 }' "$metadata")
      [ "$generation" = "$current_generation" ] || exit 22
      next_generation=$((current_generation + 1))
    else
      [ "$generation" = 0 ] || exit 22
      next_generation=1
    fi
    mkdir -p "$(dirname "$path")"
    cp "$upload" "$path"
    {
      printf 'generation=%s\n' "$next_generation"
      printf 'content_type=%s\n' "$content_type"
      printf 'cache_control=%s\n' "$cache_control"
    } > "$metadata"
    if [ -n "$dump_headers" ]; then
      {
        printf 'HTTP/1.1 200 OK\r\n'
        printf 'x-goog-generation: %s\r\n\r\n' "$next_generation"
      } > "$dump_headers"
    fi
    case "$path" in
      */control/publication-lock.json) : > "$FAKE_GCS_ROOT/.lock-written" ;;
    esac
    ;;
  GET)
    if [ -n "${FAKE_LOCK_VERIFY_ALWAYS:-}" ] &&
      [ "${url%/control/publication-lock.json}" != "$url" ] &&
      [ -f "$FAKE_GCS_ROOT/.lock-written" ]; then
      exit 22
    fi
    if [ -n "${FAKE_IDENTICAL_REWRITE_OBJECT:-}" ] &&
      [ "${url%$FAKE_IDENTICAL_REWRITE_OBJECT}" != "$url" ]; then
      rewrite_count_file="$FAKE_GCS_ROOT/.identical-rewrite-count"
      rewrite_count=0
      [ ! -f "$rewrite_count_file" ] || rewrite_count=$(cat "$rewrite_count_file")
      rewrite_count=$((rewrite_count + 1))
      printf '%s\n' "$rewrite_count" > "$rewrite_count_file"
      if [ "$rewrite_count" -eq 4 ]; then
        {
          printf 'generation=999\n'
          printf 'content_type=application/json\n'
          printf 'cache_control=no-cache, max-age=0, must-revalidate\n'
        } > "$metadata"
      fi
    fi
    if [ -n "${FAKE_LOCK_VERIFY_FAILURE:-}" ] &&
      [ "${url%/control/publication-lock.json}" != "$url" ] &&
      [ -f "$FAKE_GCS_ROOT/.lock-written" ] &&
      [ ! -f "$FAKE_GCS_ROOT/.lock-read-failed" ]; then
      : > "$FAKE_GCS_ROOT/.lock-read-failed"
      exit 22
    fi
    if [ ! -f "$path" ]; then
      [ -z "$dump_headers" ] || : > "$dump_headers"
      printf 404
      exit 0
    fi
    cp "$path" "$output"
    current_generation=1
    case "$path" in
      */version.json)
        current_content_type=application/json
        current_cache_control='no-cache, max-age=0, must-revalidate'
        ;;
      */install.sh|*/install.ps1)
        current_content_type='text/plain; charset=utf-8'
        case "$path" in
          */releases/*) current_cache_control='public, max-age=31536000, immutable' ;;
          *) current_cache_control='no-cache, max-age=0, must-revalidate' ;;
        esac
        ;;
      */checksums.sha256|*/installer-checksums.sha256)
        current_content_type='text/plain; charset=utf-8'
        current_cache_control='public, max-age=31536000, immutable'
        ;;
      *)
        current_content_type=application/octet-stream
        current_cache_control='public, max-age=31536000, immutable'
        ;;
    esac
    if [ -f "$metadata" ]; then
      current_generation=$(awk -F= '$1 == "generation" { print $2 }' "$metadata")
      current_content_type=$(awk -F= '$1 == "content_type" { sub(/^[^=]*=/, ""); print }' "$metadata")
      current_cache_control=$(awk -F= '$1 == "cache_control" { sub(/^[^=]*=/, ""); print }' "$metadata")
    fi
    if [ -n "$dump_headers" ]; then
      {
        printf 'HTTP/1.1 200 OK\r\n'
        printf 'x-goog-generation: %s\r\n' "$current_generation"
        printf 'Content-Type: %s\r\n' "$current_content_type"
        printf 'Cache-Control: %s\r\n\r\n' "$current_cache_control"
      } > "$dump_headers"
    fi
    printf 200
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
			"QODO_SUPPORT_BUNDLE_PUBLICATION_OWNER=test-publisher",
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
	base := "https://storage.googleapis.com/" + bucket + "/support-bundle/"
	firstWrites := make(map[string]int)
	for _, line := range lines {
		fields := strings.Split(line, "|")
		if len(fields) != 5 {
			t.Fatalf("malformed request log line: %q", line)
		}
		if strings.HasPrefix(line, "DELETE|") || strings.Contains(line, "storage.objects.list") {
			t.Fatalf("broad or destructive request logged: %q", line)
		}
		if fields[0] != "PUT" || !strings.HasPrefix(fields[1], base) {
			continue
		}
		if fields[4] == "" {
			t.Fatalf("write has no generation precondition: %q", line)
		}
		relative := strings.TrimPrefix(fields[1], base)
		if _, exists := firstWrites[relative]; !exists {
			firstWrites[relative] = len(firstWrites)
		}
		if strings.HasPrefix(relative, "releases/1.2.3/") {
			if fields[3] != "public, max-age=31536000, immutable" ||
				fields[4] != "0" {
				t.Fatalf("immutable write has wrong contract: %q", line)
			}
			filename := filepath.Base(relative)
			expectedType := "text/plain; charset=utf-8"
			if strings.HasPrefix(filename, "qodo-support-bundle-") {
				expectedType = "application/octet-stream"
			}
			if fields[2] != expectedType {
				t.Fatalf("immutable write has wrong content type: %q", line)
			}
		} else if relative == "control/publication-lock.json" {
			if fields[2] != "application/json" || fields[3] != "no-store" {
				t.Fatalf("publication lock has wrong response metadata: %q", line)
			}
		} else if fields[3] != "no-cache, max-age=0, must-revalidate" {
			t.Fatalf("mutable write has wrong cache control: %q", line)
		} else {
			expectedType := "text/plain; charset=utf-8"
			if relative == "version.json" {
				expectedType = "application/json"
			}
			if fields[2] != expectedType {
				t.Fatalf("mutable write has wrong content type: %q", line)
			}
		}
	}
	for _, filename := range releaseFiles() {
		relative := "releases/1.2.3/" + filename
		if _, ok := firstWrites[relative]; !ok {
			t.Fatalf("missing immutable write for %s:\n%s", filename, data)
		}
	}
	installSH, okSH := firstWrites["install.sh"]
	installPS1, okPS1 := firstWrites["install.ps1"]
	version, okVersion := firstWrites["version.json"]
	if !okSH || !okPS1 || !okVersion ||
		version < installSH || version < installPS1 {
		t.Fatalf("version.json was not the final mutable write:\n%s", data)
	}
	lockWrites := 0
	firstLock := -1
	lastLock := -1
	installSHLine := -1
	installPS1Line := -1
	versionLine := -1
	for index, line := range lines {
		if strings.HasPrefix(
			line,
			"PUT|"+base+"control/publication-lock.json|",
		) {
			lockWrites++
			if firstLock == -1 {
				firstLock = index
			}
			lastLock = index
		}
		if strings.HasPrefix(line, "PUT|"+base+"install.sh|") {
			installSHLine = index
		}
		if strings.HasPrefix(line, "PUT|"+base+"install.ps1|") {
			installPS1Line = index
		}
		if strings.HasPrefix(line, "PUT|"+base+"version.json|") {
			versionLine = index
		}
	}
	if lockWrites < 2 || firstLock >= installSHLine || firstLock >= installPS1Line ||
		lastLock <= versionLine {
		t.Fatalf("publication lock does not bracket mutable activation:\n%s", data)
	}
}

func assertPublishedRelease(
	t *testing.T,
	fakeGCS, bucket, source, version string,
) {
	t.Helper()
	for _, filename := range releaseFiles() {
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
