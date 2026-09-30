package e2e_test

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const fakeKubectlEnvironment = "QODO_SUPPORT_BUNDLE_FAKE_KUBECTL"

func TestMain(m *testing.M) {
	if os.Getenv(fakeKubectlEnvironment) == "1" {
		os.Exit(runFakeKubectl(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

func TestNativeCLICollectsBundleWithFakeKubectl(t *testing.T) {
	repository := repositoryRoot(t)
	binaryName := "qodo-support-bundle"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binary := filepath.Join(t.TempDir(), binaryName)
	build := exec.Command("go", "build", "-trimpath", "-o", binary, "./cmd/qodo-support-bundle")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native CLI: %v\n%s", err, output)
	}

	helper, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatalf("resolve fake kubectl path: %v", err)
	}
	workDirectory := filepath.Join(t.TempDir(), "unrelated working directory")
	outputDirectory := filepath.Join(t.TempDir(), "portable output")
	if err := os.MkdirAll(workDirectory, 0o700); err != nil {
		t.Fatalf("create working directory: %v", err)
	}
	if err := os.MkdirAll(outputDirectory, 0o700); err != nil {
		t.Fatalf("create output directory: %v", err)
	}
	archivePath := filepath.Join(outputDirectory, "smoke bundle.tar.gz")
	command := exec.Command(
		binary,
		"collect",
		"--namespace", "portability-smoke",
		"--context", "portability-context",
		"--kubectl", helper,
		"--since", "5m",
		"--log-workers", "1",
		"--output", archivePath,
	)
	command.Dir = workDirectory
	command.Env = append(os.Environ(), fakeKubectlEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("collect bundle: %v\n%s", err, output)
	}

	files := readArchive(t, archivePath)
	for _, path := range []string{
		"manifest.json",
		"checksums.sha256",
		"summary.md",
		"kubernetes/pods.jsonl",
		"kubernetes/events.jsonl",
		"kubernetes/logs/app-0/app.log",
		"kubernetes/workload-coverage.json",
	} {
		if _, exists := files[path]; !exists {
			t.Fatalf("archive is missing %q", path)
		}
	}
	var manifest struct {
		SchemaVersion string `json:"schema_version"`
		Collection    struct {
			Status string `json:"status"`
		} `json:"collection"`
	}
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if manifest.SchemaVersion != "4" || manifest.Collection.Status != "complete" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	logOutput := string(files["kubernetes/logs/app-0/app.log"])
	for _, secret := range []string{"customer@example.com", "raw-secret-token"} {
		if strings.Contains(logOutput, secret) {
			t.Fatalf("collected log contains sensitive value %q", secret)
		}
	}
	verifyChecksums(t, files)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readArchive(t *testing.T, path string) map[string][]byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		t.Fatalf("open gzip stream: %v", err)
	}
	defer compressed.Close()
	files := make(map[string][]byte)
	reader := tar.NewReader(compressed)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		clean := filepath.ToSlash(filepath.Clean(header.Name))
		if filepath.IsAbs(header.Name) || clean == ".." || strings.HasPrefix(clean, "../") {
			t.Fatalf("archive contains unsafe path %q", header.Name)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		if _, duplicate := files[clean]; duplicate {
			t.Fatalf("archive contains duplicate path %q", clean)
		}
		data, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read %q: %v", clean, err)
		}
		files[clean] = data
	}
	return files
}

func verifyChecksums(t *testing.T, files map[string][]byte) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(files["checksums.sha256"])), "\n")
	if len(lines) == 0 {
		t.Fatal("checksum manifest is empty")
	}
	unchecked := make(map[string]struct{}, len(files)-1)
	for path := range files {
		if path != "checksums.sha256" {
			unchecked[path] = struct{}{}
		}
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("invalid checksum line %q", line)
		}
		if _, expected := unchecked[fields[1]]; !expected {
			t.Fatalf("checksum references unexpected or duplicate file %q", fields[1])
		}
		data, exists := files[fields[1]]
		if !exists {
			t.Fatalf("checksum references missing file %q", fields[1])
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != fields[0] {
			t.Fatalf("checksum mismatch for %q", fields[1])
		}
		delete(unchecked, fields[1])
	}
	if len(unchecked) != 0 {
		t.Fatalf("checksum manifest omits files: %v", unchecked)
	}
}

func runFakeKubectl(arguments []string, stdout io.Writer, stderr io.Writer) int {
	if argumentAfter(arguments, "--context") != "portability-context" {
		_, _ = fmt.Fprintln(stderr, "unexpected fake Kubernetes context")
		return 1
	}
	switch {
	case hasArguments(arguments, "get", "pods"):
		if argumentAfter(arguments, "--namespace") != "portability-smoke" {
			_, _ = fmt.Fprintln(stderr, "unexpected fake pod namespace")
			return 1
		}
		_, _ = io.WriteString(stdout, `{"apiVersion":"v1","kind":"PodList","items":[{`+
			`"metadata":{"name":"app-0","namespace":"portability-smoke"},`+
			`"spec":{"containers":[{"name":"app","image":"example/app:1"}]},`+
			`"status":{"phase":"Running","containerStatuses":[{`+
			`"name":"app","ready":true,"restartCount":0}]}}]}`)
	case hasArguments(arguments, "get", "events"):
		if argumentAfter(arguments, "--namespace") != "portability-smoke" {
			_, _ = fmt.Fprintln(stderr, "unexpected fake event namespace")
			return 1
		}
		_, _ = io.WriteString(stdout, `{"apiVersion":"v1","kind":"EventList","items":[]}`)
	case hasArguments(arguments, "logs"):
		if argumentAfter(arguments, "--namespace") != "portability-smoke" {
			_, _ = fmt.Fprintln(stderr, "unexpected fake log namespace")
			return 1
		}
		_, _ = io.WriteString(
			stdout,
			"2026-09-30T08:00:00Z customer@example.com token=raw-secret-token\n",
		)
	case hasArguments(arguments, "get", "--raw"):
		path := argumentAfter(arguments, "--raw")
		response, ok := fakeWorkloadResponse(path)
		if !ok {
			_, _ = fmt.Fprintln(stderr, "unsupported fake Kubernetes API path")
			return 1
		}
		_, _ = io.WriteString(stdout, response)
	default:
		_, _ = fmt.Fprintln(stderr, "unsupported fake kubectl command")
		return 1
	}
	return 0
}

func hasArguments(arguments []string, sequence ...string) bool {
	for start := 0; start+len(sequence) <= len(arguments); start++ {
		match := true
		for offset := range sequence {
			if arguments[start+offset] != sequence[offset] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func argumentAfter(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func fakeWorkloadResponse(path string) (string, bool) {
	resources := []struct {
		segment    string
		apiVersion string
		kind       string
	}{
		{"/deployments?", "apps/v1", "DeploymentList"},
		{"/statefulsets?", "apps/v1", "StatefulSetList"},
		{"/daemonsets?", "apps/v1", "DaemonSetList"},
		{"/jobs?", "batch/v1", "JobList"},
		{"/cronjobs?", "batch/v1", "CronJobList"},
		{"/services?", "v1", "ServiceList"},
		{"/endpointslices?", "discovery.k8s.io/v1", "EndpointSliceList"},
		{"/horizontalpodautoscalers?", "autoscaling/v2", "HorizontalPodAutoscalerList"},
		{"/persistentvolumeclaims?", "v1", "PersistentVolumeClaimList"},
	}
	for _, resource := range resources {
		if strings.Contains(path, resource.segment) {
			return fmt.Sprintf(
				`{"apiVersion":%q,"kind":%q,"items":[]}`,
				resource.apiVersion,
				resource.kind,
			), true
		}
	}
	return "", false
}
