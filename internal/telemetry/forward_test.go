package telemetry

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const helperProcessEnvironment = "TELEMETRY_HELPER_PROCESS"

func TestTelemetryHelperProcess(t *testing.T) {
	if os.Getenv(helperProcessEnvironment) != "1" {
		return
	}
	mode := ""
	for index, argument := range os.Args {
		if argument == "--" && index+1 < len(os.Args) {
			mode = os.Args[index+1]
			break
		}
	}
	switch mode {
	case "ready":
		_, _ = fmt.Fprintln(os.Stderr, "Forwarding from 127.0.0.1:43123 -> 9090")
	case "ready-split":
		_, _ = os.Stderr.WriteString("Forwarding from 127.0.0.")
		time.Sleep(10 * time.Millisecond)
		_, _ = os.Stderr.WriteString("1:43123 -> 9090\n")
	case "wrong-bind":
		_, _ = fmt.Fprintln(os.Stderr, "Forwarding from localhost:43123 -> 9090")
	case "early":
		_, _ = fmt.Fprintln(os.Stderr, "private stderr canary")
		os.Exit(17)
	case "overflow":
		_, _ = fmt.Fprintln(os.Stderr, strings.Repeat("private-output-", 128))
	case "silent":
	default:
		os.Exit(2)
	}
	for {
		time.Sleep(time.Hour)
	}
}

type commandCapture struct {
	name      string
	arguments []string
	command   *exec.Cmd
}

func TestKubectlForwarderBuildsSafeArgumentsAndParsesReadiness(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "ready-split", capture)

	tunnel, err := forwarder.Forward(
		context.Background(),
		Target{Service: "prometheus", Port: 9090},
	)

	if err != nil {
		t.Fatalf("Forward() error = %v", err)
	}
	if tunnel.BaseURL != "http://127.0.0.1:43123" || tunnel.Port != 43123 {
		t.Fatalf("tunnel = %+v", tunnel)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if capture.name != executable {
		t.Fatalf("binary = %q, want %q", capture.name, executable)
	}
	wantArguments := []string{
		"--kubeconfig", "/tmp/kube config",
		"--context", "customer",
		"--namespace", "observability",
		"port-forward",
		"--address=127.0.0.1",
		"service/prometheus",
		":9090",
	}
	if !reflect.DeepEqual(capture.arguments, wantArguments) {
		t.Fatalf("arguments = %#v", capture.arguments)
	}
	if strings.Contains(strings.Join(capture.arguments, " "), " sh ") {
		t.Fatalf("shell appeared in arguments: %#v", capture.arguments)
	}
	if err := tunnel.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if tunnel.Err() != nil {
		t.Fatalf("intentional close reported tunnel error = %v", tunnel.Err())
	}
	if capture.command.ProcessState == nil {
		t.Fatal("child was not reaped")
	}
}

func TestKubectlForwarderRejectsNonExplicitReadiness(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "wrong-bind", capture)
	forwarder.config.ReadinessTimeout = 50 * time.Millisecond

	tunnel, err := forwarder.Forward(
		context.Background(),
		Target{Service: "prometheus", Port: 9090},
	)

	if tunnel != nil || !errors.Is(err, ErrForwardTimeout) {
		t.Fatalf("tunnel=%+v error=%v", tunnel, err)
	}
	if capture.command.ProcessState == nil {
		t.Fatal("timed-out child was not reaped")
	}
}

func TestKubectlForwarderSanitizesEarlyExit(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "early", capture)

	tunnel, err := forwarder.Forward(
		context.Background(),
		Target{Service: "prometheus", Port: 9090},
	)

	if tunnel != nil || !errors.Is(err, ErrForwardExited) {
		t.Fatalf("tunnel=%+v error=%v", tunnel, err)
	}
	if strings.Contains(err.Error(), "private") ||
		strings.Contains(err.Error(), "exit status") {
		t.Fatalf("error leaked process details: %v", err)
	}
	if capture.command.ProcessState == nil || !capture.command.ProcessState.Exited() {
		t.Fatal("exited child was not reaped")
	}
}

func TestKubectlForwarderBoundsProcessOutput(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "overflow", capture)
	forwarder.config.MaxOutputBytes = 64

	tunnel, err := forwarder.Forward(
		context.Background(),
		Target{Service: "prometheus", Port: 9090},
	)

	if tunnel != nil || !errors.Is(err, ErrForwardOutputLimit) {
		t.Fatalf("tunnel=%+v error=%v", tunnel, err)
	}
	if strings.Contains(err.Error(), "private-output") {
		t.Fatalf("error leaked process output: %v", err)
	}
	if capture.command.ProcessState == nil {
		t.Fatal("overflowing child was not reaped")
	}
}

func TestKubectlForwarderCancellationReapsChild(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "silent", capture)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := forwarder.Forward(
			ctx,
			Target{Service: "prometheus", Port: 9090},
		)
		result <- err
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, ErrForwardCanceled) ||
			!errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Forward did not return after cancellation")
	}
	if capture.command == nil ||
		capture.command.ProcessState == nil {
		t.Fatal("canceled child was not reaped")
	}
}

func TestTunnelParentCancellationAndCloseAreIdempotent(t *testing.T) {
	t.Parallel()
	capture := &commandCapture{}
	forwarder := testForwarder(t, "ready", capture)
	ctx, cancel := context.WithCancel(context.Background())
	tunnel, err := forwarder.Forward(
		ctx,
		Target{Service: "prometheus", Port: 9090},
	)
	if err != nil {
		t.Fatalf("Forward() error = %v", err)
	}

	cancel()
	select {
	case <-tunnel.lifecycle.closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("child was not cleaned up after parent cancellation")
	}
	if !errors.Is(tunnel.Err(), ErrForwardCanceled) {
		t.Fatalf("tunnel error = %v", tunnel.Err())
	}

	const closers = 8
	var wait sync.WaitGroup
	errorsFound := make(chan error, closers)
	for index := 0; index < closers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsFound <- tunnel.Close()
		}()
	}
	wait.Wait()
	close(errorsFound)
	for closeErr := range errorsFound {
		if closeErr != nil {
			t.Fatalf("idempotent Close() error = %v", closeErr)
		}
	}
	if capture.command.ProcessState == nil {
		t.Fatal("canceled child was orphaned")
	}
}

func TestKubectlForwarderValidatesBinaryTargetAndConfig(t *testing.T) {
	t.Parallel()
	config := validForwardConfig()
	if _, err := NewKubectlForwarder("kubectl", config); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("relative binary error = %v", err)
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	forwarder, err := NewKubectlForwarder(executable, config)
	if err != nil {
		t.Fatal(err)
	}
	tests := []Target{
		{Service: "../pod", Port: 9090},
		{Service: "prometheus", Port: 0},
		{Service: "prometheus", Port: 65536},
	}
	for _, target := range tests {
		if _, err := forwarder.Forward(context.Background(), target); !errors.Is(
			err,
			ErrInvalidConfig,
		) {
			t.Fatalf("target=%+v error=%v", target, err)
		}
	}
}

func testForwarder(
	t *testing.T,
	mode string,
	capture *commandCapture,
) *KubectlForwarder {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	factory := func(name string, arguments ...string) *exec.Cmd {
		capture.name = name
		capture.arguments = append([]string(nil), arguments...)
		command := exec.Command(
			name,
			"-test.run=^TestTelemetryHelperProcess$",
			"--",
			mode,
		)
		command.Env = append(os.Environ(), helperProcessEnvironment+"=1")
		capture.command = command
		return command
	}
	forwarder, err := newKubectlForwarder(
		executable,
		validForwardConfig(),
		factory,
	)
	if err != nil {
		t.Fatal(err)
	}
	return forwarder
}

func validForwardConfig() ForwardConfig {
	return ForwardConfig{
		Namespace:        "observability",
		Context:          "customer",
		Kubeconfig:       "/tmp/kube config",
		ReadinessTimeout: time.Second,
		MaxOutputBytes:   8 << 10,
	}
}
