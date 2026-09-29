package telemetry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var forwardingLinePattern = regexp.MustCompile(
	`^Forwarding from 127\.0\.0\.1:([0-9]+) -> ([0-9]+)\r?$`,
)

type commandFactory func(name string, arguments ...string) *exec.Cmd

// KubectlForwarder opens supervised, loopback-only kubectl tunnels.
type KubectlForwarder struct {
	binary  string
	config  ForwardConfig
	command commandFactory
}

var _ Forwarder = (*KubectlForwarder)(nil)

// NewKubectlForwarder builds a production forwarder from a resolved absolute
// kubectl path.
func NewKubectlForwarder(
	binary string,
	config ForwardConfig,
) (*KubectlForwarder, error) {
	return newKubectlForwarder(binary, config, exec.Command)
}

func newKubectlForwarder(
	binary string,
	config ForwardConfig,
	factory commandFactory,
) (*KubectlForwarder, error) {
	if !filepath.IsAbs(binary) ||
		!validDNSLabel(config.Namespace) ||
		config.ReadinessTimeout <= 0 ||
		config.MaxOutputBytes <= 0 ||
		factory == nil {
		return nil, ErrInvalidConfig
	}
	return &KubectlForwarder{
		binary:  binary,
		config:  config,
		command: factory,
	}, nil
}

// Tunnel is a localhost HTTP endpoint backed by a supervised child process.
// BaseURL never contains a cluster address or caller-provided host.
type Tunnel struct {
	BaseURL string
	Port    int

	lifecycle *processLifecycle
}

// Close terminates and reaps the child. It is safe to call concurrently and
// repeatedly.
func (tunnel *Tunnel) Close() error {
	if tunnel == nil || tunnel.lifecycle == nil {
		return nil
	}
	return tunnel.lifecycle.close()
}

// Err reports a stable reason if the tunnel ended asynchronously.
func (tunnel *Tunnel) Err() error {
	if tunnel == nil || tunnel.lifecycle == nil {
		return nil
	}
	return tunnel.lifecycle.err()
}

// Forward starts kubectl and waits for its explicit IPv4 loopback readiness
// line. The returned tunnel remains tied to ctx.
func (forwarder *KubectlForwarder) Forward(
	ctx context.Context,
	target Target,
) (*Tunnel, error) {
	if forwarder == nil ||
		forwarder.command == nil ||
		!filepath.IsAbs(forwarder.binary) ||
		!validDNSLabel(forwarder.config.Namespace) ||
		forwarder.config.ReadinessTimeout <= 0 ||
		forwarder.config.MaxOutputBytes <= 0 ||
		!validDNSLabel(target.Service) ||
		target.Port < 1 ||
		target.Port > 65535 {
		return nil, ErrInvalidConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrForwardCanceled, err)
	}

	arguments := append(
		globalArguments(forwarder.config.Kubeconfig, forwarder.config.Context),
		"--namespace", forwarder.config.Namespace,
		"port-forward",
		"--address=127.0.0.1",
		"service/"+target.Service,
		":"+strconv.Itoa(target.Port),
	)
	command := forwarder.command(forwarder.binary, arguments...)
	if command == nil {
		return nil, ErrForwardStart
	}

	output := newForwardOutput(forwarder.config.MaxOutputBytes, target.Port)
	command.Stdout = output.writer()
	command.Stderr = output.writer()
	if err := command.Start(); err != nil {
		return nil, ErrForwardStart
	}

	lifecycle := newProcessLifecycle(command)
	timer := time.NewTimer(forwarder.config.ReadinessTimeout)
	defer timer.Stop()

	var failure error
	select {
	case readiness := <-output.ready:
		if err := ctx.Err(); err != nil {
			failure = errors.Join(ErrForwardCanceled, err)
			break
		}
		select {
		case <-lifecycle.waitDone:
			failure = ErrForwardExited
		default:
			tunnel := &Tunnel{
				BaseURL:   fmt.Sprintf("http://127.0.0.1:%d", readiness.localPort),
				Port:      readiness.localPort,
				lifecycle: lifecycle,
			}
			go superviseTunnel(ctx, tunnel, output)
			return tunnel, nil
		}
	case <-output.overflow:
		failure = ErrForwardOutputLimit
	case <-lifecycle.waitDone:
		failure = ErrForwardExited
	case <-timer.C:
		failure = ErrForwardTimeout
	case <-ctx.Done():
		failure = errors.Join(ErrForwardCanceled, ctx.Err())
	}

	if cleanupErr := lifecycle.close(); cleanupErr != nil {
		return nil, errors.Join(failure, cleanupErr)
	}
	return nil, failure
}

func superviseTunnel(ctx context.Context, tunnel *Tunnel, output *forwardOutput) {
	select {
	case <-ctx.Done():
		tunnel.lifecycle.setErr(ErrForwardCanceled)
		_ = tunnel.Close()
	case <-output.overflow:
		tunnel.lifecycle.setErr(ErrForwardOutputLimit)
		_ = tunnel.Close()
	case <-tunnel.lifecycle.waitDone:
		if channelClosed(tunnel.lifecycle.closing) {
			return
		}
		tunnel.lifecycle.setErr(ErrForwardUnavailable)
		_ = tunnel.Close()
	case <-tunnel.lifecycle.closing:
	case <-tunnel.lifecycle.closeDone:
	}
}

type readiness struct {
	localPort int
}

type forwardOutput struct {
	mu         sync.Mutex
	maxBytes   int64
	totalBytes int64
	remotePort int
	overflowed bool
	readySent  bool
	ready      chan readiness
	overflow   chan struct{}
}

func newForwardOutput(maxBytes int64, remotePort int) *forwardOutput {
	return &forwardOutput{
		maxBytes:   maxBytes,
		remotePort: remotePort,
		ready:      make(chan readiness, 1),
		overflow:   make(chan struct{}),
	}
}

func (output *forwardOutput) writer() io.Writer {
	return &forwardStreamWriter{output: output}
}

func (output *forwardOutput) reserve(count int) bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflowed {
		return false
	}
	if count < 0 || output.totalBytes > output.maxBytes-int64(count) {
		output.overflowed = true
		close(output.overflow)
		return false
	}
	output.totalBytes += int64(count)
	return true
}

func (output *forwardOutput) observeLine(line []byte) {
	matches := forwardingLinePattern.FindSubmatch(line)
	if len(matches) != 3 {
		return
	}
	localPort, localErr := strconv.Atoi(string(matches[1]))
	remotePort, remoteErr := strconv.Atoi(string(matches[2]))
	if localErr != nil ||
		remoteErr != nil ||
		localPort < 1 ||
		localPort > 65535 ||
		remotePort != output.remotePort {
		return
	}

	output.mu.Lock()
	defer output.mu.Unlock()
	if output.overflowed || output.readySent {
		return
	}
	output.readySent = true
	output.ready <- readiness{localPort: localPort}
}

type forwardStreamWriter struct {
	output  *forwardOutput
	partial []byte
}

func (writer *forwardStreamWriter) Write(data []byte) (int, error) {
	if !writer.output.reserve(len(data)) {
		return len(data), nil
	}
	writer.partial = append(writer.partial, data...)
	for {
		newline := bytes.IndexByte(writer.partial, '\n')
		if newline < 0 {
			return len(data), nil
		}
		writer.output.observeLine(writer.partial[:newline])
		writer.partial = writer.partial[newline+1:]
	}
}

type processLifecycle struct {
	command *exec.Cmd

	waitDone  chan struct{}
	closing   chan struct{}
	closeDone chan struct{}

	mu          sync.Mutex
	terminalErr error
	cleanupErr  error
	closeOnce   sync.Once
}

func newProcessLifecycle(command *exec.Cmd) *processLifecycle {
	lifecycle := &processLifecycle{
		command:   command,
		waitDone:  make(chan struct{}),
		closing:   make(chan struct{}),
		closeDone: make(chan struct{}),
	}
	go func() {
		_ = command.Wait()
		close(lifecycle.waitDone)
	}()
	return lifecycle
}

func (lifecycle *processLifecycle) close() error {
	lifecycle.closeOnce.Do(func() {
		close(lifecycle.closing)
		if !channelClosed(lifecycle.waitDone) {
			if err := lifecycle.command.Process.Kill(); err != nil &&
				!errors.Is(err, os.ErrProcessDone) {
				lifecycle.mu.Lock()
				lifecycle.cleanupErr = ErrForwardCleanup
				lifecycle.mu.Unlock()
			}
		}
		<-lifecycle.waitDone
		close(lifecycle.closeDone)
	})
	<-lifecycle.closeDone
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.cleanupErr
}

func (lifecycle *processLifecycle) setErr(err error) {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.terminalErr == nil {
		lifecycle.terminalErr = err
	}
}

func (lifecycle *processLifecycle) err() error {
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.terminalErr
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
}
