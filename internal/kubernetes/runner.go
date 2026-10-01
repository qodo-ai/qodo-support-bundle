package kubernetes

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

var errCommandOutputLimit = errors.New("command output limit reached")

// ExecRunner executes a kubectl-compatible binary.
type ExecRunner struct {
	Binary string
}

// Run executes one bounded kubectl command.
func (runner ExecRunner) Run(
	ctx context.Context,
	maxBytes int64,
	arguments ...string,
) (CommandResult, error) {
	if !filepath.IsAbs(runner.Binary) {
		return CommandResult{}, errors.New("kubectl binary path must be absolute")
	}
	commandContext, cancel := context.WithCancel(ctx)
	defer cancel()
	stdout := newStoppingBoundedBuffer(maxBytes, cancel)
	stderr := newBoundedBuffer(64 << 10)
	command := exec.CommandContext(commandContext, runner.Binary, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if stdout.Truncated() && ctx.Err() == nil {
		err = nil
	}
	return CommandResult{
		Stdout:          stdout.Bytes(),
		Stderr:          stderr.Bytes(),
		Truncated:       stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
	}, err
}
