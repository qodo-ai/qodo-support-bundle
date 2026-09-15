package kubernetes

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
)

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
	stdout := newBoundedBuffer(maxBytes)
	stderr := newBoundedBuffer(64 << 10)
	command := exec.CommandContext(ctx, runner.Binary, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	return CommandResult{
		Stdout:    stdout.Bytes(),
		Stderr:    stderr.Bytes(),
		Truncated: stdout.Truncated(),
	}, err
}
