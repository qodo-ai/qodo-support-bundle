package kubernetes

import (
	"context"
	"os/exec"
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
