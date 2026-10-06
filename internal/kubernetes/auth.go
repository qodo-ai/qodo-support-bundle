package kubernetes

import (
	"errors"
	"strings"
	"unicode"
)

// AuthenticationHelperUnavailableError identifies an exec auth command that
// kubectl could not start without retaining kubectl's stderr.
type AuthenticationHelperUnavailableError struct {
	Command string
	Cause   error
}

func (err *AuthenticationHelperUnavailableError) Error() string {
	return "Kubernetes authentication helper is unavailable"
}

func (err *AuthenticationHelperUnavailableError) Unwrap() error {
	return err.Cause
}

// ClassifyAuthenticationHelperUnavailable recognizes client-go's missing exec
// helper diagnostic and deliberately ignores all other kubectl failures.
func ClassifyAuthenticationHelperUnavailable(
	result CommandResult,
) error {
	if result.StderrTruncated {
		return nil
	}
	const prefix = "getting credentials: exec: executable "
	stderr := string(result.Stderr)
	offset := strings.Index(strings.ToLower(stderr), prefix)
	if offset < 0 {
		return nil
	}
	line := stderr[offset+len(prefix):]
	if end := strings.IndexAny(line, "\r\n"); end >= 0 {
		line = line[:end]
	}
	const suffix = " not found"
	if !strings.HasSuffix(strings.ToLower(line), suffix) {
		return nil
	}
	command := strings.TrimSpace(line[:len(line)-len(suffix)])
	if command == "" || len(command) > 4096 ||
		strings.IndexFunc(command, unicode.IsControl) >= 0 {
		return nil
	}
	return &AuthenticationHelperUnavailableError{
		Command: command,
		Cause:   errors.New("kubectl could not start the authentication helper"),
	}
}
