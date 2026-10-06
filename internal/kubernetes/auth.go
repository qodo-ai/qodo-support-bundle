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
	return "Kubernetes authentication is unavailable"
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
	stderr := string(result.Stderr)
	const credentialPrefix = "getting credentials: exec: executable "
	prefixes := []string{
		credentialPrefix,
		"error: " + credentialPrefix,
		"unable to connect to the server: " + credentialPrefix,
	}
	for _, rawLine := range strings.Split(stderr, "\n") {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		for _, prefix := range prefixes {
			if !strings.HasPrefix(lower, prefix) {
				continue
			}
			const suffix = " not found"
			remainder := line[len(prefix):]
			if !strings.HasSuffix(strings.ToLower(remainder), suffix) {
				continue
			}
			command := strings.TrimSpace(remainder[:len(remainder)-len(suffix)])
			if command == "" || len(command) > 4096 ||
				strings.IndexFunc(command, unicode.IsControl) >= 0 {
				return nil
			}
			return &AuthenticationHelperUnavailableError{
				Command: command,
				Cause:   errors.New("kubectl could not start the authentication helper"),
			}
		}
	}
	return nil
}
