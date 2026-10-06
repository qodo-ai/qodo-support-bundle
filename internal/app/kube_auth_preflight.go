package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/qodo-ai/qodo-support-bundle/internal/kubernetes"
)

const kubeconfigInspectionLimit int64 = 1 << 20

type executableLookup func(string) (string, error)

func checkAuthenticationHelper(
	ctx context.Context,
	runner kubernetes.Runner,
	kubeconfig string,
	kubeContext string,
	lookup executableLookup,
) error {
	if runner == nil {
		return errors.New(
			"unable to inspect selected kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	arguments := kubeconfigArguments(kubeconfig)
	arguments = append(
		arguments,
		"--context", kubeContext,
		"config", "view", "--minify", "--output=json",
	)
	result, err := runner.Run(ctx, kubeconfigInspectionLimit, arguments...)
	if err != nil || result.Truncated {
		if errors.Is(ctx.Err(), context.Canceled) {
			return context.Canceled
		}
		return errors.New(
			"unable to inspect selected kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	command, err := authenticationHelperCommand(result.Stdout)
	if err != nil {
		return errors.New(
			"unable to inspect selected kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	if command == "" {
		return nil
	}
	if lookup == nil {
		lookup = exec.LookPath
	}
	resolved, lookupErr := lookup(command)
	if lookupErr == nil && resolved != "" {
		return nil
	}
	if lookupErr == nil {
		lookupErr = errors.New("authentication helper resolved to an empty path")
	}
	return &kubernetes.AuthenticationHelperUnavailableError{
		Command: command,
		Cause:   lookupErr,
	}
}

func authenticationHelperCommand(data []byte) (string, error) {
	var config struct {
		Users []struct {
			User struct {
				Exec *struct {
					Command string `json:"command"`
				} `json:"exec"`
			} `json:"user"`
		} `json:"users"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&config); err != nil {
		return "", err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return "", errors.New("unexpected data after kubeconfig JSON")
	}
	command := ""
	for _, user := range config.Users {
		if user.User.Exec == nil {
			continue
		}
		current := user.User.Exec.Command
		if strings.TrimSpace(current) == "" || command != "" {
			return "", errors.New("invalid exec authentication command")
		}
		command = current
	}
	return command, nil
}

func resolveSelectedKubeContext(
	ctx context.Context,
	discovery kubernetesWizardDiscovery,
	explicitContext string,
) (string, error) {
	if explicitContext != "" {
		return explicitContext, nil
	}
	if discovery.Runner == nil {
		return "", errors.New(
			"unable to read current kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	arguments := discovery.baseArguments()
	arguments = append(arguments, "config", "current-context")
	result, err := discovery.Runner.Run(
		ctx,
		kubeconfigInspectionLimit,
		arguments...,
	)
	if err != nil || result.Truncated {
		if errors.Is(ctx.Err(), context.Canceled) {
			return "", context.Canceled
		}
		return "", errors.New(
			"unable to read current kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	current := strings.TrimSpace(string(result.Stdout))
	if current == "" || strings.ContainsAny(current, "\r\n") {
		return "", errors.New(
			"unable to read current kubeconfig context; check kubectl and kubeconfig settings",
		)
	}
	return current, nil
}

func kubeconfigArguments(kubeconfig string) []string {
	if kubeconfig == "" {
		return nil
	}
	return []string{"--kubeconfig", kubeconfig}
}

func writeAuthenticationHelperGuidance(
	writer io.Writer,
	_ *kubernetes.AuthenticationHelperUnavailableError,
	kubeContext string,
	namespace string,
) {
	if namespace == "" {
		namespace = "default"
	}
	contextDisplay := terminalLine(kubeContext)
	namespaceDisplay := terminalLine(namespace)
	contextArgument := verificationCommandArgument(contextDisplay, "<context>")
	namespaceArgument := verificationCommandArgument(namespaceDisplay, "<namespace>")
	_, _ = fmt.Fprintf(
		writer,
		"Kubernetes authentication is unavailable\n\n"+
			"Context: %s\n\n"+
			"Configure authentication for this context, then verify:\n\n"+
			"kubectl --context %s get pods --namespace %s\n\n"+
			"Rerun Qodo Scout after kubectl succeeds.\n",
		contextDisplay,
		contextArgument,
		namespaceArgument,
	)
}

func verificationCommandArgument(value string, placeholder string) string {
	if value == "" {
		return placeholder
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			strings.ContainsRune("-._:/@+", character) {
			continue
		}
		return placeholder
	}
	return value
}

func authenticationVerificationNamespace(
	allNamespaces bool,
	namespaces []string,
) string {
	if !allNamespaces && len(namespaces) > 0 {
		return namespaces[0]
	}
	return "default"
}
