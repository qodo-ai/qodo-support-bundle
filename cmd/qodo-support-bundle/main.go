package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/qodo-ai/qodo-support-bundle/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), interruptSignals()...)
	defer cancel()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
