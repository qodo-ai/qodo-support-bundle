package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/Codium-ai/qodo-platform/tools/qodo-support-bundle/internal/app"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	os.Exit(app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
