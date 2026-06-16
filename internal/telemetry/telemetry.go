package telemetry

import "context"

type ShutdownFunc func(ctx context.Context) error

func NoopShutdown(ctx context.Context) error {
	return ctx.Err()
}
