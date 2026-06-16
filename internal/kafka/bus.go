package kafka

import (
	"context"

	"github.com/r0m43k/CSCP/pkg/events"
)

type Producer interface {
	Publish(ctx context.Context, event events.Event) error
}

type Consumer interface {
	Consume(ctx context.Context, handler Handler) error
}

type Handler func(ctx context.Context, event events.Event) error

type NoopProducer struct{}

func (p NoopProducer) Publish(ctx context.Context, event events.Event) error {
	return ctx.Err()
}
