package controllers

import "context"

type Reconciler interface {
	Reconcile(ctx context.Context, name string) error
}

type NoopReconciler struct{}

func (r NoopReconciler) Reconcile(ctx context.Context, name string) error {
	return ctx.Err()
}
