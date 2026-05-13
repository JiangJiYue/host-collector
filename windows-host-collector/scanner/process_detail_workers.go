package scanner

import (
	"context"

	"collector-shared/orchestration"
)

func runBoundedWorkers[T any](
	ctx context.Context,
	workerCount int,
	input []T,
	fn func(context.Context, T),
) {
	orchestration.RunBounded(ctx, workerCount, input, fn)
}
