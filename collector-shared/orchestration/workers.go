package orchestration

import (
	"context"
	"sync"
)

type Job[T any] struct {
	Value T
}

func RunBounded[T any](
	ctx context.Context,
	workerCount int,
	input []T,
	fn func(context.Context, T),
) {
	if workerCount <= 0 {
		workerCount = 1
	}

	jobs := make(chan Job[T])
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
					fn(ctx, job.Value)
				}
			}
		}()
	}

	for _, item := range input {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- Job[T]{Value: item}:
		}
	}

	close(jobs)
	wg.Wait()
}
