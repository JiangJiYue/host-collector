package orchestration

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRunBoundedProcessesAllJobsBeforeReturn(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		processed []int
	)

	RunBounded(context.Background(), 2, []int{1, 2, 3, 4}, func(ctx context.Context, value int) {
		time.Sleep(10 * time.Millisecond)
		mu.Lock()
		processed = append(processed, value)
		mu.Unlock()
	})

	mu.Lock()
	defer mu.Unlock()
	if len(processed) != 4 {
		t.Fatalf("expected all jobs to finish before return, got %d", len(processed))
	}
}

func TestRunBoundedDefaultsInvalidWorkerCount(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	processed := 0
	RunBounded(context.Background(), 0, []int{1, 2}, func(ctx context.Context, value int) {
		mu.Lock()
		processed++
		mu.Unlock()
	})

	mu.Lock()
	defer mu.Unlock()
	if processed != 2 {
		t.Fatalf("expected default worker to process all jobs, got %d", processed)
	}
}
