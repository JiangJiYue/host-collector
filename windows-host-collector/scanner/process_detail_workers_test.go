package scanner

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestRunBoundedWorkersWaitsForWorkersToFinish(t *testing.T) {
	t.Parallel()

	var (
		mu        sync.Mutex
		processed []int
	)

	runBoundedWorkers(context.Background(), 2, []int{1, 2, 3, 4}, func(ctx context.Context, value int) {
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
