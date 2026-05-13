package orchestration

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRunRetriesUntilOperationSucceeds(t *testing.T) {
	var attempts int
	var events []Attempt

	err := Run(context.Background(), Policy{
		MaxRetries: 3,
		Backoff:    func(int) time.Duration { return 0 },
		OnRetry: func(attempt Attempt) {
			events = append(events, attempt)
		},
	}, func(context.Context, int) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 retry events, got %#v", events)
	}
	if events[0].Attempt != 1 || events[0].NextAttempt != 2 || events[0].MaxAttempts != 4 {
		t.Fatalf("unexpected retry event: %#v", events[0])
	}
}

func TestRunStopsOnPermanentError(t *testing.T) {
	permanent := errors.New("permanent")
	var attempts int

	err := Run(context.Background(), Policy{
		MaxRetries: 3,
		Backoff:    func(int) time.Duration { return 0 },
		Retryable:  func(error) bool { return false },
	}, func(context.Context, int) error {
		attempts++
		return permanent
	})

	if !errors.Is(err, permanent) {
		t.Fatalf("expected permanent error, got %v", err)
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
}

func TestRunCancelsDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	err := Run(ctx, Policy{
		MaxRetries: 3,
		Backoff:    func(int) time.Duration { return time.Hour },
		OnRetry: func(Attempt) {
			cancel()
		},
	}, func(context.Context, int) error {
		return errors.New("temporary")
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestRunTreatsNegativeBackoffAsZero(t *testing.T) {
	var attempts int

	err := Run(context.Background(), Policy{
		MaxRetries: 1,
		Backoff:    func(int) time.Duration { return -time.Second },
	}, func(context.Context, int) error {
		attempts++
		if attempts == 1 {
			return errors.New("temporary")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected retry to succeed, got %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}
