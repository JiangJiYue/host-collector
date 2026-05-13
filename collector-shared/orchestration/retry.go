package orchestration

import (
	"context"
	"errors"
	"time"
)

type Attempt struct {
	Attempt     int
	NextAttempt int
	MaxAttempts int
	Err         error
	Delay       time.Duration
}

type Policy struct {
	MaxRetries int
	Backoff    func(attempt int) time.Duration
	Retryable  func(error) bool
	OnRetry    func(Attempt)
}

func Run(ctx context.Context, policy Policy, operation func(context.Context, int) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	maxAttempts := policy.MaxRetries + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := operation(ctx, attempt)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt == maxAttempts || !isRetryable(policy, err) {
			return err
		}

		delay := backoff(policy, attempt)
		if policy.OnRetry != nil {
			policy.OnRetry(Attempt{
				Attempt:     attempt,
				NextAttempt: attempt + 1,
				MaxAttempts: maxAttempts,
				Err:         err,
				Delay:       delay,
			})
		}
		if err := wait(ctx, delay); err != nil {
			return err
		}
	}
	return lastErr
}

func isRetryable(policy Policy, err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if policy.Retryable == nil {
		return true
	}
	return policy.Retryable(err)
}

func backoff(policy Policy, attempt int) time.Duration {
	if policy.Backoff == nil {
		return time.Duration(attempt) * time.Second
	}
	delay := policy.Backoff(attempt)
	if delay < 0 {
		return 0
	}
	return delay
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
