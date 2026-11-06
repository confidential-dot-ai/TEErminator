package verifier

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitContext reports when a caller reaches the wait for the shared result.
// This lets the test hold the check until all callers have joined it.
type waitContext struct {
	context.Context
	waiting chan<- struct{}
	once    sync.Once
}

func (c *waitContext) Done() <-chan struct{} {
	c.once.Do(func() { c.waiting <- struct{}{} })
	return c.Context.Done()
}

func TestAttestedLeafSharesRefresh(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			const callers = 64
			c := NewSessionCache(time.Minute)
			now := time.Now()
			c.now = func() time.Time { return now }
			oldLeaf, newLeaf := [32]byte{1}, [32]byte{2}
			c.RecordPass("server", c.Now(), oldLeaf, now.Add(time.Hour))
			now = now.Add(time.Minute + time.Second)
			release := make(chan struct{})
			defer close(release)
			waiting := make(chan struct{}, callers)
			var checks atomic.Int32
			checkErr := errors.New("attest-lb: HTTP 429")
			attest := func(context.Context) (*SessionVerdict, error) {
				checks.Add(1)
				<-release
				if fail {
					return nil, checkErr
				}
				return &SessionVerdict{LeafSHA256: newLeaf, LeafNotAfter: now.Add(time.Hour)}, nil
			}
			results := make(chan error, callers)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			for range callers {
				go func() {
					leaf, err := c.AttestedLeaf(&waitContext{Context: ctx, waiting: waiting}, "server", attest)
					if fail {
						if !errors.Is(err, checkErr) {
							results <- errors.New("caller lost shared failure")
							return
						}
					} else if err != nil || leaf != newLeaf {
						results <- errors.New("caller did not get refreshed leaf")
						return
					}
					results <- nil
				}()
			}
			for range callers {
				select {
				case <-waiting:
				case <-ctx.Done():
					t.Fatal("callers did not join refresh")
				}
			}
			// Use a send, so the deferred close remains safe on test failure.
			// One check must consume it; all other callers share that result.
			select {
			case release <- struct{}{}:
			case <-ctx.Done():
				t.Fatal("check did not start")
			}
			for range callers {
				select {
				case err := <-results:
					if err != nil {
						t.Error(err)
					}
				case <-ctx.Done():
					t.Fatal("callers did not finish")
				}
			}
			if got := checks.Load(); got != 1 {
				t.Fatalf("checks = %d, want 1", got)
			}
			var retries int
			leaf, err := c.AttestedLeaf(ctx, "server", func(context.Context) (*SessionVerdict, error) {
				retries++
				return &SessionVerdict{LeafSHA256: newLeaf, LeafNotAfter: now.Add(time.Hour)}, nil
			})
			if err != nil || leaf != newLeaf {
				t.Fatalf("next request = %x, %v", leaf, err)
			}
			if fail && retries != 1 {
				t.Fatal("failed check prevented a retry")
			}
			if !fail && retries != 0 {
				t.Fatal("successful check was not cached")
			}
		})
	}
}

func TestAttestedLeafCallerCancellationAndOtherServer(t *testing.T) {
	c := NewSessionCache(time.Minute)
	started, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan error, 1)
	pin := [32]byte{3}
	go func() {
		_, err := c.AttestedLeaf(ctx, "server", func(checkCtx context.Context) (*SessionVerdict, error) {
			close(started)
			select {
			case <-release:
			case <-checkCtx.Done():
				return nil, checkCtx.Err()
			}
			return &SessionVerdict{LeafSHA256: pin, LeafNotAfter: time.Now().Add(time.Hour)}, nil
		})
		first <- err
	}()
	<-started
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}

	otherCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	// Another server must not wait for the blocked check.
	if _, err := c.AttestedLeaf(otherCtx, "other-server", func(context.Context) (*SessionVerdict, error) {
		return &SessionVerdict{LeafSHA256: pin, LeafNotAfter: time.Now().Add(time.Hour)}, nil
	}); err != nil {
		t.Fatal(err)
	}

	waiting := make(chan struct{}, 1)
	second := make(chan error, 1)
	go func() {
		leaf, err := c.AttestedLeaf(&waitContext{Context: otherCtx, waiting: waiting}, "server", func(context.Context) (*SessionVerdict, error) {
			return nil, errors.New("second caller started a duplicate check")
		})
		if err == nil && leaf != pin {
			err = errors.New("wrong leaf")
		}
		second <- err
	}()
	<-waiting
	release <- struct{}{}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
}
