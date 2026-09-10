package fstxn

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAcquireCancellationAndTry(t *testing.T) {
	dir := t.TempDir()
	l, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err := AcquireContext(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("waiting acquisition: %v", err)
	}
	if _, err := TryAcquire(dir); !errors.Is(err, ErrBusy) {
		t.Fatalf("try acquisition: %v", err)
	}
	l.Close()
	next, err := TryAcquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
}
