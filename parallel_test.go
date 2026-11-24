package qat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"
	"time"
)

func openHardwareInstance(t *testing.T, instance int, poll time.Duration) *Engine {
	t.Helper()
	if os.Getenv("QATGO_TEST_HW") != "1" {
		t.Skip("set QATGO_TEST_HW=1 to run QAT hardware tests")
	}
	e, err := Open(Options{Instance: instance, PollInterval: poll})
	if err != nil {
		t.Fatalf("open instance %d: %v", instance, err)
	}
	t.Logf("instance %d: %+v", instance, e.Info())
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func TestHardwareMultipleEngineLifecycle(t *testing.T) {
	e0 := openHardwareInstance(t, 0, 0)
	e32 := openHardwareInstance(t, 32, 0)
	if duplicate, err := Open(Options{Instance: 0}); !errors.Is(err, ErrInUse) {
		if duplicate != nil {
			_ = duplicate.Close()
		}
		t.Fatalf("duplicate instance was not rejected: %v", err)
	}
	// 65535 passes Go's option validation but is absent from this host's
	// instance list, so this exercises native failed-open cleanup.
	if absent, err := Open(Options{Instance: 65535}); err == nil {
		_ = absent.Close()
		t.Fatal("unavailable instance opened successfully")
	}
	p0 := poolForTest(t, e0, 1, 4097)
	p32 := poolForTest(t, e32, 1, 4097)
	b0 := bufferForTest(t, p0)
	payload, err := b0.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pattern(payload, 19)
	s32 := streamForTest(t, e32)
	if err := s32.Submit(context.Background(), b0, len(payload)); err == nil {
		t.Fatal("cross-engine whole-buffer submission accepted")
	}
	if _, err := s32.SubmitRange(context.Background(), b0, 0, len(payload)); err == nil {
		t.Fatal("cross-engine range submission accepted")
	}
	if _, err := b0.Bytes(); err != nil {
		t.Fatal("cross-engine rejection changed lease ownership", err)
	}
	if err := s32.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b0.Release(); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, 3*4097+65)
	pattern(data, 71)
	want := sha256.Sum256(data)
	check := func(e *Engine, p *Pool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		got, n, err := e.HashReader(ctx, bytes.NewReader(data), p)
		if err != nil || n != int64(len(data)) || got != want {
			t.Fatalf("instance %d hash: bytes=%d digest=%x error=%v", e.Info().Instance, n, got, err)
		}
	}
	check(e0, p0)
	check(e32, p32)
	if err := p0.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e0.Close(); err != nil {
		t.Fatal(err)
	}
	// Closing one Engine must retain the shared allocator and SAL for others.
	check(e32, p32)
	reopened := openHardwareInstance(t, 0, 0)
	reopenedPool := poolForTest(t, reopened, 1, 4097)
	check(reopened, reopenedPool)
	check(e32, p32)
}

func TestHardwareIndependentEndpointsPendingTogether(t *testing.T) {
	// This host configures two crypto instances per VF and sixteen VFs per
	// endpoint. These indexes select the first VF on each of its three PFs.
	instances := []int{0, 32, 64}
	engines := make([]*Engine, len(instances))
	streams := make([]*Stream, len(instances))
	requests := make([]*Submission, len(instances))
	want := make([][32]byte, len(instances))
	for i, instance := range instances {
		engines[i] = openHardwareInstance(t, instance, 250*time.Millisecond)
		p := poolForTest(t, engines[i], 1, 16*MiB+129)
		b := bufferForTest(t, p)
		data, err := b.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		pattern(data, 1009*i)
		want[i] = sha256.Sum256(data)
		streams[i] = streamForTest(t, engines[i], StreamOptions{RequestBytes: 4 * MiB})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		requests[i], err = streams[i].SubmitRange(ctx, b, 0, len(data))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Instance 1 shares instance 0's VF. Stopping that distinct idle instance
	// must not stop instance 0 or tear down the process-wide runtime.
	idle := openHardwareInstance(t, 1, 0)
	for i := range engines {
		for j := 0; j < i; j++ {
			if engines[i].Info().PCI[:2] == engines[j].Info().PCI[:2] {
				t.Fatalf("selected indexes do not span distinct PCI buses: %+v %+v", engines[i].Info(), engines[j].Info())
			}
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	var observed []RequestProgress
	for {
		observed = observed[:0]
		allPending := true
		for _, s := range streams {
			progress := s.Progress()
			observed = append(observed, progress)
			allPending = allPending && progress.Submitted > progress.Completed
		}
		if allPending {
			// A second unchanged collection gives the individually sampled
			// counters a common interval with no delivered callbacks.
			for i, s := range streams {
				if s.Progress() != observed[i] {
					allPending = false
					break
				}
			}
			if allPending {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("did not observe accepted requests pending on all endpoints: %+v", observed)
		}
		time.Sleep(100 * time.Microsecond)
	}
	// These are real accepted CPA requests with callbacks not yet delivered;
	// counters alone do not establish simultaneous execution inside silicon.
	t.Logf("accepted requests pending on distinct endpoints: %+v", observed)
	if err := idle.Close(); err != nil {
		t.Fatal("close idle instance while other endpoints are pending", err)
	}
	if absent, err := Open(Options{Instance: 65535}); err == nil {
		_ = absent.Close()
		t.Fatal("unavailable instance opened while other endpoints were active")
	}
	for i, s := range streams {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		got, err := s.Finish(ctx)
		if err == nil {
			err = requests[i].Wait(ctx)
		}
		cancel()
		if err != nil || got != want[i] {
			t.Fatalf("endpoint %d digest=%x error=%v", instances[i], got, err)
		}
		progress := s.Progress()
		if progress.Submitted == 0 || progress.Submitted != progress.Completed {
			t.Fatalf("endpoint %d did not drain its accepted requests: %+v", instances[i], progress)
		}
	}
}
