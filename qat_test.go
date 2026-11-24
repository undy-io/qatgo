package qat

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

func openHardware(t *testing.T, poll time.Duration) *Engine {
	t.Helper()
	if os.Getenv("QATGO_TEST_HW") != "1" {
		t.Skip("set QATGO_TEST_HW=1 to run QAT hardware tests")
	}
	e, err := Open(Options{PollInterval: poll})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.Close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func poolForTest(t *testing.T, e *Engine, count, size int) *Pool {
	t.Helper()
	p, err := e.NewPool(count, size)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := p.Close(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func bufferForTest(t *testing.T, p *Pool) *Buffer {
	t.Helper()
	b, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Release() })
	return b
}

func streamForTest(t *testing.T, e *Engine, opts ...StreamOptions) *Stream {
	t.Helper()
	s, err := e.NewSHA256(opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func pattern(p []byte, base int) {
	for i := range p {
		j := i + base
		p[i] = byte((uint64(j)*131 + uint64(j>>8)*17) ^ uint64(j>>16))
	}
}

func TestOptionsValidation(t *testing.T) {
	for _, o := range []Options{{Instance: -1}, {Instance: 65536}, {PollInterval: -1}, {PollInterval: 2 * time.Second}} {
		if e, err := Open(o); err == nil {
			_ = e.Close()
			t.Fatalf("invalid options accepted: %+v", o)
		}
	}
}

func TestCancellationWaitingForProducer(t *testing.T) {
	// Simulate another producer holding the submission gate while queue space
	// is unavailable. Public operations must honor deadlines before handoff.
	s := &Stream{operation: make(chan struct{}, 1)}
	s.operation <- struct{}{}
	for _, call := range []func(context.Context) error{
		func(ctx context.Context) error { return s.Submit(ctx, nil, 0) },
		func(ctx context.Context) error { _, err := s.SubmitRange(ctx, nil, 0, 0); return err },
		s.Flush,
		func(ctx context.Context) error { _, err := s.Finish(ctx); return err },
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
		err := call(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("producer gate did not honor context: %v", err)
		}
	}
	s.leave()
}

func TestHardwareDigestBoundaries(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 2*MiB+257)
	for _, n := range []int{0, 1, 55, 56, 63, 64, 65, MiB - 1, MiB, MiB + 1, 2*MiB + 257} {
		t.Run(stringName(n), func(t *testing.T) {
			b, err := p.Acquire(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			data, _ := b.Bytes()
			pattern(data[:n], 0)
			want := sha256.Sum256(data[:n])
			s, err := e.NewSHA256()
			if err != nil {
				_ = b.Release()
				t.Fatal(err)
			}
			if err = s.Submit(context.Background(), b, n); err != nil {
				_ = b.Release()
				_ = s.Close()
				t.Fatal(err)
			}
			got, err := s.Finish(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Fatalf("digest mismatch at %d bytes: got %x want %x", n, got, want)
			}
			if again, err := s.Finish(context.Background()); again != got || err != nil {
				t.Fatal("non-idempotent Finish")
			}
			if _, err = b.Bytes(); !errors.Is(err, ErrBufferOwned) {
				t.Fatal("transferred lease stayed accessible")
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func stringName(n int) string {
	if n == 0 {
		return "empty"
	}
	var out [24]byte
	i := len(out)
	for n > 0 {
		i--
		out[i] = byte(n%10) + '0'
		n /= 10
	}
	return string(out[i:])
}

func TestHardwareContiguousRangePipeline(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 4*MiB+193)
	b := bufferForTest(t, p)
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 4*MiB+193 || cap(data) != len(data) {
		t.Fatal("incorrect contiguous slice size")
	}
	s := streamForTest(t, e, StreamOptions{RequestBytes: 256 * 1024, QueueDepth: 2})
	// Fill only newly received regions. This exercises offsets, 64-byte tail
	// carry and physical allocation crossings while earlier regions hash.
	want := sha256.New()
	chunks := []int{1, 17, 47, 2*MiB - 19, 63, 65, 777777, 1048577}
	var requests []*Submission
	for offset, i := 0, 0; offset < len(data); i++ {
		n := chunks[i%len(chunks)]
		if n > len(data)-offset {
			n = len(data) - offset
		}
		pattern(data[offset:offset+n], offset)
		_, _ = want.Write(data[offset : offset+n])
		r, err := s.SubmitRange(context.Background(), b, offset, n)
		if err != nil {
			t.Fatal(err)
		}
		requests = append(requests, r)
		offset += n
	}
	got, err := s.Finish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[:], want.Sum(nil)) {
		t.Fatalf("range digest mismatch: %x", got)
	}
	for _, r := range requests {
		if err := r.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareLeaseAndRangeOwnership(t *testing.T) {
	e := openHardware(t, 250*time.Microsecond)
	p := poolForTest(t, e, 1, 4*MiB)
	b := bufferForTest(t, p)
	data, _ := b.Bytes()
	pattern(data, 0)
	s := streamForTest(t, e)
	if err := e.Close(); !errors.Is(err, ErrInUse) {
		t.Fatal("engine close ignored children")
	}
	if err := p.Close(); !errors.Is(err, ErrInUse) {
		t.Fatal("pool close ignored lease")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled acquire")
	}
	if err := s.Submit(ctx, b, 64); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled submit")
	}
	if _, err := b.Bytes(); err != nil {
		t.Fatal("canceled submit consumed lease")
	}
	r, err := s.SubmitRange(context.Background(), b, 0, len(data))
	if err != nil {
		t.Fatal(err)
	}
	// These checks are made while the worker must acquire this lease's mutex
	// before finishing, so completed requests also remain safe to inspect.
	b.mu.Lock()
	active := len(b.regions) != 0
	b.mu.Unlock()
	if active {
		if _, err := s.SubmitRange(context.Background(), b, 0, len(data)); err != nil && !errors.Is(err, ErrInUse) {
			t.Fatal(err)
		}
	}
	if err := r.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
	if err := b.Release(); !errors.Is(err, ErrBufferOwned) {
		t.Fatal("double release accepted")
	}
	newLease, err := p.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.Bytes(); !errors.Is(err, ErrBufferOwned) {
		t.Fatal("old lease became valid again")
	}
	if err = newLease.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareHashReader(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 2, 65537)
	data := make([]byte, MiB+123)
	pattern(data, 0)
	got, n, err := e.HashReader(context.Background(), bytes.NewReader(data), p)
	if err != nil || n != int64(len(data)) || got != sha256.Sum256(data) {
		t.Fatalf("HashReader: %d %x %v", n, got, err)
	}
	got, n, err = e.HashReader(context.Background(), bytes.NewReader(nil), p)
	if err != nil || n != 0 || got != sha256.Sum256(nil) {
		t.Fatal("empty HashReader", err)
	}
}

func TestHardwareConcurrentStreams(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 3, 128*1024+19)
	var wg sync.WaitGroup
	for worker := 0; worker < 3; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			data := make([]byte, 512*1024+worker)
			pattern(data, worker)
			got, n, err := e.HashReader(context.Background(), bytes.NewReader(data), p)
			if err != nil || n != int64(len(data)) || got != sha256.Sum256(data) {
				t.Errorf("concurrent stream %d: %v", worker, err)
			}
		}(worker)
	}
	wg.Wait()
}

func TestHardwareClosedPool(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 64)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Acquire(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal("acquire after close")
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrNoProgress }

func TestHardwareReadErrorDrains(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 64)
	_, _, err := e.HashReader(context.Background(), failingReader{}, p)
	if !errors.Is(err, io.ErrNoProgress) {
		t.Fatal(err)
	}
	b := bufferForTest(t, p)
	if err = b.Release(); err != nil {
		t.Fatal(err)
	}
}

type blockedReader struct{ entered, unblock chan struct{} }

func (r *blockedReader) Read([]byte) (int, error) { close(r.entered); <-r.unblock; return 0, io.EOF }

func TestHardwareBlockedFillOwnership(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 64)
	b := bufferForTest(t, p)
	s := streamForTest(t, e)
	r := &blockedReader{entered: make(chan struct{}), unblock: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(r.unblock) }) }
	defer unblock()
	filled := make(chan error, 1)
	go func() { _, err := b.Fill(r); filled <- err }()
	<-r.entered
	if err := b.Release(); !errors.Is(err, ErrInUse) {
		t.Fatal("release during blocked Fill", err)
	}
	if _, err := s.SubmitRange(context.Background(), b, 0, 64); !errors.Is(err, ErrInUse) {
		t.Fatal("submit during Fill", err)
	}
	if err := s.Submit(context.Background(), b, 64); !errors.Is(err, ErrInUse) {
		t.Fatal("transfer during Fill", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Finish(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled Finish", err)
	}
	unblock()
	if err := <-filled; !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	copy(data, "abc")
	if _, err := s.SubmitRange(context.Background(), b, 0, 3); err != nil {
		t.Fatal(err)
	}
	got, err := s.Finish(context.Background())
	if err != nil || got != sha256.Sum256([]byte("abc")) {
		t.Fatal("Finish retry after cancellation", err)
	}
}

func cancellationStreamForTest(t *testing.T, e *Engine) *Stream {
	t.Helper()
	s, err := e.NewSHA256(StreamOptions{RequestBytes: 4 * MiB, QueueDepth: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil && !errors.Is(err, context.Canceled) {
			t.Error(err)
		}
	})
	return s
}

func finishCanceledForTest(t *testing.T, s *Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := s.Finish(ctx)
	if !errors.Is(err, context.Canceled) || got != ([32]byte{}) {
		t.Fatalf("canceled Finish returned digest %x and error %v", got, err)
	}
}

// A successful CPA submission is observed through native counters, rather than
// inferred from a queued Go job or a sleep. The long poll interval leaves a
// window after submission and before callback delivery. Hardware may already
// have finished during that window; its memory is still owned by CPA until the
// callback is delivered. Retry if scheduling hides the first-request window.
func firstPendingCancellationStream(t *testing.T, e *Engine, b *Buffer, bytes int) (*Stream, *Submission) {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		s := cancellationStreamForTest(t, e)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		r, err := s.SubmitRange(ctx, b, 0, bytes)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			progress := s.Progress()
			if progress.Submitted == 1 && progress.Completed == 0 {
				t.Logf("observed native request accepted with callback pending: %+v", progress)
				return s, r
			}
			if progress.Submitted > 1 || progress.Completed > 0 {
				break
			}
			time.Sleep(100 * time.Microsecond)
		}
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		_, err = s.Finish(ctx)
		cancel()
		if err != nil {
			t.Fatal("draining unobserved request window", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("could not observe the first accepted request before callback delivery")
	return nil, nil
}

func TestHardwareCancelBeforeWork(t *testing.T) {
	e := openHardware(t, 0)
	p := poolForTest(t, e, 1, 64)
	b := bufferForTest(t, p)
	s := cancellationStreamForTest(t, e)
	s.Cancel()
	s.Cancel() // Idempotent, including before any hardware work exists.
	if err := s.Submit(context.Background(), b, 64); err == nil {
		t.Fatal("canceled stream accepted a whole buffer")
	}
	if _, err := s.SubmitRange(context.Background(), b, 0, 64); err == nil {
		t.Fatal("canceled stream accepted a range")
	}
	if _, err := b.Bytes(); err != nil {
		t.Fatal("rejected submissions changed lease ownership", err)
	}
	finishCanceledForTest(t, s)
	if progress := s.Progress(); progress.Submitted != 0 || progress.Completed != 0 {
		t.Fatalf("pre-work cancellation submitted hardware work: %+v", progress)
	}
	if err := s.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal("first canceled Close", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("repeated canceled Close", err)
	}
	if err := b.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareCancelAcceptedRequest(t *testing.T) {
	// The first native poll normally runs before a 4 MiB hash can complete;
	// a 250 ms interval then makes the accepted/pending state observable.
	// Use a separate engine with the long interval, rather than a test-only
	// device reset or an artificial completion callback.
	e := openHardware(t, 250*time.Millisecond)
	p := poolForTest(t, e, 1, 16*MiB)
	b := bufferForTest(t, p)
	data, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pattern(data, 0)
	s, r := firstPendingCancellationStream(t, e, b, 16*MiB)
	s.Cancel()
	if progress := s.Progress(); progress.Submitted != 1 || progress.Completed != 0 {
		t.Fatalf("first request was no longer pending immediately after cancellation: %+v", progress)
	}
	if err := b.Release(); !errors.Is(err, ErrInUse) {
		t.Fatal("cancellation released memory before the pending callback", err)
	}
	if err := p.Close(); !errors.Is(err, ErrInUse) {
		t.Fatal("pool closed before the pending callback", err)
	}
	waitCtx, stopWaiting := context.WithCancel(context.Background())
	stopWaiting()
	if err := r.Wait(waitCtx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled completion wait", err)
	}
	if err := b.Release(); !errors.Is(err, ErrInUse) {
		t.Fatal("canceling the wait released pending DMA memory", err)
	}
	finishCanceledForTest(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("accepted range did not finish canceled", err)
	}
	if progress := s.Progress(); progress.Submitted != 1 || progress.Completed != 1 {
		t.Fatalf("cancellation submitted additional partial/final requests: %+v", progress)
	}
	if err := s.Close(); !errors.Is(err, context.Canceled) {
		t.Fatal("close canceled session after callback", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("repeated canceled Close", err)
	}
	if err := b.Release(); err != nil {
		t.Fatal("release after canceled operation drained", err)
	}
	reused := bufferForTest(t, p)
	data, err = reused.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pattern(data, 101)
	want := sha256.Sum256(data)
	fresh := streamForTest(t, e)
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fresh.SubmitRange(ctx, reused, 0, len(data)); err != nil {
		t.Fatal(err)
	}
	got, err := fresh.Finish(ctx)
	if err != nil || got != want {
		t.Fatalf("reused buffer hash after cancellation: %x, %v", got, err)
	}
}

func TestHardwareCancelUnblocksQueuedProducer(t *testing.T) {
	e := openHardware(t, 250*time.Millisecond)
	p := poolForTest(t, e, 1, 16*MiB)
	b := bufferForTest(t, p)
	data, _ := b.Bytes()
	pattern(data, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, first := firstPendingCancellationStream(t, e, b, 4*MiB)
	second, err := s.SubmitRange(ctx, b, 4*MiB, 4*MiB)
	if err != nil {
		t.Fatal(err)
	}
	produced := make(chan error, 1)
	go func() {
		_, err := s.SubmitRange(ctx, b, 8*MiB, 4*MiB)
		produced <- err
	}()
	deadline := time.Now().Add(100 * time.Millisecond)
	for len(s.operation) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("producer did not enter the submission gate")
		}
		time.Sleep(100 * time.Microsecond)
	}
	if len(s.jobs) != 1 {
		t.Fatal("test producer was not waiting on a full queue")
	}
	canceled := make(chan struct{})
	go func() { s.Cancel(); close(canceled) }()
	select {
	case <-canceled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Cancel blocked behind the queued producer or hardware completion")
	}
	select {
	case err := <-produced:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("queued producer was not canceled", err)
		}
	case <-ctx.Done():
		t.Fatal("queued producer stayed blocked after cancellation")
	}
	finishCanceledForTest(t, s)
	for _, r := range []*Submission{first, second} {
		if err := r.Wait(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal("range did not complete canceled", err)
		}
	}
	if progress := s.Progress(); progress.Submitted != 1 || progress.Completed != 1 {
		t.Fatalf("queued work reached hardware after cancellation: %+v", progress)
	}
	if err := b.Release(); err != nil {
		t.Fatal("queued producer left a reserved region behind", err)
	}
}
