// qatalloc compares retaining one DMA buffer with allocating and freeing it
// for each blob. Engine initialization stays outside both measurements.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	qat "github.com/undy-io/qatgo"
)

type sample struct {
	AllocMS float64 `json:"alloc_ms"`
	FreeMS  float64 `json:"free_ms"`
	LeaseMS float64 `json:"lease_ms"`
	FillMS  float64 `json:"fill_ms"`
	HashMS  float64 `json:"hash_ms"`
	TotalMS float64 `json:"total_ms"`
}

type report struct {
	GeneratedUTC      time.Time `json:"generated_utc"`
	GoVersion         string    `json:"go_version"`
	Device            qat.Info  `json:"device"`
	Bytes             int       `json:"blob_bytes"`
	AllocationBytes   int       `json:"allocation_bytes"`
	RequestBytes      int       `json:"request_bytes"`
	PollUS            int       `json:"poll_us"`
	Warmup            int       `json:"warmup_rounds"`
	Iterations        int       `json:"measured_rounds"`
	SHA256            string    `json:"sha256"`
	Verified          bool      `json:"all_digests_verified"`
	FirstFresh        sample    `json:"first_fresh_after_engine_open"`
	ReusePoolAllocMS  float64   `json:"reused_pool_one_time_alloc_ms"`
	ReusePoolFreeMS   float64   `json:"reused_pool_one_time_free_ms"`
	ReuseMean         sample    `json:"reuse_mean"`
	FreshMean         sample    `json:"fresh_mean"`
	ReuseSamples      []sample  `json:"reuse_samples"`
	FreshSamples      []sample  `json:"fresh_samples"`
	FreshMinusReuseMS float64   `json:"fresh_minus_reuse_mean_total_ms"`
	Notes             []string  `json:"measurement_notes"`
}

var pattern = func() []byte {
	p := make([]byte, 4096)
	for i := range p {
		p[i] = byte((i*131 + 17) ^ (i >> 5))
	}
	return p
}()

func milliseconds(start time.Time) float64 {
	return float64(time.Since(start)) / float64(time.Millisecond)
}

func fill(dst []byte) {
	n := copy(dst, pattern)
	for n < len(dst) {
		n += copy(dst[n:], dst[:n])
	}
}

// The CPU reference uses only the small repeating pattern. It runs once,
// before opening the engine, outside every measured interval.
func reference(bytes int) [32]byte {
	h := sha256.New()
	for left := bytes; left > 0; {
		n := min(left, len(pattern))
		_, _ = h.Write(pattern[:n])
		left -= n
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func measure(e *qat.Engine, p *qat.Pool, o qat.PoolOptions, want [32]byte) (s sample, err error) {
	fresh := p == nil
	var b *qat.Buffer
	var stream *qat.Stream
	// Cleanup order is significant: Close must drain hardware work before
	// Release or Pool.Close can succeed. A hardware error never bypasses this.
	defer func() {
		if stream != nil {
			err = errors.Join(err, stream.Close())
		}
		if b != nil {
			err = errors.Join(err, b.Release())
		}
		if fresh && p != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	totalStart := time.Now()
	start := time.Now()
	if fresh {
		p, err = e.NewPoolWithOptions(o)
		s.AllocMS = milliseconds(start)
		if err != nil {
			return s, err
		}
	}
	start = time.Now()
	b, err = p.Acquire(context.Background())
	if err != nil {
		return s, err
	}
	data, err := b.Bytes()
	if err != nil {
		return s, err
	}
	s.LeaseMS = milliseconds(start)
	start = time.Now()
	fill(data)
	s.FillMS = milliseconds(start)
	start = time.Now()
	stream, err = e.NewSHA256()
	if err != nil {
		return s, err
	}
	if _, err = stream.SubmitRange(context.Background(), b, 0, len(data)); err != nil {
		return s, err
	}
	sum, err := stream.Finish(context.Background())
	if err != nil {
		return s, err
	}
	if err = stream.Close(); err != nil {
		return s, err
	}
	stream = nil
	s.HashMS = milliseconds(start)
	start = time.Now()
	if err = b.Release(); err != nil {
		return s, err
	}
	b = nil
	s.LeaseMS += milliseconds(start)
	if fresh {
		start = time.Now()
		if err = p.Close(); err != nil {
			return s, err
		}
		p = nil
		s.FreeMS = milliseconds(start)
	}
	s.TotalMS = milliseconds(totalStart)
	if sum != want {
		return s, fmt.Errorf("SHA256 mismatch: got %x want %x", sum, want)
	}
	return s, nil
}

func mean(samples []sample) (m sample) {
	for _, s := range samples {
		m.AllocMS += s.AllocMS
		m.FreeMS += s.FreeMS
		m.LeaseMS += s.LeaseMS
		m.FillMS += s.FillMS
		m.HashMS += s.HashMS
		m.TotalMS += s.TotalMS
	}
	n := float64(len(samples))
	m.AllocMS /= n
	m.FreeMS /= n
	m.LeaseMS /= n
	m.FillMS /= n
	m.HashMS /= n
	m.TotalMS /= n
	return m
}

func run() (err error) {
	bytes := flag.Int("bytes", 256*qat.MiB, "bytes per contiguous DMA-backed blob")
	iterations := flag.Int("iterations", 5, "measured rounds, each containing reuse and fresh allocation")
	warmup := flag.Int("warmup", 1, "unmeasured rounds before measured rounds")
	allocation := flag.Int("allocation", qat.DefaultAllocationBytes, "physical allocation bytes: 2097152 or 4194304")
	pollUS := flag.Int("poll-us", int(qat.DefaultPollInterval/time.Microsecond), "native poll delay in microseconds; 0 busy polls")
	jsonPath := flag.String("json", "", "write settings, raw samples and mean times as JSON")
	flag.Parse()
	if flag.NArg() != 0 || *bytes <= 0 || uint64(*bytes) > qat.MaxStreamBytes ||
		*iterations < 1 || *iterations > 100000 || *warmup < 0 || *warmup > 100000 ||
		(*allocation != 2*qat.MiB && *allocation != 4*qat.MiB) || *pollUS < 0 || *pollUS > 1000000 {
		return errors.New("invalid arguments; see -help")
	}
	want := reference(*bytes)
	e, err := qat.Open(qat.Options{PollInterval: time.Duration(*pollUS) * time.Microsecond})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	o := qat.PoolOptions{Count: 1, BufferBytes: *bytes, AllocationBytes: *allocation}
	r := report{GeneratedUTC: time.Now().UTC(), GoVersion: runtime.Version(), Device: e.Info(),
		Bytes: *bytes, AllocationBytes: *allocation, RequestBytes: qat.DefaultRequestBytes,
		PollUS: *pollUS, Warmup: *warmup, Iterations: *iterations, SHA256: hex.EncodeToString(want[:]),
		Notes: []string{
			"Engine initialization and shutdown are excluded. Each hash includes a new SHA256 session, submission, completion and session close.",
			"Fresh creates one pool and its DMA allocations/alias mapping, then destroys that pool including native qaeMemFreeNUMA cleanup and unmapping.",
			"Reuse retains one pool; its one-time allocation/free are reported separately. Lease includes Acquire, Bytes and Release.",
			"The first fresh sample is the first pool after engine open, not a cold boot or flushed kernel/USDM cache. It is excluded from measured means.",
			"Fresh and reuse order alternates by round. Warmups are excluded. Total is directly timed, not a sum of phase means.",
			"Fill is a deterministic synthetic memory write, not network or disk I/O. CPU SHA256 reference and digest comparisons are outside sample timing.",
			"At most two full-size DMA buffers coexist: the retained pool and the current fresh pool; allocation rounding and native metadata add overhead.",
		}}
	if r.FirstFresh, err = measure(e, nil, o, want); err != nil {
		return fmt.Errorf("first fresh: %w", err)
	}
	start := time.Now()
	p, err := e.NewPoolWithOptions(o)
	r.ReusePoolAllocMS = milliseconds(start)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	for round := 0; round < *warmup+*iterations; round++ {
		for position := 0; position < 2; position++ {
			fresh := (round+position)%2 == 1
			pool := p
			if fresh {
				pool = nil
			}
			s, measureErr := measure(e, pool, o, want)
			if measureErr != nil {
				return fmt.Errorf("round %d fresh=%t: %w", round, fresh, measureErr)
			}
			if round >= *warmup {
				if fresh {
					r.FreshSamples = append(r.FreshSamples, s)
				} else {
					r.ReuseSamples = append(r.ReuseSamples, s)
				}
			}
		}
	}
	start = time.Now()
	if err = p.Close(); err != nil {
		return err
	}
	r.ReusePoolFreeMS = milliseconds(start)
	r.ReuseMean, r.FreshMean = mean(r.ReuseSamples), mean(r.FreshSamples)
	r.FreshMinusReuseMS = r.FreshMean.TotalMS - r.ReuseMean.TotalMS
	r.Verified = true
	fmt.Printf("%d-byte blobs, %d measured rounds; engine kept initialized\n", *bytes, *iterations)
	fmt.Printf("First pool after engine open: alloc %.3f ms, free %.3f ms (excluded from means)\n", r.FirstFresh.AllocMS, r.FirstFresh.FreeMS)
	fmt.Printf("Retained pool one-time costs: alloc %.3f ms, free %.3f ms\n", r.ReusePoolAllocMS, r.ReusePoolFreeMS)
	fmt.Printf("%-12s %10s %10s %10s %10s %10s %10s\n", "Mean ms", "Alloc", "Free", "Lease", "Fill", "Hash", "Total")
	for _, row := range []struct {
		name string
		s    sample
	}{{"Reuse", r.ReuseMean}, {"Fresh", r.FreshMean}} {
		fmt.Printf("%-12s %10.3f %10.3f %10.3f %10.3f %10.3f %10.3f\n", row.name, row.s.AllocMS, row.s.FreeMS, row.s.LeaseMS, row.s.FillMS, row.s.HashMS, row.s.TotalMS)
	}
	fmt.Printf("Fresh minus reuse total: %.3f ms/blob (%+.2f%%); every digest matched Go SHA256.\n", r.FreshMinusReuseMS, 100*r.FreshMinusReuseMS/r.ReuseMean.TotalMS)
	if *jsonPath != "" {
		data, marshalErr := json.MarshalIndent(r, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		return os.WriteFile(*jsonPath, append(data, '\n'), 0644)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qatalloc:", err)
		os.Exit(1)
	}
}
