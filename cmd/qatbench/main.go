// qatbench measures SHA-256 of one contiguous DMA-backed application buffer.
// Run with the legacy QAT drivers loaded and permission to use their devices.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"syscall"
	"time"

	qat "github.com/undy-io/qatgo"
)

const mib = 1024 * 1024

type options struct {
	bytes, iterations, warmup, request, allocation, buffers, pollUS, instance int
	receiveChunk                                                              int
	rateMiB                                                                   float64
	tune, serial                                                              bool
	jsonPath                                                                  string
}

type config struct {
	RequestBytes    int `json:"request_bytes"`
	AllocationBytes int `json:"allocation_bytes"`
	PollUS          int `json:"poll_us"`
	ReceiveChunk    int `json:"receive_chunk_bytes,omitempty"`
}

type sample struct {
	WallMS float64 `json:"wall_ms"`
	CPUMS  float64 `json:"process_cpu_ms"`
}

type result struct {
	MeanMS       float64  `json:"mean_ms"`
	MedianMS     float64  `json:"median_ms"`
	MinMS        float64  `json:"min_ms"`
	MaxMS        float64  `json:"max_ms"`
	MeanCPUMS    float64  `json:"mean_process_cpu_ms"`
	MiBPerSecond float64  `json:"mib_per_second"`
	Samples      []sample `json:"samples"`
}

type measurement struct {
	Config              config   `json:"config"`
	Device              qat.Info `json:"device"`
	ContiguousBytes     int      `json:"contiguous_bytes_per_buffer"`
	PoolBuffers         int      `json:"pool_buffers"`
	CPU                 result   `json:"cpu_go_sha256"`
	QAT                 result   `json:"qat_resident"`
	QATSpeedup          float64  `json:"qat_resident_speedup_vs_cpu"`
	ReceiveCPU          *result  `json:"simulated_receive_cpu,omitempty"`
	ReceiveQAT          *result  `json:"simulated_receive_qat,omitempty"`
	ReceiveSpeedup      float64  `json:"simulated_receive_qat_speedup_vs_cpu,omitempty"`
	ReceiveRangeCount   int      `json:"receive_ranges_per_blob,omitempty"`
	EffectiveRequestMax int      `json:"effective_request_max_bytes"`
}

type report struct {
	Version      int           `json:"schema_version"`
	Generated    time.Time     `json:"generated_utc"`
	GoVersion    string        `json:"go_version"`
	Bytes        int           `json:"blob_bytes"`
	Iterations   int           `json:"iterations"`
	Warmup       int           `json:"warmup"`
	RateMiB      float64       `json:"simulated_receive_rate_mib_per_second"`
	Serial       bool          `json:"serial_receive_control"`
	Digest       string        `json:"sha256"`
	Verified     bool          `json:"all_digests_verified"`
	Notes        []string      `json:"measurement_notes"`
	Measurements []measurement `json:"measurements"`
	BestResident int           `json:"best_resident_measurement_index"`
	BestReceive  *int          `json:"best_receive_measurement_index,omitempty"`
}

func parseOptions() (options, error) {
	o := options{}
	flag.IntVar(&o.bytes, "bytes", 256*mib, "bytes in each contiguous application buffer")
	flag.IntVar(&o.iterations, "iterations", 3, "measured hashes per backend/configuration")
	flag.IntVar(&o.warmup, "warmup", 1, "untimed hashes per backend/configuration")
	flag.IntVar(&o.request, "request", qat.DefaultRequestBytes, "maximum QAT request bytes (multiple of 64, up to 4 MiB)")
	flag.IntVar(&o.allocation, "allocation", qat.DefaultAllocationBytes, "physical allocation bytes: 2 MiB or 4 MiB")
	flag.IntVar(&o.buffers, "buffers", 2, "number of full-size contiguous buffers in the reusable pool")
	flag.IntVar(&o.pollUS, "poll-us", int(qat.DefaultPollInterval/time.Microsecond), "delay after unsuccessful native polling, in microseconds; 0 busy polls")
	flag.IntVar(&o.instance, "instance", 0, "legacy QAT crypto instance")
	flag.IntVar(&o.receiveChunk, "receive-chunk", 0, "simulate receiving this many bytes per range; 0 disables receive mode")
	flag.Float64Var(&o.rateMiB, "rate-mib", 0, "simulated receive rate in MiB/s; 0 is unpaced")
	flag.BoolVar(&o.serial, "serial", false, "wait for each received range before producing the next (overlap control)")
	flag.BoolVar(&o.tune, "tune", false, "test a staged request/allocation/poll/receive-chunk shortlist")
	flag.StringVar(&o.jsonPath, "json", "", "write machine-readable settings, raw samples and summaries to this file")
	flag.Parse()
	if flag.NArg() != 0 {
		return o, fmt.Errorf("unexpected positional arguments: %v", flag.Args())
	}
	if o.bytes <= 0 || uint64(o.bytes) > qat.MaxStreamBytes {
		return o, fmt.Errorf("-bytes must be positive and at most %d", qat.MaxStreamBytes)
	}
	if o.iterations < 1 || o.warmup < 0 || o.iterations > 100000 || o.warmup > 100000 {
		return o, errors.New("-iterations must be 1..100000 and -warmup 0..100000")
	}
	if o.request < 64 || o.request > 4*mib || o.request%64 != 0 {
		return o, errors.New("-request must be a multiple of 64 between 64 and 4194304")
	}
	if o.allocation != 2*mib && o.allocation != 4*mib {
		return o, errors.New("-allocation must be 2097152 or 4194304")
	}
	if o.buffers < 1 || o.buffers > 1024 || o.pollUS < 0 || o.pollUS > 1000000 || o.instance < 0 {
		return o, errors.New("invalid -buffers, -poll-us, or -instance")
	}
	if o.receiveChunk < 0 || o.rateMiB < 0 || math.IsNaN(o.rateMiB) || math.IsInf(o.rateMiB, 0) {
		return o, errors.New("-receive-chunk and -rate-mib must be nonnegative finite values")
	}
	if o.rateMiB > 0 && o.receiveChunk == 0 {
		o.receiveChunk = qat.DefaultReceiveBytes
	}
	if o.receiveChunk > o.bytes {
		o.receiveChunk = o.bytes
	}
	if o.rateMiB > 0 && float64(o.bytes)/(o.rateMiB*mib) > float64(math.MaxInt64)/float64(time.Second) {
		return o, errors.New("simulated receive duration exceeds time.Duration range")
	}
	return o, nil
}

func processCPU() (time.Duration, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond, nil
}

func timed(f func() ([32]byte, error)) (sample, [32]byte, error) {
	cpuStart, err := processCPU()
	if err != nil {
		return sample{}, [32]byte{}, err
	}
	start := time.Now()
	sum, err := f()
	elapsed := time.Since(start)
	cpuEnd, cpuErr := processCPU()
	return sample{WallMS: float64(elapsed) / float64(time.Millisecond),
		CPUMS: float64(cpuEnd-cpuStart) / float64(time.Millisecond)}, sum, errors.Join(err, cpuErr)
}

// A small deterministic repeating pattern keeps receive simulation independent
// of random-number generation. SHA-256's work is independent of these values.
var pattern = func() []byte {
	p := make([]byte, 4096)
	for i := range p {
		p[i] = byte((i*131 + 17) ^ (i >> 5))
	}
	return p
}()

func fillRange(dst []byte, absoluteOffset int) {
	if len(dst) == 0 {
		return
	}
	first := copy(dst, pattern[absoluteOffset%len(pattern):])
	if first == len(dst) {
		return
	}
	n := first + copy(dst[first:], pattern)
	// Repeated doubling is a cheap synthetic receive write, not an RNG.
	for n < len(dst) {
		n += copy(dst[n:], dst[first:n])
	}
}

func initializePool(ctx context.Context, p *qat.Pool, count, bytes int) (sum [32]byte, err error) {
	leases := make([]*qat.Buffer, 0, count)
	defer func() {
		for _, b := range leases {
			err = errors.Join(err, b.Release())
		}
	}()
	for i := 0; i < count; i++ {
		b, e := p.Acquire(ctx)
		if e != nil {
			return sum, e
		}
		leases = append(leases, b)
		data, e := b.Bytes()
		if e != nil {
			return sum, e
		}
		if len(data) != bytes || cap(data) != bytes {
			return sum, fmt.Errorf("pool buffer is not one full %d-byte slice: len=%d cap=%d", bytes, len(data), cap(data))
		}
		fillRange(data, 0)
		if i == 0 {
			sum = sha256.Sum256(data)
		}
	}
	return sum, nil
}

func cpuResident(ctx context.Context, p *qat.Pool) (s sample, sum [32]byte, err error) {
	b, err := p.Acquire(ctx)
	if err != nil {
		return s, sum, err
	}
	defer func() { err = errors.Join(err, b.Release()) }()
	data, err := b.Bytes()
	if err != nil {
		return s, sum, err
	}
	return timed(func() ([32]byte, error) { return sha256.Sum256(data), nil })
}

func qatResident(ctx context.Context, e *qat.Engine, p *qat.Pool, bytes, request int) (s sample, sum [32]byte, err error) {
	b, err := p.Acquire(ctx)
	if err != nil {
		return s, sum, err
	}
	owned := true
	defer func() {
		if owned {
			err = errors.Join(err, b.Release())
		}
	}()
	stream, err := e.NewSHA256(qat.StreamOptions{RequestBytes: request, QueueDepth: 2})
	if err != nil {
		return s, sum, err
	}
	defer func() { err = errors.Join(err, stream.Close()) }()
	return timed(func() ([32]byte, error) {
		if err := stream.Submit(ctx, b, bytes); err != nil {
			return [32]byte{}, err
		}
		owned = false
		return stream.Finish(ctx)
	})
}

func paceReceive(start time.Time, received int, rateMiB float64) {
	if rateMiB == 0 {
		return
	}
	target := time.Duration(float64(received) / (rateMiB * mib) * float64(time.Second))
	if remaining := target - time.Since(start); remaining > 0 {
		time.Sleep(remaining)
	}
}

func receiveCPU(ctx context.Context, p *qat.Pool, o options, chunk int) (s sample, sum [32]byte, err error) {
	b, err := p.Acquire(ctx)
	if err != nil {
		return s, sum, err
	}
	defer func() { err = errors.Join(err, b.Release()) }()
	data, err := b.Bytes()
	if err != nil {
		return s, sum, err
	}
	return timed(func() ([32]byte, error) {
		h := sha256.New()
		start := time.Now()
		for offset := 0; offset < len(data); {
			n := min(chunk, len(data)-offset)
			paceReceive(start, offset+n, o.rateMiB)
			fillRange(data[offset:offset+n], offset)
			_, _ = h.Write(data[offset : offset+n])
			offset += n
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		return digest, nil
	})
}

func receiveQAT(ctx context.Context, e *qat.Engine, p *qat.Pool, o options, c config) (s sample, sum [32]byte, err error) {
	b, err := p.Acquire(ctx)
	if err != nil {
		return s, sum, err
	}
	// Close first drains all submitted ranges, then the caller returns its lease.
	defer func() { err = errors.Join(err, b.Release()) }()
	data, err := b.Bytes()
	if err != nil {
		return s, sum, err
	}
	stream, err := e.NewSHA256(qat.StreamOptions{RequestBytes: c.RequestBytes, QueueDepth: 2})
	if err != nil {
		return s, sum, err
	}
	defer func() { err = errors.Join(err, stream.Close()) }()
	return timed(func() ([32]byte, error) {
		start := time.Now()
		for offset := 0; offset < len(data); {
			n := min(c.ReceiveChunk, len(data)-offset)
			paceReceive(start, offset+n, o.rateMiB)
			// Earlier ranges belong to the card until completion. Only this
			// previously unsubmitted suffix is written by the producer.
			fillRange(data[offset:offset+n], offset)
			_, err := stream.SubmitRange(ctx, b, offset, n)
			if err != nil {
				return [32]byte{}, err
			}
			if o.serial {
				if err := stream.Flush(ctx); err != nil {
					return [32]byte{}, err
				}
			}
			offset += n
		}
		return stream.Finish(ctx)
	})
}

func summarize(samples []sample, bytes int) result {
	r := result{Samples: samples}
	ordered := make([]float64, len(samples))
	for i, s := range samples {
		r.MeanMS += s.WallMS / float64(len(samples))
		r.MeanCPUMS += s.CPUMS / float64(len(samples))
		ordered[i] = s.WallMS
	}
	sort.Float64s(ordered)
	r.MinMS, r.MaxMS = ordered[0], ordered[len(ordered)-1]
	r.MedianMS = (ordered[(len(ordered)-1)/2] + ordered[len(ordered)/2]) / 2
	r.MiBPerSecond = float64(bytes) / mib / (r.MeanMS / 1000)
	return r
}

func runConfig(ctx context.Context, o options, c config, expected *[32]byte) (m measurement, err error) {
	e, err := qat.Open(qat.Options{Instance: o.instance, PollInterval: time.Duration(c.PollUS) * time.Microsecond})
	if err != nil {
		return m, err
	}
	defer func() { err = errors.Join(err, e.Close()) }()
	p, err := e.NewPoolWithOptions(qat.PoolOptions{Count: o.buffers, BufferBytes: o.bytes, AllocationBytes: c.AllocationBytes})
	if err != nil {
		return m, err
	}
	defer func() { err = errors.Join(err, p.Close()) }()
	sum, err := initializePool(ctx, p, o.buffers, o.bytes)
	if err != nil {
		return m, err
	}
	if *expected == ([32]byte{}) {
		*expected = sum
	} else if sum != *expected {
		return m, errors.New("initialized pool data differs between configurations")
	}
	m = measurement{Config: c, Device: e.Info(), ContiguousBytes: o.bytes, PoolBuffers: o.buffers,
		EffectiveRequestMax: min(c.RequestBytes, c.AllocationBytes)}
	var cpuSamples, qatSamples, receiveCPUSamples, receiveQATSamples []sample
	for round := 0; round < o.warmup+o.iterations; round++ {
		// Rotate CPU/card order across rounds instead of consistently warming
		// the same path first. The full buffer is larger than typical CPU caches.
		for step := 0; step < 2; step++ {
			backend := (round + step) % 2
			var s sample
			var digest [32]byte
			if backend == 0 {
				s, digest, err = cpuResident(ctx, p)
			} else {
				s, digest, err = qatResident(ctx, e, p, o.bytes, c.RequestBytes)
			}
			if err != nil {
				return m, fmt.Errorf("resident backend %d, round %d: %w", backend, round, err)
			}
			if digest != *expected {
				return m, fmt.Errorf("resident backend %d digest mismatch, round %d", backend, round)
			}
			if round >= o.warmup {
				if backend == 0 {
					cpuSamples = append(cpuSamples, s)
				} else {
					qatSamples = append(qatSamples, s)
				}
			}
		}
		if c.ReceiveChunk == 0 {
			continue
		}
		for step := 0; step < 2; step++ {
			backend := (round + step) % 2
			var s sample
			var digest [32]byte
			if backend == 0 {
				s, digest, err = receiveCPU(ctx, p, o, c.ReceiveChunk)
			} else {
				s, digest, err = receiveQAT(ctx, e, p, o, c)
			}
			if err != nil {
				return m, fmt.Errorf("receive backend %d, round %d: %w", backend, round, err)
			}
			if digest != *expected {
				return m, fmt.Errorf("receive backend %d digest mismatch, round %d", backend, round)
			}
			if round >= o.warmup {
				if backend == 0 {
					receiveCPUSamples = append(receiveCPUSamples, s)
				} else {
					receiveQATSamples = append(receiveQATSamples, s)
				}
			}
		}
	}
	m.CPU, m.QAT = summarize(cpuSamples, o.bytes), summarize(qatSamples, o.bytes)
	m.QATSpeedup = m.CPU.MeanMS / m.QAT.MeanMS
	if c.ReceiveChunk > 0 {
		cpu, card := summarize(receiveCPUSamples, o.bytes), summarize(receiveQATSamples, o.bytes)
		m.ReceiveCPU, m.ReceiveQAT = &cpu, &card
		m.ReceiveSpeedup = cpu.MeanMS / card.MeanMS
		m.ReceiveRangeCount = (o.bytes-1)/c.ReceiveChunk + 1
	}
	return m, nil
}

func printResult(index int, m measurement) {
	fmt.Printf("[%d] request=%d allocation=%d poll=%dus; PCI=%s NUMA=%d; one contiguous %d-byte slice per lease\n",
		index, m.Config.RequestBytes, m.Config.AllocationBytes, m.Config.PollUS, m.Device.PCI, m.Device.NUMANode, m.ContiguousBytes)
	fmt.Printf("    Go SHA256: %8.3f ms, %9.2f MiB/s, process CPU %8.3f ms/blob\n", m.CPU.MeanMS, m.CPU.MiBPerSecond, m.CPU.MeanCPUMS)
	fmt.Printf("    QAT ready: %8.3f ms, %9.2f MiB/s, process CPU %8.3f ms/blob; %.3fx CPU throughput\n", m.QAT.MeanMS, m.QAT.MiBPerSecond, m.QAT.MeanCPUMS, m.QATSpeedup)
	if m.ReceiveQAT != nil {
		fmt.Printf("    Receive %d-byte ranges (%d/blob): CPU %8.3f ms (%8.3f CPU ms), QAT %8.3f ms (%8.3f CPU ms); %.3fx\n",
			m.Config.ReceiveChunk, m.ReceiveRangeCount, m.ReceiveCPU.MeanMS, m.ReceiveCPU.MeanCPUMS,
			m.ReceiveQAT.MeanMS, m.ReceiveQAT.MeanCPUMS, m.ReceiveSpeedup)
	}
}

func writeJSON(path string, r report) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0644)
}

func run() error {
	o, err := parseOptions()
	if err != nil {
		return err
	}
	fmt.Printf("SHA256 of %d bytes (%.6f MiB); %d full-size pooled buffers; %d measured + %d warmup per backend/config\n",
		o.bytes, float64(o.bytes)/mib, o.buffers, o.iterations, o.warmup)
	fmt.Println("CPU = Go crypto/sha256 with its normal CPU acceleration. QAT = direct CPA, no software fallback.")
	fmt.Println("Resident times include Submit+Finish; allocation, filling, session creation and digest checks are outside those times.")
	fmt.Println("CPU times are whole-process user+system time, including native worker threads; this program does not set affinity (external taskset can restrict CPUs).")
	if o.receiveChunk > 0 || o.tune {
		fmt.Printf("Receive simulation writes successive disjoint ranges of one full-size slice; rate %.3f MiB/s (0=unpaced), serial=%v.\n", o.rateMiB, o.serial)
		fmt.Println("Receive times include synthetic writes, pacing, submission and final digest; they are not network measurements.")
	}
	r := report{Version: 1, Generated: time.Now().UTC(), GoVersion: runtime.Version(), Bytes: o.bytes,
		Iterations: o.iterations, Warmup: o.warmup, RateMiB: o.rateMiB, Serial: o.serial,
		Notes: []string{
			"Every lease exposes one contiguous C-allocated DMA-backed byte slice of blob_bytes; physical allocations can be disjoint.",
			"Resident wall time includes Submit and Finish; allocation, deterministic fill, session creation and verification are excluded.",
			"CPU uses Go crypto/sha256 and its normal CPU instruction acceleration; no QAT fallback is used.",
			"Process CPU is getrusage(RUSAGE_SELF) user+system and includes native workers and Go runtime activity.",
			"Receive simulation writes into successive disjoint ranges of the same full-blob lease; submitted prefixes are not modified while QAT reads them.",
			"Receive timings include pacing and synthetic writes; rate=0 means unpaced. CPU receive control hashes each received range synchronously.",
			"The tuning shortlist is staged, not an exhaustive parameter search; fastest means fastest measured in this run.",
		}}
	ctx := context.Background()
	var expected [32]byte
	seen := make(map[config]bool)
	measure := func(c config) error {
		if seen[c] {
			return nil
		}
		seen[c] = true
		m, err := runConfig(ctx, o, c, &expected)
		if err != nil {
			return fmt.Errorf("request=%d allocation=%d poll=%d receive=%d: %w", c.RequestBytes, c.AllocationBytes, c.PollUS, c.ReceiveChunk, err)
		}
		i := len(r.Measurements)
		r.Measurements = append(r.Measurements, m)
		if i == 0 || m.QAT.MeanMS < r.Measurements[r.BestResident].QAT.MeanMS {
			r.BestResident = i
		}
		if m.ReceiveQAT != nil && (r.BestReceive == nil || m.ReceiveQAT.MeanMS < r.Measurements[*r.BestReceive].ReceiveQAT.MeanMS) {
			best := i
			r.BestReceive = &best
		}
		printResult(i, m)
		return nil
	}
	base := config{RequestBytes: o.request, AllocationBytes: o.allocation, PollUS: o.pollUS, ReceiveChunk: o.receiveChunk}
	if !o.tune {
		if err := measure(base); err != nil {
			return err
		}
	} else {
		// First compare request size without adding a poll delay. A 4 MiB
		// request needs 4 MiB physical allocations to avoid a 2 MiB boundary.
		for _, request := range []int{64 * 1024, 256 * 1024, mib, 2 * mib, 4 * mib} {
			allocation := 2 * mib
			if request > allocation {
				allocation = 4 * mib
			}
			if err := measure(config{RequestBytes: request, AllocationBytes: allocation}); err != nil {
				return err
			}
		}
		best := r.Measurements[r.BestResident].Config
		for _, allocation := range []int{2 * mib, 4 * mib} {
			c := best
			c.AllocationBytes = allocation
			if err := measure(c); err != nil {
				return err
			}
		}
		best = r.Measurements[r.BestResident].Config
		for _, poll := range []int{50, 250} {
			c := best
			c.PollUS = poll
			if err := measure(c); err != nil {
				return err
			}
		}
		best = r.Measurements[r.BestResident].Config
		for _, chunk := range []int{64 * 1024, 256 * 1024, mib, 4 * mib, 16 * mib} {
			c := best
			c.ReceiveChunk = min(chunk, o.bytes)
			if err := measure(c); err != nil {
				return err
			}
		}
		// Also honor any explicitly supplied combination outside the shortlist.
		if o.receiveChunk > 0 || o.request != mib || o.allocation != 2*mib || o.pollUS != 0 {
			if err := measure(base); err != nil {
				return err
			}
		}
	}
	r.Digest = hex.EncodeToString(expected[:])
	r.Verified = true
	fmt.Printf("SHA256: %s; every warmup and measured digest matched.\n", r.Digest)
	best := r.Measurements[r.BestResident]
	fmt.Printf("Fastest tested resident: [%d] request=%d allocation=%d poll=%dus: %.3f ms, %.2f MiB/s, %.3fx CPU throughput.\n",
		r.BestResident, best.Config.RequestBytes, best.Config.AllocationBytes, best.Config.PollUS,
		best.QAT.MeanMS, best.QAT.MiBPerSecond, best.QATSpeedup)
	if r.BestReceive != nil {
		best := r.Measurements[*r.BestReceive]
		fmt.Printf("Fastest tested simulated receive: [%d] chunk=%d: %.3f ms, %.2f MiB/s, process CPU %.3f ms/blob.\n",
			*r.BestReceive, best.Config.ReceiveChunk, best.ReceiveQAT.MeanMS, best.ReceiveQAT.MiBPerSecond, best.ReceiveQAT.MeanCPUMS)
	}
	if o.jsonPath != "" {
		if err := writeJSON(o.jsonPath, r); err != nil {
			return err
		}
		fmt.Printf("JSON: %s\n", o.jsonPath)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qatbench:", err)
		os.Exit(1)
	}
}
