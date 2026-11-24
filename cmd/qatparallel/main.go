// qatparallel compares resident SHA256 throughput across independent QAT
// instances and CPU workers. Allocation and SHA256 session setup are untimed.
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
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	qat "github.com/undy-io/qatgo"
)

type preset struct {
	name      string
	instances []int
}

func presets() []preset {
	p := []preset{{"single", []int{0}}, {"shared3", []int{0, 0, 0}}}
	for _, n := range []int{2, 4, 8, 16} {
		x := preset{name: fmt.Sprintf("one%d", n)}
		for i := 0; i < n; i++ {
			x.instances = append(x.instances, i)
		}
		p = append(p, x)
	}
	for _, n := range []int{1, 2, 4, 8} {
		x := preset{name: fmt.Sprintf("three%d", n)}
		for _, base := range []int{0, 32, 64} {
			for i := 0; i < n; i++ {
				x.instances = append(x.instances, base+i)
			}
		}
		p = append(p, x)
	}
	return p
}

type options struct {
	bytes, iterations, warmup, pollUS, request int
	cpu                                        bool
	jsonPath                                   string
}

type batchSample struct {
	WallMS       float64   `json:"batch_wall_ms"`
	CPUMS        float64   `json:"process_cpu_ms"`
	CPUMSPerBlob float64   `json:"process_cpu_ms_per_blob"`
	MiBPerSecond float64   `json:"aggregate_mib_per_second"`
	LatencyMS    []float64 `json:"individual_blob_latency_ms"`
}

type summary struct {
	MeanWallMS       float64       `json:"mean_batch_wall_ms"`
	MedianWallMS     float64       `json:"median_batch_wall_ms"`
	MeanCPUMS        float64       `json:"mean_process_cpu_ms"`
	MeanCPUMSPerBlob float64       `json:"mean_process_cpu_ms_per_blob"`
	MiBPerSecond     float64       `json:"aggregate_mib_per_second"`
	MeanLatencyMS    float64       `json:"mean_individual_blob_latency_ms"`
	MaxLatencyMS     float64       `json:"max_individual_blob_latency_ms"`
	Samples          []batchSample `json:"samples"`
}

type workerInfo struct {
	Worker      int      `json:"worker"`
	ExpectedBus string   `json:"expected_pci_bus"`
	Device      qat.Info `json:"device"`
}

type caseResult struct {
	Name                 string       `json:"name"`
	Workers              []workerInfo `json:"workers"`
	IndependentInstances int          `json:"independent_instances"`
	PayloadBytes         uint64       `json:"payload_bytes"`
	QAT                  summary      `json:"qat"`
	CPU                  *summary     `json:"cpu,omitempty"`
	CPUReferenceCase     string       `json:"cpu_reference_case,omitempty"`
}

type report struct {
	GeneratedUTC    time.Time    `json:"generated_utc"`
	GoVersion       string       `json:"go_version"`
	GOMAXPROCS      int          `json:"gomaxprocs"`
	BytesPerBlob    int          `json:"bytes_per_blob"`
	Iterations      int          `json:"measured_batches_per_backend"`
	Warmup          int          `json:"warmup_batches_per_backend"`
	PollUS          int          `json:"poll_us"`
	AllocationBytes int          `json:"allocation_bytes"`
	RequestBytes    int          `json:"request_bytes"`
	SHA256          string       `json:"sha256"`
	Verified        bool         `json:"all_digests_verified"`
	Notes           []string     `json:"measurement_notes"`
	Cases           []caseResult `json:"cases"`
}

type worker struct {
	e    *qat.Engine
	p    *qat.Pool
	b    *qat.Buffer
	data []byte
}

var pattern = func() []byte {
	p := make([]byte, 4096)
	for i := range p {
		p[i] = byte((i*131 + 17) ^ (i >> 5))
	}
	return p
}()

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

func expectedBus(instance int) string {
	switch {
	case instance < 32:
		return "3d"
	case instance < 64:
		return "3f"
	default:
		return "41"
	}
}

func processCPU() (time.Duration, error) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, err
	}
	return time.Duration(usage.Utime.Sec+usage.Stime.Sec)*time.Second +
		time.Duration(usage.Utime.Usec+usage.Stime.Usec)*time.Microsecond, nil
}

func measureBatch(workers []*worker, cpu bool, request int, want [32]byte) (s batchSample, err error) {
	streams := make([]*qat.Stream, len(workers))
	defer func() {
		// Closing drains any outstanding work before the caller releases buffers.
		for _, stream := range streams {
			if stream != nil {
				err = errors.Join(err, stream.Close())
			}
		}
	}()
	if !cpu {
		for i, w := range workers {
			if streams[i], err = w.e.NewSHA256(qat.StreamOptions{RequestBytes: request}); err != nil {
				return s, err
			}
		}
	}
	s.LatencyMS = make([]float64, len(workers))
	sums := make([][32]byte, len(workers))
	errs := make([]error, len(workers))
	start, abort := make(chan struct{}), make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(len(workers))
	done.Add(len(workers))
	for i, w := range workers {
		go func() {
			defer done.Done()
			ready.Done()
			select {
			case <-start:
			case <-abort:
				return
			}
			t := time.Now()
			if cpu {
				sums[i] = sha256.Sum256(w.data)
			} else if _, errs[i] = streams[i].SubmitRange(context.Background(), w.b, 0, len(w.data)); errs[i] == nil {
				sums[i], errs[i] = streams[i].Finish(context.Background())
			}
			s.LatencyMS[i] = float64(time.Since(t)) / float64(time.Millisecond)
		}()
	}
	ready.Wait()
	cpuStart, err := processCPU()
	if err != nil {
		close(abort)
		done.Wait()
		return s, err
	}
	t := time.Now()
	close(start)
	done.Wait()
	elapsed := time.Since(t)
	cpuEnd, err := processCPU()
	if err != nil {
		return s, err
	}
	s.WallMS = float64(elapsed) / float64(time.Millisecond)
	s.CPUMS = float64(cpuEnd-cpuStart) / float64(time.Millisecond)
	s.CPUMSPerBlob = s.CPUMS / float64(len(workers))
	s.MiBPerSecond = float64(len(workers)*len(workers[0].data)) / qat.MiB / elapsed.Seconds()
	for i := range workers {
		if errs[i] != nil {
			return s, fmt.Errorf("worker %d: %w", i, errs[i])
		}
		if sums[i] != want {
			return s, fmt.Errorf("worker %d SHA256 mismatch: got %x want %x", i, sums[i], want)
		}
	}
	return s, nil
}

func summarize(samples []batchSample, payloadBytes uint64) (r summary) {
	r.Samples = samples
	walls := make([]float64, len(samples))
	latencies := 0
	for i, s := range samples {
		walls[i] = s.WallMS
		r.MeanWallMS += s.WallMS
		r.MeanCPUMS += s.CPUMS
		r.MeanCPUMSPerBlob += s.CPUMSPerBlob
		for _, latency := range s.LatencyMS {
			r.MeanLatencyMS += latency
			r.MaxLatencyMS = max(r.MaxLatencyMS, latency)
			latencies++
		}
	}
	r.MeanWallMS /= float64(len(samples))
	r.MeanCPUMS /= float64(len(samples))
	r.MeanCPUMSPerBlob /= float64(len(samples))
	r.MeanLatencyMS /= float64(latencies)
	r.MiBPerSecond = float64(payloadBytes) / qat.MiB / (r.MeanWallMS / 1000)
	sort.Float64s(walls)
	r.MedianWallMS = walls[len(walls)/2]
	if len(walls)%2 == 0 {
		r.MedianWallMS = (r.MedianWallMS + walls[len(walls)/2-1]) / 2
	}
	return r
}

func runCase(p preset, o options, want [32]byte, cpuReference string) (r caseResult, err error) {
	r.Name = p.name
	r.PayloadBytes = uint64(len(p.instances)) * uint64(o.bytes)
	engines := make(map[int]*qat.Engine)
	workers := make([]*worker, 0, len(p.instances))
	defer func() {
		for _, w := range workers {
			if w.b != nil {
				err = errors.Join(err, w.b.Release())
			}
			if w.p != nil {
				err = errors.Join(err, w.p.Close())
			}
		}
		for _, e := range engines {
			err = errors.Join(err, e.Close())
		}
	}()
	for i, instance := range p.instances {
		e := engines[instance]
		if e == nil {
			e, err = qat.Open(qat.Options{Instance: instance, PollInterval: time.Duration(o.pollUS) * time.Microsecond})
			if err != nil {
				return r, fmt.Errorf("open instance %d: %w", instance, err)
			}
			engines[instance] = e
		}
		info, bus := e.Info(), expectedBus(instance)
		if !strings.HasPrefix(strings.ToLower(info.PCI), bus+":") {
			return r, fmt.Errorf("instance %d maps to PCI %s; expected bus %s for this host's preset", instance, info.PCI, bus)
		}
		r.Workers = append(r.Workers, workerInfo{Worker: i, ExpectedBus: bus, Device: info})
		w := &worker{e: e}
		workers = append(workers, w)
		if w.p, err = e.NewPool(1, o.bytes); err != nil {
			return r, err
		}
		if w.b, err = w.p.Acquire(context.Background()); err != nil {
			return r, err
		}
		if w.data, err = w.b.Bytes(); err != nil {
			return r, err
		}
		n := copy(w.data, pattern)
		for n < len(w.data) {
			n += copy(w.data[n:], w.data[:n])
		}
	}
	r.IndependentInstances = len(engines)
	var qatSamples, cpuSamples []batchSample
	for round := 0; round < o.warmup+o.iterations; round++ {
		// Alternate CPU/QAT order when this worker count needs a CPU baseline.
		backends := []bool{false}
		if o.cpu && cpuReference == "" {
			backends = []bool{round%2 == 0, round%2 != 0}
		}
		for _, cpu := range backends {
			s, batchErr := measureBatch(workers, cpu, o.request, want)
			if batchErr != nil {
				return r, fmt.Errorf("round %d CPU=%t: %w", round, cpu, batchErr)
			}
			if round >= o.warmup {
				if cpu {
					cpuSamples = append(cpuSamples, s)
				} else {
					qatSamples = append(qatSamples, s)
				}
			}
		}
	}
	r.QAT = summarize(qatSamples, r.PayloadBytes)
	if len(cpuSamples) > 0 {
		cpu := summarize(cpuSamples, r.PayloadBytes)
		r.CPU = &cpu
	} else if o.cpu {
		r.CPUReferenceCase = cpuReference
	}
	return r, nil
}

func run() error {
	o := options{}
	var names string
	flag.StringVar(&names, "cases", "single,shared3,one2,one4,three1,three2,three4", "comma-separated presets: single,shared3,one2,one4,one8,one16,three1,three2,three4,three8; all enables up to 6 GiB payload")
	flag.IntVar(&o.bytes, "bytes", 256*qat.MiB, "bytes per worker's contiguous DMA buffer")
	flag.IntVar(&o.iterations, "iterations", 3, "measured batches per backend and case")
	flag.IntVar(&o.warmup, "warmup", 1, "warmup batches per backend and case")
	flag.IntVar(&o.pollUS, "poll-us", int(qat.DefaultPollInterval/time.Microsecond), "delay after unsuccessful QAT poll in microseconds; 0 busy polls")
	flag.IntVar(&o.request, "request", qat.DefaultRequestBytes, "maximum QAT request bytes: multiple of 64 up to 4194304")
	flag.BoolVar(&o.cpu, "cpu", true, "measure CPU baseline once per distinct worker count")
	flag.StringVar(&o.jsonPath, "json", "", "write settings, per-worker devices, raw samples and summaries as JSON")
	flag.Parse()
	if flag.NArg() != 0 || o.bytes <= 0 || uint64(o.bytes) > qat.MaxStreamBytes ||
		o.iterations < 1 || o.iterations > 100000 || o.warmup < 0 || o.warmup > 100000 ||
		o.pollUS < 0 || o.pollUS > 1000000 || o.request < 64 || o.request > 4*qat.MiB || o.request%64 != 0 {
		return errors.New("invalid arguments; see -help")
	}
	all := presets()
	var selected []preset
	seen := make(map[string]bool)
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		found := false
		for _, p := range all {
			if name == "all" || p.name == name {
				found = true
				if !seen[p.name] {
					selected = append(selected, p)
					seen[p.name] = true
				}
			}
		}
		if !found {
			return fmt.Errorf("unknown case %q; see -help", name)
		}
	}
	want := reference(o.bytes)
	r := report{GeneratedUTC: time.Now().UTC(), GoVersion: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0),
		BytesPerBlob: o.bytes, Iterations: o.iterations, Warmup: o.warmup, PollUS: o.pollUS,
		AllocationBytes: qat.DefaultAllocationBytes, RequestBytes: o.request,
		SHA256: hex.EncodeToString(want[:]), Notes: []string{
			"Resident-data benchmark: buffer allocation, fill, page first touch, engine initialization, session creation and cleanup are outside timed batches.",
			"Every worker owns one independent contiguous DMA buffer and digest state. Shared3 intentionally uses three streams on one serialized engine.",
			"QAT batch timing includes synchronized start, submission and Finish completion; individual latencies start when each worker is scheduled.",
			"Process CPU time is measured once around the whole batch, across all process threads. Digest verification is outside timing.",
			"CPU baselines use the same resident buffers; duplicate worker counts reference the first measured case with that count, which can have different PCI/NUMA placement.",
			"Cases are sequential; all buffers and engines close before the next case. Largest default case holds 3 GiB payload; optional three8 holds 6 GiB, plus allocator overhead.",
			"Host-specific presets require crypto indexes 0..31 on PCI bus 3d, 32..63 on 3f and 64..95 on 41; mappings are checked before timing.",
		}}
	cpuCases := make(map[int]string)
	fmt.Printf("%d-byte independent blobs; %d measured batches after %d warmups\n", o.bytes, o.iterations, o.warmup)
	fmt.Printf("%-10s %7s %9s %12s %12s %12s %12s\n", "Case", "Workers", "Instances", "QAT MiB/s", "CPU MiB/s", "Blob mean ms", "CPU ms/blob")
	for _, p := range selected {
		result, err := runCase(p, o, want, cpuCases[len(p.instances)])
		if err != nil {
			return fmt.Errorf("case %s: %w", p.name, err)
		}
		cpuLabel := "disabled"
		if result.CPU != nil {
			cpuCases[len(p.instances)] = p.name
			cpuLabel = fmt.Sprintf("%.2f", result.CPU.MiBPerSecond)
		} else if result.CPUReferenceCase != "" {
			cpuLabel = "see " + result.CPUReferenceCase
		}
		fmt.Printf("%-10s %7d %9d %12.2f %12s %12.3f %12.3f\n", p.name, len(p.instances), result.IndependentInstances,
			result.QAT.MiBPerSecond, cpuLabel, result.QAT.MeanLatencyMS, result.QAT.MeanCPUMSPerBlob)
		r.Cases = append(r.Cases, result)
	}
	r.Verified = true
	fmt.Println("Every warmup and measured digest matched Go SHA256.")
	if o.jsonPath != "" {
		data, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(o.jsonPath, append(data, '\n'), 0644)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "qatparallel:", err)
		os.Exit(1)
	}
}
