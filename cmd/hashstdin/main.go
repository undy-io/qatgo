// hashstdin reads into one contiguous DMA-backed buffer while QAT hashes
// completed ranges of that same buffer. No payload copy is needed for QAT.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	qat "github.com/undy-io/qatgo"
)

type options struct {
	bytes, buffers, allocation, chunk, instance, pollUS int
}

func parseOptions() (options, error) {
	o := options{}
	flag.IntVar(&o.bytes, "bytes", 256*qat.MiB, "maximum stdin bytes to hash; reading stops at this limit")
	flag.IntVar(&o.buffers, "buffers", 1, "number of full-size buffers in the reusable pool (this command leases one)")
	flag.IntVar(&o.allocation, "allocation", qat.DefaultAllocationBytes, "physical DMA allocation bytes: 2097152 or 4194304")
	flag.IntVar(&o.chunk, "chunk", qat.DefaultReceiveBytes, "receive bytes per range; QAT hashes each range while the next is read")
	flag.IntVar(&o.instance, "instance", 0, "legacy QAT crypto instance index")
	flag.IntVar(&o.pollUS, "poll-us", int(qat.DefaultPollInterval/time.Microsecond), "delay after unsuccessful polling, in microseconds; 0 busy polls")
	flag.Parse()
	if flag.NArg() != 0 {
		return o, errors.New("read data from stdin; positional arguments are not accepted")
	}
	if o.bytes <= 0 || uint64(o.bytes) > qat.MaxStreamBytes {
		return o, fmt.Errorf("-bytes must be positive and at most %d", qat.MaxStreamBytes)
	}
	if o.buffers < 1 || o.buffers > 1024 || o.chunk < 1 {
		return o, errors.New("-buffers must be 1..1024 and -chunk must be positive")
	}
	if o.allocation != 2*qat.MiB && o.allocation != 4*qat.MiB {
		return o, errors.New("-allocation must be 2097152 or 4194304")
	}
	if o.instance < 0 || o.instance > 65535 || o.pollUS < 0 || o.pollUS > 1000000 {
		return o, errors.New("-instance must be 0..65535 and -poll-us must be 0..1000000")
	}
	return o, nil
}

func hashInput(o options, input io.Reader) (sum [32]byte, n int, elapsed time.Duration, info qat.Info, err error) {
	ctx := context.Background()
	engine, err := qat.Open(qat.Options{
		Instance: o.instance, PollInterval: time.Duration(o.pollUS) * time.Microsecond,
	})
	if err != nil {
		return sum, n, elapsed, info, err
	}
	defer func() { err = errors.Join(err, engine.Close()) }()
	info = engine.Info()
	pool, err := engine.NewPoolWithOptions(qat.PoolOptions{
		Count: o.buffers, BufferBytes: o.bytes, AllocationBytes: o.allocation,
	})
	if err != nil {
		return sum, n, elapsed, info, err
	}
	defer func() { err = errors.Join(err, pool.Close()) }()
	buffer, err := pool.Acquire(ctx)
	if err != nil {
		return sum, n, elapsed, info, err
	}
	defer func() { err = errors.Join(err, buffer.Release()) }()

	// This replaces make([]byte, o.bytes). It is one normal contiguous slice;
	// its backing memory belongs to the DMA pool, so release the lease last.
	payload, err := buffer.Bytes()
	if err != nil {
		return sum, n, elapsed, info, err
	}
	stream, err := engine.NewSHA256()
	if err != nil {
		return sum, n, elapsed, info, err
	}
	// Defers run in this order: drain/close stream, release buffer, close pool,
	// close engine. A pending-DMA error leaves the lease and runtime retained.
	defer func() { err = errors.Join(err, stream.Close()) }()

	start := time.Now()
	for n < len(payload) {
		length := o.chunk
		if length > len(payload)-n {
			length = len(payload) - n
		}
		count, readErr := io.ReadFull(input, payload[n:n+length])
		if count > 0 {
			// SubmitRange retains only this completed region. The next read
			// writes a disjoint region of the SAME payload slice concurrently.
			if _, submitErr := stream.SubmitRange(ctx, buffer, n, count); submitErr != nil {
				return sum, n, time.Since(start), info, submitErr
			}
			n += count
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrUnexpectedEOF) {
				break // Short stdin is valid; the digest covers exactly n bytes.
			}
			return sum, n, time.Since(start), info, fmt.Errorf("read stdin: %w", readErr)
		}
	}
	sum, err = stream.Finish(ctx)
	elapsed = time.Since(start)
	return sum, n, elapsed, info, err
}

func run() error {
	o, err := parseOptions()
	if err != nil {
		return err
	}
	sum, n, elapsed, info, err := hashInput(o, os.Stdin)
	if err != nil {
		return err
	}
	if _, err = fmt.Printf("%x  -\n", sum); err != nil {
		return err
	}
	rate := float64(n) / qat.MiB / elapsed.Seconds()
	_, err = fmt.Fprintf(os.Stderr,
		"Hashed %d bytes in %.3f s (%.2f MiB/s); QAT instance %d, PCI %s, NUMA %d\n",
		n, elapsed.Seconds(), rate, info.Instance, info.PCI, info.NUMANode)
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hashstdin:", err)
		os.Exit(1)
	}
}
