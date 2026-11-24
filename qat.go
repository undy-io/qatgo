// Package qat provides reusable, C-allocated DMA buffers and streaming SHA-256
// for the legacy Intel C62x QAT driver. It requires Linux, cgo and libqat_s.
package qat

/*
#cgo CFLAGS: -std=c11
#cgo LDFLAGS: -L/opt/qat/lib -Wl,-rpath,/opt/qat/lib -lqat_s -lusdm_drv_s -lpthread
#include "native.h"
#include "alias.h"
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"
)

const (
	MiB = 1024 * 1024
	// Defaults measured on this C62x host; all sizes remain configurable.
	DefaultAllocationBytes = 4 * MiB
	DefaultRequestBytes    = 4 * MiB
	DefaultReceiveBytes    = 4 * MiB
	DefaultPollInterval    = 250 * time.Microsecond
	// MaxStreamBytes is the legacy driver's partial-hash length limit.
	MaxStreamBytes = uint64(1<<32 - 65)
)

var (
	ErrClosed      = errors.New("qat: resource closed")
	ErrInUse       = errors.New("qat: resource still in use")
	ErrBufferOwned = errors.New("qat: buffer lease was released or transferred")
	ErrFinalized   = errors.New("qat: stream already finalized")
	processMu      sync.Mutex
	processEngines = make(map[int]*Engine)
)

// Options selects a crypto instance in the shared process-wide QAT runtime.
type Options struct {
	Instance int
	// PollInterval is the delay between unsuccessful polls. Zero busy polls.
	PollInterval time.Duration
}

// DefaultOptions selects the measured low-CPU polling configuration. An
// explicit Options{PollInterval: 0} selects busy polling instead.
func DefaultOptions() Options { return Options{PollInterval: DefaultPollInterval} }

// Info identifies the selected virtual function and its NUMA node.
type Info struct {
	Instance, NUMANode int
	PCI                string
}

// Engine owns one crypto instance. Close its streams and pools before closing
// it. Distinct instances can be open concurrently and share one native runtime;
// each instance serializes its own requests. Use separate instances to execute
// independent hashes in parallel, including across physical endpoints.
type Engine struct {
	mu             sync.Mutex
	ptr            *C.qg_engine
	info           Info
	pools, streams int
}

func nativeError(buf *[512]C.char) error { return errors.New(C.GoString(&buf[0])) }

// Open initializes QAT using the existing SSL application configuration.
func Open(o Options) (*Engine, error) {
	if o.Instance < 0 || o.Instance > 65535 || o.PollInterval < 0 || o.PollInterval > time.Second {
		return nil, errors.New("qat: invalid instance or polling interval")
	}
	processMu.Lock()
	defer processMu.Unlock()
	if processEngines[o.Instance] != nil {
		return nil, fmt.Errorf("%w: crypto instance %d is already open", ErrInUse, o.Instance)
	}
	e := &Engine{}
	var errbuf [512]C.char
	if C.qg_open(C.uint(o.Instance), C.uint(o.PollInterval/time.Microsecond), &e.ptr, &errbuf[0], 512) != 0 {
		return nil, nativeError(&errbuf)
	}
	var node, bdf C.uint
	C.qg_info(e.ptr, &node, &bdf)
	e.info = Info{Instance: o.Instance, NUMANode: int(node), PCI: fmt.Sprintf("%02x:%02x.%x", uint(bdf)>>8, (uint(bdf)>>3)&31, uint(bdf)&7)}
	processEngines[o.Instance] = e
	return e, nil
}

func (e *Engine) Info() Info { return e.info }

// Close refuses to release this instance while its pools or streams are live.
// The last Engine to close also shuts down the shared process-wide runtime.
func (e *Engine) Close() error {
	processMu.Lock()
	defer processMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr == nil {
		return nil
	}
	if e.pools != 0 || e.streams != 0 {
		return fmt.Errorf("%w: %d pools, %d streams", ErrInUse, e.pools, e.streams)
	}
	var errbuf [512]C.char
	if C.qg_close(e.ptr, &errbuf[0], 512) != 0 {
		return nativeError(&errbuf)
	}
	e.ptr = nil
	delete(processEngines, e.info.Instance)
	return nil
}

// PoolOptions separates application buffer size from physical allocation size.
type PoolOptions struct {
	Count       int
	BufferBytes int
	// AllocationBytes is 2 MiB or 4 MiB (default). These allocation sizes use
	// complete USDM slabs, which can be aliased into one contiguous address range.
	AllocationBytes int
}

type allocation struct {
	blocks          []*C.qg_buffer
	base            unsafe.Pointer
	mapped          C.size_t
	size, blockSize int
}

// Pool holds a fixed number of reusable DMA-backed application buffers.
// Each Buffer has one contiguous virtual address range. Physical allocations
// may be disjoint. The alias mapping is specific to this legacy USDM driver.
type Pool struct {
	engine    *Engine
	mu        sync.Mutex
	available chan *allocation
	all       []*allocation
	closed    bool
	closing   bool
	leases    int
	size      int
}

// NewPool allocates count fixed-size buffers, each exposed as one []byte.
func (e *Engine) NewPool(count, bufferBytes int) (*Pool, error) {
	return e.NewPoolWithOptions(PoolOptions{Count: count, BufferBytes: bufferBytes})
}

func (e *Engine) NewPoolWithOptions(o PoolOptions) (*Pool, error) {
	if o.AllocationBytes == 0 {
		o.AllocationBytes = DefaultAllocationBytes
	}
	if o.Count <= 0 || o.BufferBytes <= 0 || uint64(o.BufferBytes) > MaxStreamBytes ||
		(o.AllocationBytes != 2*MiB && o.AllocationBytes != 4*MiB) {
		return nil, errors.New("qat: positive pool count/size and 2 or 4 MiB allocation size required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr == nil {
		return nil, ErrClosed
	}
	p := &Pool{engine: e, available: make(chan *allocation, o.Count), size: o.BufferBytes}
	var errbuf [512]C.char
	cleanup := func() {
		for _, a := range p.all {
			a.free()
		}
	}
	for i := 0; i < o.Count; i++ {
		a := &allocation{size: o.BufferBytes, blockSize: o.AllocationBytes}
		p.all = append(p.all, a)
		n := (o.BufferBytes + o.AllocationBytes - 1) / o.AllocationBytes
		for j := 0; j < n; j++ {
			var block *C.qg_buffer
			if C.qg_buffer_alloc(e.ptr, C.size_t(o.AllocationBytes), &block, &errbuf[0], 512) != 0 {
				cleanup()
				return nil, nativeError(&errbuf)
			}
			a.blocks = append(a.blocks, block)
		}
		// The array contains only C pointers, and C copies no Go pointers.
		if C.qg_alias_create(&a.blocks[0], C.size_t(len(a.blocks)), C.size_t(a.blockSize), &a.base, &a.mapped, &errbuf[0], 512) != 0 {
			cleanup()
			return nil, nativeError(&errbuf)
		}
		p.available <- a
	}
	e.pools++
	return p, nil
}

func (a *allocation) free() error {
	if a.base != nil {
		var errbuf [512]C.char
		if C.qg_alias_destroy(a.base, a.mapped, &errbuf[0], 512) != 0 {
			return nativeError(&errbuf)
		}
		a.base = nil
	}
	for _, b := range a.blocks {
		C.qg_buffer_free(b)
	}
	a.blocks = nil
	return nil
}

// Buffer is a single-use lease on a pooled allocation. Acquire returns a new
// lease object each time, so stale lease handles never become valid again.
type Buffer struct {
	mu         sync.Mutex
	pool       *Pool
	allocation *allocation
	state      int // 0 caller owns, 1 stream owns, 2 returned
	regions    map[*Submission]struct{}
	filling    bool
}

// Acquire waits for a free buffer or context cancellation.
func (p *Pool) Acquire(ctx context.Context) (*Buffer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case a := <-p.available:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed || p.closing {
			return nil, ErrClosed
		}
		p.leases++
		return &Buffer{pool: p, allocation: a}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Bytes returns one contiguous slice of C-allocated DMA-backed memory, with
// len==cap==the configured application buffer size. Do not retain or access
// the slice after Release or a successful Stream.Submit. It is not Go heap memory.
func (b *Buffer) Bytes() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != 0 {
		return nil, ErrBufferOwned
	}
	if b.filling {
		return nil, ErrInUse
	}
	return unsafe.Slice((*byte)(b.allocation.base), b.allocation.size), nil
}

// Fill reads exactly the buffer capacity, or returns a short count and the
// underlying EOF/error. It has io.ReadFull semantics and does not make a copy.
// Context cancellation cannot interrupt an arbitrary io.Reader's blocked Read.
func (b *Buffer) Fill(r io.Reader) (int, error) {
	b.mu.Lock()
	if b.state != 0 {
		b.mu.Unlock()
		return 0, ErrBufferOwned
	}
	if len(b.regions) != 0 || b.filling {
		b.mu.Unlock()
		return 0, ErrInUse
	}
	b.filling = true
	data := unsafe.Slice((*byte)(b.allocation.base), b.allocation.size)
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.filling = false; b.mu.Unlock() }()
	return io.ReadFull(r, data)
}

func (b *Buffer) release(expected int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != expected {
		return ErrBufferOwned
	}
	if len(b.regions) != 0 || b.filling {
		return ErrInUse
	}
	b.state = 2
	p := b.pool
	p.mu.Lock()
	defer p.mu.Unlock()
	p.leases--
	p.available <- b.allocation
	return nil
}

// Release returns an unsubmitted lease. Submitted buffers belong to the stream.
func (b *Buffer) Release() error { return b.release(0) }

// Close refuses to unmap memory while leases are checked out or queued for DMA.
func (p *Pool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.leases != 0 {
		return fmt.Errorf("%w: %d buffer leases", ErrInUse, p.leases)
	}
	if !p.closing {
		p.closing = true
		close(p.available)
	}
	for _, a := range p.all {
		if err := a.free(); err != nil {
			return err
		}
	}
	p.closed = true
	p.engine.mu.Lock()
	p.engine.pools--
	p.engine.mu.Unlock()
	return nil
}

// StreamOptions controls submission granularity independently of buffer size.
type StreamOptions struct {
	// RequestBytes defaults to 4 MiB; it must be a positive multiple of 64,
	// at most 4 MiB. Requests also stop at physical allocation boundaries.
	RequestBytes int
	// QueueDepth defaults to 2. The pool bounds total outstanding memory.
	QueueDepth int
}

type job struct {
	buffer    *Buffer
	offset, n int
	barrier   chan error
	region    *Submission
}

// Submission reserves a range in a caller-owned Buffer until Done closes.
// Other non-overlapping regions may be filled while QAT reads this region.
type Submission struct {
	done      chan struct{}
	err       error
	buffer    *Buffer
	offset, n int
}

func (r *Submission) Done() <-chan struct{} { return r.done }
func (r *Submission) Wait(ctx context.Context) error {
	select {
	case <-r.done:
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *Submission) complete(err error) {
	r.buffer.mu.Lock()
	defer r.buffer.mu.Unlock()
	delete(r.buffer.regions, r)
	r.err = err
	close(r.done)
}

// Stream computes one SHA-256 digest across all submissions, in submission
// order. A worker goroutine owns the native session and polls completions.
// Submit allows another goroutine to receive into a different buffer meanwhile.
type Stream struct {
	engine          *Engine
	ptr             *C.qg_hash
	tail            *C.qg_buffer
	tailBytes       []byte
	tailN           int
	requestBytes    int
	operation       chan struct{}
	sealed          bool
	accepted        uint64
	jobs            chan job
	done            chan struct{}
	cancelOnce      sync.Once
	cancelRequested chan struct{}
	errMu           sync.Mutex
	err             error
	sum             [32]byte
	quarantine      []job
	closeMu         sync.Mutex
	nativeMu        sync.Mutex // protects native pointer lifetime, not request polling
	closed          bool
	progress        RequestProgress
}

// RequestProgress counts actual CPA requests accepted by QAT and completion
// callbacks, including a final request. It is observational: wait for a
// Submission or Finish/Close before reusing memory, regardless of the counts.
type RequestProgress struct {
	Submitted uint64
	Completed uint64
}

// Progress can be called while a request is pending and after Close. Reading
// counters does not poll the device or wait for an outstanding request.
func (s *Stream) Progress() RequestProgress {
	s.nativeMu.Lock()
	defer s.nativeMu.Unlock()
	if s.ptr != nil {
		s.progress = s.nativeProgress()
	}
	return s.progress
}

func (s *Stream) nativeProgress() RequestProgress {
	var submitted, completed C.uint64_t
	C.qg_hash_progress(s.ptr, &submitted, &completed)
	return RequestProgress{Submitted: uint64(submitted), Completed: uint64(completed)}
}

func (e *Engine) NewSHA256(options ...StreamOptions) (*Stream, error) {
	if len(options) > 1 {
		return nil, errors.New("qat: pass at most one StreamOptions")
	}
	o := StreamOptions{}
	if len(options) == 1 {
		o = options[0]
	}
	if o.RequestBytes == 0 {
		o.RequestBytes = DefaultRequestBytes
	}
	if o.QueueDepth == 0 {
		o.QueueDepth = 2
	}
	if o.RequestBytes < 64 || o.RequestBytes > 4*MiB || o.RequestBytes%64 != 0 || o.QueueDepth < 1 {
		return nil, errors.New("qat: request size must be a multiple of 64 up to 4 MiB; positive queue depth required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr == nil {
		return nil, ErrClosed
	}
	s := &Stream{engine: e, requestBytes: o.RequestBytes, operation: make(chan struct{}, 1), jobs: make(chan job, o.QueueDepth), done: make(chan struct{}), cancelRequested: make(chan struct{})}
	var errbuf [512]C.char
	if C.qg_buffer_alloc(e.ptr, 64, &s.tail, &errbuf[0], 512) != 0 {
		return nil, nativeError(&errbuf)
	}
	if C.qg_hash_new(e.ptr, &s.ptr, &errbuf[0], 512) != 0 {
		C.qg_buffer_free(s.tail)
		return nil, nativeError(&errbuf)
	}
	s.tailBytes = unsafe.Slice((*byte)(C.qg_buffer_data(s.tail)), 64)
	e.streams++
	go s.run()
	return s, nil
}

func (s *Stream) currentError() error { s.errMu.Lock(); defer s.errMu.Unlock(); return s.err }
func (s *Stream) cancellationError() error {
	select {
	case <-s.cancelRequested:
		return context.Canceled
	default:
		return nil
	}
}
func (s *Stream) enter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Stream) leave() { <-s.operation }
func (s *Stream) setError(err error) {
	s.errMu.Lock()
	defer s.errMu.Unlock()
	if s.err == nil {
		s.err = err
	}
}

// Cancel stops the stream at a hardware-request boundary and discards its
// digest. It does not abort an accepted CPA request and does not wait for DMA.
// Wait for Submission.Done, or Finish with a live context returning
// context.Canceled, before reusing accepted memory. A wait deadline does not
// establish completion; native errors may still quarantine memory until Close.
// Finish and Close return context.Canceled once safely drained, unless a native
// error occurred. Calls are idempotent; cancellation after completion has no
// effect. Cancel does not interrupt an arbitrary reader in another goroutine.
func (s *Stream) Cancel() {
	// Signal before acquiring the producer gate: a producer blocked on queue
	// capacity must be able to roll back its lease and leave that gate.
	s.cancelOnce.Do(func() { close(s.cancelRequested) })
	s.nativeMu.Lock()
	if s.ptr != nil {
		C.qg_hash_request_cancel(s.ptr)
	}
	s.nativeMu.Unlock()
	_ = s.enter(context.Background())
	if !s.sealed {
		s.sealed = true
		close(s.jobs)
	}
	s.leave()
}

// Submit transfers this lease to the stream only if it returns nil. The first
// n bytes are hashed. Accepted memory cannot be read, changed, or released by
// the caller. It automatically returns to its pool after QAT completion.
// Arbitrary lengths work; only up to 63 trailing bytes are staged internally.
func (s *Stream) Submit(ctx context.Context, b *Buffer, n int) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer s.leave()
	if err := s.cancellationError(); err != nil {
		return err
	}
	if s.sealed {
		return ErrFinalized
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.currentError(); err != nil {
		return err
	}
	if b == nil {
		return errors.New("qat: nil buffer")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.state != 0 {
		return ErrBufferOwned
	}
	if len(b.regions) != 0 || b.filling {
		return ErrInUse
	}
	if b.pool.engine != s.engine {
		return errors.New("qat: buffer belongs to a different engine")
	}
	if n < 0 || n > b.allocation.size {
		return errors.New("qat: invalid submission length")
	}
	if uint64(n) > MaxStreamBytes-s.accepted {
		return errors.New("qat: legacy SHA256 stream length limit exceeded")
	}
	b.state = 1
	select {
	case s.jobs <- job{buffer: b, n: n}:
		s.accepted += uint64(n)
		return nil
	case <-ctx.Done():
		b.state = 0
		return ctx.Err()
	case <-s.cancelRequested:
		b.state = 0
		return context.Canceled
	}
}

// SubmitRange appends b[offset:offset+n] asynchronously, keeping the Buffer
// lease with the caller. Only that range is reserved. The caller can receive
// into a disjoint region of the SAME contiguous []byte while hashing proceeds.
// Do not change the submitted range until its Submission completes. Buffer
// Release and overlapping active ranges are rejected. Cancellation before
// enqueue leaves the buffer unchanged.
func (s *Stream) SubmitRange(ctx context.Context, b *Buffer, offset, n int) (*Submission, error) {
	if err := s.enter(ctx); err != nil {
		return nil, err
	}
	defer s.leave()
	if err := s.cancellationError(); err != nil {
		return nil, err
	}
	if s.sealed {
		return nil, ErrFinalized
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.currentError(); err != nil {
		return nil, err
	}
	if b == nil {
		return nil, errors.New("qat: nil buffer")
	}
	r, err := func() (*Submission, error) {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.state != 0 {
			return nil, ErrBufferOwned
		}
		if b.filling {
			return nil, ErrInUse
		}
		if b.pool.engine != s.engine {
			return nil, errors.New("qat: buffer belongs to a different engine")
		}
		if offset < 0 || n < 0 || n > b.allocation.size || offset > b.allocation.size-n {
			return nil, errors.New("qat: invalid submission range")
		}
		if uint64(n) > MaxStreamBytes-s.accepted {
			return nil, errors.New("qat: legacy SHA256 stream length limit exceeded")
		}
		for r := range b.regions {
			if n > 0 && r.n > 0 && offset < r.offset+r.n && r.offset < offset+n {
				return nil, ErrInUse
			}
		}
		r := &Submission{done: make(chan struct{}), buffer: b, offset: offset, n: n}
		if b.regions == nil {
			b.regions = make(map[*Submission]struct{})
		}
		b.regions[r] = struct{}{}
		return r, nil
	}()
	if err != nil {
		return nil, err
	}
	// Never hold b.mu while waiting for queue capacity: completing an earlier
	// range of this same buffer needs that mutex before the worker can dequeue.
	select {
	case s.jobs <- job{buffer: b, offset: offset, n: n, region: r}:
		s.accepted += uint64(n)
		return r, nil
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.regions, r)
		b.mu.Unlock()
		return nil, ctx.Err()
	case <-s.cancelRequested:
		b.mu.Lock()
		delete(b.regions, r)
		b.mu.Unlock()
		return nil, context.Canceled
	}
}

// Flush waits for accepted submissions to finish reading their buffers. It
// does not finalize the hash. At most 63 bytes remain in private tail storage.
func (s *Stream) Flush(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	if err := s.cancellationError(); err != nil {
		s.leave()
		return err
	}
	if s.sealed {
		s.leave()
		return ErrFinalized
	}
	if err := ctx.Err(); err != nil {
		s.leave()
		return err
	}
	ack := make(chan error, 1)
	select {
	case s.jobs <- job{barrier: ack}:
		s.leave()
	case <-ctx.Done():
		s.leave()
		return ctx.Err()
	case <-s.cancelRequested:
		s.leave()
		return context.Canceled
	}
	select {
	case err := <-ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Stream) update(block *C.qg_buffer, offset, n int, final bool) error {
	if err := s.cancellationError(); err != nil {
		return err
	}
	var errbuf [512]C.char
	var digest [32]byte
	flag := C.int(0)
	if final {
		flag = 1
	}
	result := C.qg_hash_update(s.ptr, block, C.size_t(offset), C.size_t(n), flag,
		(*C.uchar)(unsafe.Pointer(&digest[0])), &errbuf[0], 512)
	if result == 1 {
		return context.Canceled
	}
	if result != 0 {
		return nativeError(&errbuf)
	}
	// The native call completed its accepted request. A concurrent Cancel can
	// now stop this stream safely, including while finalization was pending.
	if err := s.cancellationError(); err != nil {
		return err
	}
	if final {
		s.sum = digest
	}
	return nil
}

func (s *Stream) consume(b *Buffer, start, n int) error {
	a := b.allocation
	for i, left := start/a.blockSize, n; left > 0; i++ {
		within := start % a.blockSize
		length := left
		if length > a.blockSize-within {
			length = a.blockSize - within
		}
		bytes := unsafe.Slice((*byte)(C.qg_buffer_data(a.blocks[i])), a.blockSize)[within : within+length]
		offset := 0
		if s.tailN > 0 {
			take := 64 - s.tailN
			if take > length {
				take = length
			}
			copy(s.tailBytes[s.tailN:], bytes[:take])
			s.tailN += take
			offset += take
			if s.tailN == 64 {
				if err := s.update(s.tail, 0, 64, false); err != nil {
					return err
				}
				s.tailN = 0
			}
		}
		full := (length - offset) / 64 * 64
		for full > 0 {
			request := full
			if request > s.requestBytes {
				request = s.requestBytes
			}
			if err := s.update(a.blocks[i], within+offset, request, false); err != nil {
				return err
			}
			offset += request
			full -= request
		}
		if offset < length {
			s.tailN = copy(s.tailBytes, bytes[offset:])
		}
		left -= length
		start += length
	}
	return nil
}

func (s *Stream) run() {
	defer close(s.done)
	for j := range s.jobs {
		if s.currentError() == nil {
			if err := s.cancellationError(); err != nil {
				s.setError(err)
			}
		}
		if j.barrier != nil {
			j.barrier <- s.currentError()
			continue
		}
		if err := s.currentError(); err != nil {
			if j.region != nil {
				j.region.complete(err)
			} else {
				_ = j.buffer.release(1)
			}
			continue
		}
		err := s.consume(j.buffer, j.offset, j.n)
		if err == nil {
			err = s.cancellationError()
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			s.setError(err)
			// An error may mean a DMA timeout. Keep the entire allocation leased
			// until native hash cleanup confirms no request is still in flight.
			s.quarantine = append(s.quarantine, j)
		} else {
			if err != nil {
				s.setError(err)
			}
			if j.region != nil {
				j.region.complete(err)
			} else {
				_ = j.buffer.release(1)
			}
		}
	}
	if s.currentError() == nil {
		if err := s.update(s.tail, 0, s.tailN, true); err != nil {
			s.setError(err)
		}
	}
}

// Finish seals the stream, waits for accepted work, and returns SHA256 of all
// submitted bytes. Repeated calls return the same result. Its context bounds
// only the wait; a later Finish can retrieve the result. Stream.Cancel instead
// discards the digest and returns context.Canceled after accepted DMA drains.
func (s *Stream) Finish(ctx context.Context) ([32]byte, error) {
	if err := s.enter(ctx); err != nil {
		return [32]byte{}, err
	}
	if !s.sealed {
		if err := ctx.Err(); err != nil {
			s.leave()
			return [32]byte{}, err
		}
		s.sealed = true
		close(s.jobs)
	}
	s.leave()
	select {
	case <-s.done:
		return s.sum, s.currentError()
	case <-ctx.Done():
		return [32]byte{}, ctx.Err()
	}
}

// Close drains accepted work and releases the native session. It may block
// even if a previous Finish's context expired. A stalled native request keeps
// buffers quarantined and returns an error instead of freeing active DMA.
// Retry Close after hardware recovery if it reports outstanding DMA.
func (s *Stream) Close() error {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return nil
	}
	_, hashErr := s.Finish(context.Background())
	var errbuf [512]C.char
	var submitted, completed C.uint64_t
	s.nativeMu.Lock()
	if C.qg_hash_free(s.ptr, &submitted, &completed, &errbuf[0], 512) != 0 {
		s.nativeMu.Unlock()
		return errors.Join(hashErr, nativeError(&errbuf))
	}
	s.progress = RequestProgress{Submitted: uint64(submitted), Completed: uint64(completed)}
	s.ptr = nil
	s.nativeMu.Unlock()
	C.qg_buffer_free(s.tail)
	s.tail = nil
	s.tailBytes = nil
	for _, j := range s.quarantine {
		if j.region != nil {
			j.region.complete(hashErr)
		} else {
			_ = j.buffer.release(1)
		}
	}
	s.quarantine = nil
	s.closed = true
	s.engine.mu.Lock()
	s.engine.streams--
	s.engine.mu.Unlock()
	return hashErr
}

// HashReader receives directly into pooled DMA memory while the worker hashes
// previously filled buffers. The pool must belong to this engine. Reader errors
// are returned after accepted work has drained; no digest is returned on error.
func (e *Engine) HashReader(ctx context.Context, r io.Reader, p *Pool) (sum [32]byte, n int64, err error) {
	if p == nil || p.engine != e {
		return sum, 0, errors.New("qat: pool belongs to a different engine")
	}
	s, err := e.NewSHA256()
	if err != nil {
		return sum, 0, err
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	for {
		b, acquireErr := p.Acquire(ctx)
		if acquireErr != nil {
			return sum, n, acquireErr
		}
		count, readErr := b.Fill(r)
		if count > 0 {
			if submitErr := s.Submit(ctx, b, count); submitErr != nil {
				_ = b.Release()
				return sum, n, submitErr
			}
			n += int64(count)
		} else {
			_ = b.Release()
		}
		if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
			sum, err = s.Finish(ctx)
			return sum, n, err
		}
		if readErr != nil {
			return sum, n, readErr
		}
	}
}
