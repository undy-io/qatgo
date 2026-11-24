# qatgo

Go DMA buffer pools and asynchronous SHA-256 hashing for Intel C62x QAT
accelerators, using the [legacy QAT driver and userspace stack](https://github.com/undy-io/qat-legacy-linux).
This is a community project, independent of Intel. The tested hardware is an
Intel Adapter 8970 with three C62x endpoints; other hardware and driver stacks
have not been validated.

The code in this repository is licensed under [BSD-3-Clause](LICENSE).
The native Intel driver and firmware retain their separate licenses.

This module replaces `make([]byte, size)` with a fixed pool of DMA-backed
buffers. Each application buffer is **one contiguous virtual address range**, exposed as a normal Go `[]byte`.
For example, a 256 MiB buffer has `len(payload) == cap(payload) == 268435456`.

Backing storage comes from `qaeMemAllocNUMA`. The current USDM driver limits
an allocation to 4 MiB, so the module allocates complete 2 MiB or 4 MiB slabs
and maps an additional view of those same pages into one reserved virtual
range. QAT uses the original slab mappings. There is no full-payload staging copy
between the application's byte slice and the card; unaligned chunk boundaries
use a private 64-byte tail buffer. Physical slabs do not have
to be adjacent. This layout was verified on the actual driver and hardware.

The module also provides one ordered SHA-256 stream across many asynchronous
range submissions. The receiver can fill a later region of the **same 256 MiB
slice** while QAT reads an earlier region. Finish returns SHA-256 of the entire
submitted byte stream, not a collection of chunk digests.

The [async service design](DESIGN.md) covers a proposed consumer API, automatic
endpoint discovery, bounded scheduling, ownership and adding a second card.

## Hash support on the tested host

The Go module currently implements **plain SHA-256 only**. A separate native
survey queried all 96 configured crypto instances and tested one representative
instance on each of the three C62x endpoints. All instances advertised the same
hash capabilities. Results below describe the installed driver and hardware,
not additional algorithms already exposed by the Go API.

| Algorithm | Digest bytes | Current driver | Incremental hashing |
| --- | ---: | --- | --- |
| SHA-1 | 20 | Disabled at build time; hardware supports opt-in | Requires opt-in and a new verification run |
| SHA-256 | 32 | Verified | Verified |
| SHA-384 | 48 | Verified | Verified |
| SHA-512 | 64 | Verified | Verified |
| SHA3-256 | 32 | Verified for one complete request | Rejected by this C62x driver/device combination |
| MD5 / SHA-224 | 16 / 28 | Disabled at build time; hardware supports opt-in | Requires opt-in and a new verification run |
| SHA3-224 / SHA3-384 / SHA3-512 | 28 / 48 / 64 | Not advertised on these endpoints | Unavailable |
| SHAKE128 / SHAKE256 / SM3 | Variable / variable / 32 | Not advertised on these endpoints | Unavailable |
| BLAKE2 / BLAKE3 / SHA-512/224 / SHA-512/256 | Varies | No algorithm selector in this installed CPA API | Unavailable through this backend |

For SHA-256, SHA-384, SHA-512 and SHA3-256, the probe tested both plain hashing
and HMAC. Across the three endpoints, 42 digests matched OpenSSL and six SHA3
partial requests were rejected as expected. Inputs were 529 bytes; incremental
tests submitted an aligned prefix and a short final chunk into one digest
state. This checks correctness and mode availability, not large-buffer limits
or performance. In particular, SHA3-256 support does not establish that the
current multi-slab Go wrapper can submit a complete 256 MiB SHA3 request.

SHA-1 can be useful for compatibility with protocols that require it. The
tested driver source tree was configured with `QAT_LEGACY_ALGORITHMS = n`. Intel's
[algorithm matrix](https://www.intel.com/content/www/us/en/support/articles/000093843/technologies/intel-quickassist-technology-intel-qat.html)
documents the `--enable-legacy-algorithms` configure option. Enabling SHA-1
requires preserving the existing configure options, adding that opt-in, and
cleanly rebuilding/installing both the kernel modules and userspace libraries.
The new modules must be loaded and the application restarted. A device config
file change alone is insufficient. The survey did not change driver settings.

The next Go API revision should make the algorithm, digest length and block
size explicit, preserving SHA-256 and allowing SHA-1 as an opt-in extension. SHA-1 uses 64-byte blocks like
SHA-256; SHA-384 and SHA-512 use 128-byte blocks. Buffer ownership, completion
and cancellation rules remain the same. HMAC additionally needs explicit key
and session handling and is not part of the current Go wrapper.

The driver also advertises AES-XCBC, AES-CMAC, AES-CBC-MAC, AES-GMAC,
AES-CCM/GCM authentication, KASUMI-F9, SNOW3G-UIA2 and ZUC-EIA3. These are
keyed MAC or authenticated-encryption operations, rather than interchangeable
unkeyed blob hashes; the survey enumerated but did not execute them. Poly1305
is not advertised on these endpoints.

Raw results are in [hash-survey.jsonl](hash-survey.jsonl). The probe writes
expected rejection diagnostics to standard error; local diagnostic logs are
excluded from version control. The [probe source](tools/hashsurvey.c) is
separate from the Go library and also requires OpenSSL development headers/libraries. Reproduce from this repository
root after setting `QAT_SOURCE` to the legacy driver checkout, with no other
QAT application using the tested single-process `SSL` context:

```sh
export QAT_SOURCE=/path/to/qat-legacy-linux
cc -std=c11 -Wall -Wextra -Werror \
  -I"$QAT_SOURCE/quickassist/include" \
  -I"$QAT_SOURCE/quickassist/include/lac" \
  -I"$QAT_SOURCE/quickassist/include/icp" \
  -I"$QAT_SOURCE/quickassist/utilities/libusdm_drv" tools/hashsurvey.c \
  -L/opt/qat/lib -Wl,-rpath,/opt/qat/lib \
  -lqat_s -lusdm_drv_s -lcrypto -lpthread -o /tmp/qat-hash-survey
sudo /tmp/qat-hash-survey > hash-survey.jsonl 2> hash-survey-errors.log
```

The first startup attempt encountered a USDM contiguous-allocation failure
before any hashing. A subsequent attempt succeeded without changing settings.
This remains a startup failure the future service must report and clean up;
the successful survey does not establish allocation reliability under load.

## Replace the allocation

```go
import (
    "context"
    qat "github.com/undy-io/qatgo"
)

ctx := context.Background()
engine, err := qat.Open(qat.DefaultOptions())
if err != nil { /* handle error */ }
defer engine.Close()

pool, err := engine.NewPool(2, 256 * qat.MiB)
if err != nil { /* handle error */ }
defer pool.Close()

lease, err := pool.Acquire(ctx)
if err != nil { /* handle error */ }
defer lease.Release()

payload, err := lease.Bytes() // replaces make([]byte, 256 * qat.MiB)
if err != nil { /* handle error */ }
// Read directly into payload. Its type is []byte.
```

The pool should live across many blobs; avoid allocating/freeing all DMA
storage per blob. Acquire waits when all leases are in use, providing bounded
memory and backpressure. Reused buffers retain their old contents, unlike a
fresh `make`; fully overwrite the payload or call `clear(payload)` if needed.

From a consumer module, add the published module:

```sh
go get github.com/undy-io/qatgo
```

The package name is `qat`. Consumer builds need the same native dependencies
and include/library settings described below. For local development, a
`go.work` file or a `replace github.com/undy-io/qatgo => /path/to/qatgo`
directive can select a local checkout.

## Receive and hash one contiguous blob incrementally

The essential loop, with error handling abbreviated, is:

```go
h, err := engine.NewSHA256(qat.StreamOptions{
    RequestBytes: qat.DefaultRequestBytes,
    QueueDepth: 2,
})
if err != nil { /* handle error */ }
defer h.Close() // register AFTER lease.Release so hash drains first

const receiveChunk = qat.DefaultReceiveBytes
received := 0
for received < len(payload) {
    end := min(received + receiveChunk, len(payload))
    n, readErr := io.ReadFull(reader, payload[received:end])
    if n > 0 {
        _, err = h.SubmitRange(ctx, lease, received, n)
        if err != nil { /* handle error */ }
        received += n
    }
    if readErr == io.EOF || readErr == io.ErrUnexpectedEOF { break }
    if readErr != nil { /* handle error */ }
}
digest, err := h.Finish(ctx)
```

`SubmitRange` returns after enqueueing, so the next `ReadFull` can run while
QAT hashes the preceding range. QueueDepth bounds queued work and the producer
waits if hashing falls behind. The hash follows submission order. For a blob,
submit ranges in increasing offset order.

Each returned `Submission` has `Done()` and `Wait(ctx)`. Do not change a
submitted range until it completes. You may read/write disjoint regions of
the same payload in the meantime. Finish waits for all accepted ranges;
it is safe to release the lease after Finish succeeds. For arbitrary byte
counts, the stream carries up to 63 bytes in private DMA storage, ensuring
every nonfinal hardware update is a multiple of SHA-256's 64-byte block size.

The complete, compiled stdin example is
[`cmd/hashstdin/main.go`](cmd/hashstdin/main.go). It reads directly into the
single contiguous slice, submits ranges, checks errors, and drains hashing
before returning memory. It hashes up to `-bytes`, accepts short EOF, and
prints a standard hex SHA-256 digest.

## Other interfaces and lifetimes

- `Stream.Submit(ctx, lease, n)` transfers the whole lease to the worker. It
  automatically returns to its pool after QAT has read it. This is convenient
  when receiving the next blob into another buffer.
- `Stream.SubmitRange(ctx, lease, offset, n)` keeps the lease with the caller,
  reserving only that region. Overlapping active ranges are rejected.
- `Stream.Flush(ctx)` waits for accepted range reads without finalizing SHA-256.
- `Engine.HashReader(ctx, reader, pool)` provides a short reader-to-digest API,
  receiving into reusable pool buffers while previous buffers hash. It does
  not retain a whole input larger than one pool buffer.
- A canceled Submit leaves ownership with the caller if it returns an error.
  A successful Submit transfers ownership even if the context later expires.
- Canceling Finish/Wait bounds waiting. It does not revoke hardware DMA or
  interrupt an arbitrary `io.Reader`. Finish can be retried to get its result.
- `Stream.Cancel()` terminates hashing at a hardware-request boundary. It
  stops future requests, drains an accepted request, and discards the digest.
  It seals the stream and unblocks producers waiting for queue space.
- Cleanup order is stream Close, lease Release, pool Close, engine Close.
  Closing a pool with active leases, or an engine with child resources,
  returns `ErrInUse`. There are no GC finalizers freeing live DMA memory.
- A native hardware timeout quarantines affected buffers. Cleanup refuses
  unsafe frees; retain the objects and retry cleanup after hardware recovery.

Keep the lease alive for as long as any code uses its slices. A raw slice
retained after Release cannot be invalidated by Go; using it would race with
the next owner. Avoid append operations that grow/reallocate the payload.
The memory is C-owned and not counted as Go managed heap by the garbage
collector, so the pool size is the application's explicit memory budget.

## Cancellation boundary

The CPA symmetric interface used by this driver has **no per-request abort**.
Its [request ownership contract](https://github.com/undy-io/qat-legacy-linux/blob/main/quickassist/include/lac/cpa_cy_sym.h)
requires retaining memory until the completion callback, and removing a
session with outstanding requests fails. [Intel's lifecycle documentation](https://intel.github.io/quickassist/API_PG/QAT_cryptoAPI.html#ciphersample)
also requires draining outstanding requests before removing the session.
Stopping a partially hashed blob is supported by removing its session after
those requests complete; no final digest request is required.

`h.Cancel()` requests cooperative cancellation. The worker checks before
each native request, including retries and finalization. An accepted request,
or a submission racing with cancellation, must complete before its memory is
returned. With the default request size this means draining the current
**up to 4 MiB request**, rather than hashing the rest of the 256 MiB blob.
Device failures can extend that wait and still quarantine memory;
cancellation does not turn a hardware failure into a safe free.

After Cancel, call `h.Finish(context.Background())` to wait for the actual
drain. On ordinary cancellation it returns a zero digest and
`context.Canceled`; then the caller's range-based lease can be released.
Alternatively, wait for every active `Submission.Done()` before reusing its
ranges. Whole leases transferred with Submit return to the pool automatically.
Always Close the stream to remove its native session. The first successful
Close of a canceled stream also returns `context.Canceled`; later Close calls
return nil. Cancel is idempotent and has no effect on a completed result.
Concurrent native teardown may briefly hold Cancel/Progress's lifetime lock;
Cancel does not perform a drain of its own.

Contexts passed to Submit control queue admission; contexts passed to
Finish/Wait control waiting only. A deadline returning from either wait does
**not** establish DMA completion or permit buffer reuse. Cancel is explicit
so an HTTP/request deadline cannot silently change a buffer's ownership.
It does not interrupt a blocked reader; the application must arrange that
separately. No device reset is used to implement cancellation.

`Stream.Progress()` exposes actual accepted-request and completion-callback
counts, including finalization, for diagnostics. Counts are observational;
they do not replace Submission/Finish completion for ownership decisions.
`TestHardwareCancelAcceptedRequest` observes a real accepted request with
its callback pending, cancels it, verifies Release/Pool.Close are refused
until completion, checks that no later requests were submitted, and then
hashes successfully using the same buffer again. A long test-only poll
interval makes that observation reliable; it does not assert that the
silicon is still actively hashing at the instant of cancellation.

## Build and validate

Requirements: Linux, cgo, a C compiler, Go 1.22+, the
[legacy QAT stack](https://github.com/undy-io/qat-legacy-linux) SDK headers,
`/opt/qat/lib/{libqat_s,libusdm_drv_s}.so`, and a configured `SSL` crypto
application context. Build and install the driver/userspace stack first, load
the modules and start its configured devices. The application needs permission
to open the QAT and USDM devices; the hardware commands below use `sudo` on the
tested host. Running without hardware is possible only for the tests that
explicitly skip hardware access; compilation still requires the native SDK.

This module depends on the legacy USDM mapping ABI; it is not a generic
qatlib/VFIO allocator. Set SDK include directories explicitly when using the
module from another repository or the Go module cache. For example, from the
root of this repository, or before building a consumer:

```sh
export QAT_SOURCE=/path/to/qat-legacy-linux
export CGO_CFLAGS="-I$QAT_SOURCE/quickassist/include -I$QAT_SOURCE/quickassist/include/lac -I$QAT_SOURCE/quickassist/include/icp -I$QAT_SOURCE/quickassist/utilities/libusdm_drv"

make                      # builds qatbench, hashstdin, qatalloc and qatparallel
make test                 # hardware tests skip unless explicitly enabled
make hardware-test        # uses sudo for device permissions on the tested host
make race-test            # hardware + Go race detector + cgocheck2
make vet

printf abc | sudo ./hashstdin -bytes 268435456
sudo taskset -c 0,2 ./qatbench -iterations 5 -json run.json
sudo taskset -c 0,2 ./qatbench -tune -json tuning.json
sudo taskset -c 0,2 ./qatalloc -iterations 7 -warmup 1 -json allocation.json
sudo ./qatparallel -cases single,three1,three4 -iterations 3 -json parallel.json
```

Library linking and runtime lookup default to `/opt/qat/lib`. For a different
installation prefix, supply `CGO_LDFLAGS` with its `-L` and `-Wl,-rpath` paths.
The commands with CPU affinity or instance indexes describe the tested host;
adjust those selections to the local NUMA and QAT topology.

The Makefile uses `go` from `PATH`; `make GO=/path/to/go` selects another
installed toolchain. The development workspace also has a local-toolchain
fallback, which is not required for consumers.
`make QAT_SOURCE=/path/to/qat-legacy-linux` can supply the include paths for
the repository's commands and tests. Consumer builds still need `CGO_CFLAGS`.

The tested application configuration permits one process at a time. Within
that process, multiple Engine handles can open distinct crypto instances and
share one SAL/USDM runtime. Run hardware tests/benchmarks sequentially.

The test suite covers empty inputs, SHA-256 padding boundaries, allocation
boundaries, arbitrary partial lengths, queued ranges of the same contiguous
buffer, lease reuse, concurrent streams, reader errors, cancellation after
hardware acceptance, blocked-producer cancellation and cleanup. Results
are compared with Go `crypto/sha256`. The hardware race/cgo check run passed;
its inspected kernel output contained no QAT errors. Local diagnostic logs are
not published because they can contain unrelated host details.

## Measure sizes and polling

`qatbench` compares Go `crypto/sha256` with direct QAT CPA calls and verifies
every digest. It reports wall time and **whole-process CPU time**, including
the native worker. Pool allocation, initialization and session setup are
outside resident timings. Pool buffers are each full contiguous blobs.

```sh
# Tune request sizes 64 KiB..4 MiB, physical allocations 2/4 MiB, and polling.
# Then compare receive range sizes in the same contiguous blob.
sudo taskset -c 0,2 ./qatbench -tune -iterations 3 -warmup 1 -json tuning.json

# Simulated ingress, which is distinct from a network benchmark.
sudo taskset -c 0,2 ./qatbench -receive-chunk 4194304 -rate-mib 400 -poll-us 250
# Control: wait for each submitted range before receiving the next.
sudo taskset -c 0,2 ./qatbench -receive-chunk 4194304 -rate-mib 400 -poll-us 250 -serial
```

Allocation size, request size, and receive range size are separate settings.
The application can retain 256 MiB blobs regardless of those settings. More
pool buffers allow more blobs in flight, at the cost of full buffer memory;
two 256 MiB buffers use about 512 MiB of payload RAM. The alias view adds
virtual address mappings rather than a second copy of payload pages.

One buffer is sufficient for receiving and hashing different regions of the
same blob. A second full buffer is useful when receiving the next blob while
still processing the previous one; increase the count to match actual
application concurrency rather than allocating spare full blobs by default.

The staged tuning shortlist identifies the fastest measured configuration,
not a universal optimum. Measure with your actual reader and concurrency
before choosing production values. One SHA-256 state is serial: this engine
serializes native operations on its selected instance, while the producer can
run concurrently. Use `qatparallel` to measure aggregate throughput across
distinct instances and endpoints.

## Parallel independent blobs across the three endpoints

The host has three physical QAT endpoints: `0000:3d:00.0`, `0000:3f:00.0`
and `0000:41:00.0`. Its 48 local VFs expose 96 configured crypto instances.
An API instance is a queue/channel, rather than a dedicated physical compute
engine. [Intel's load-balancing documentation](https://intel.github.io/quickassist/PG/infrastructure_load_balancing.html)
describes hardware arbitration within an endpoint and application-directed
distribution across endpoints.

`Open(Options{Instance: index, PollInterval: DefaultPollInterval})` can now be
called for several **distinct indexes** in the same process. Initialization
of SAL and USDM occurs once, and the last Engine close shuts them down. Each
Engine owns its pools and sessions and serializes its own native requests;
different Engine handles can have hardware requests outstanding concurrently.
Duplicate opens of one index are rejected. Closing one Engine preserves the
other Engines and their allocations, including active hashes.

For this host's current configuration, indexes **0, 32 and 64** select a VF
on each physical endpoint. Indexes 0..31, 32..63 and 64..95 select instances
on the corresponding endpoints. Check `Engine.Info().PCI` when configuring
another system: enumeration indexes are not a portable topology guarantee.
The benchmark checks each selected instance's actual PCI bus.

Create a fixed pool per selected Engine and route each incoming blob to one
of those pools, for example round robin. All ranges of that blob use the
same Engine/Stream. A buffer belongs to its pool's Engine; cross-Engine
submissions are rejected. Multiple streams sharing one Engine remain a
correctness/concurrency interface, while its native mutex serializes their
hardware work. Independent instances provide the measured throughput gain.

Chunks of one standard SHA-256 digest preserve an ordered state. The CPA
interface permits queuing later partial requests before earlier callbacks,
but this legacy driver queues those requests in software until the preceding
partial response (`lac_sym_queue.c` and `lac_sym_cb.c`). Prequeuing could reduce
host handoff gaps; it does not create independent SHA states for one blob.
[Intel recommends multiple sessions](https://intel.github.io/quickassist/PERF/design_guidelines.html#symmetric-crypto-partial-operations)
to keep hardware busy when using partial operations. This module uses one
accepted request at a time per instance and overlaps requests from different
instances. These measurements do not isolate internal DMA and compute stages.

[`cmd/qatparallel/main.go`](cmd/qatparallel/main.go) measures synchronized
batches of independent blobs, verifies every digest against Go SHA-256, and
compares CPU workers using the same resident buffers. It excludes allocation,
initial filling, engine startup, session setup and cleanup. Process CPU time
is measured once for the entire batch. Worker count determines the number of
full-size buffers, so the memory cost remains explicit.

```sh
# This host: node 0 CPUs, matching the QAT endpoints and DMA allocations.
sudo taskset -c 0,2,4,6,8,10,12,14,16,18,20,22,24,26,28,30,32,34,36,38,40,42,44,46,48,50,52,54 \
    ./qatparallel -cases all -iterations 3 -warmup 1 -json parallel.json
```

[`parallel-256mib.json`](parallel-256mib.json) records three measured batches
after one warmup for each case, with 256 MiB per blob, 4 MiB allocations and
requests, and 250 microsecond polling:

| Physical endpoints / independent instances | Buffers | Payload RAM | QAT MiB/s | CPU MiB/s |
| --- | ---: | ---: | ---: | ---: |
| One endpoint / one instance | 1 | 256 MiB | 580.37 | 340.38 |
| One endpoint / one instance, three serialized streams | 3 | 768 MiB | 580.96 | 1,017.76 |
| One endpoint / eight instances | 8 | 2 GiB | 4,475.78 | 2,582.22 |
| One endpoint / sixteen instances | 16 | 4 GiB | 5,691.49 | 4,029.65 |
| Three endpoints / one instance each | 3 | 768 MiB | 1,724.70 | 1,017.76 |
| Three endpoints / two instances each | 6 | 1.5 GiB | 3,421.02 | 1,996.06 |
| Three endpoints / four instances each | 12 | 3 GiB | 6,805.49 | 3,609.84 |
| Three endpoints / eight instances each | 24 | 6 GiB | **12,796.24** | **4,815.17** |

The largest measured case achieved **12.50 GiB/s**, about **22.05 times**
single-stream QAT throughput and **2.66 times** CPU throughput at the same
24-worker concurrency. QAT used 20.157 process CPU ms/blob compared with
1,180.916 for CPU hashing. The 24-blob batch completed in 480.141 ms on QAT
versus 1,275.967 ms on CPU. Mean individual QAT blob latency was 471.281 ms,
compared with 441.095 ms for one stream. This improves aggregate throughput;
it does not reduce one blob's hashing time by the throughput scaling factor.

All data was already resident in the reusable DMA buffers. Input I/O and
allocator cost will change application-level throughput. The tested range
does not establish a maximum hardware throughput or optimal production
concurrency. Choose the number of pooled buffers against the application's
memory budget and required throughput. CPU tests used node 0's 28 logical
CPUs (14 physical cores); repeated worker counts share one measured CPU
baseline, identified in the JSON.

The completed hardware race/cgocheck2 suite includes real accepted requests
pending across
all three endpoints, distinct payloads/digests, close of an idle instance
while others work, failed/duplicate opens, cross-Engine ownership rejection
and reuse after another Engine closes. Pending callbacks alone do not prove
simultaneous execution inside silicon; the throughput experiment measures
the resulting scaling.

### Receive/hash overlap within one blob

The separate [`receive-overlap.json`](receive-overlap.json) and
[`receive-serial.json`](receive-serial.json) runs compare the existing streaming
pipeline with a control that waits for QAT after every received range. Both
use a single contiguous 256 MiB buffer, 4 MiB ranges/requests, 250 microsecond
polling, CPUs 0/2, three measured runs and one warmup:

| Synthetic ingress mode | Mean wall ms/blob | MiB/s |
| --- | ---: | ---: |
| Write next range while QAT hashes the preceding range | 445.338 | 574.84 |
| Wait for each range before writing the next | 497.794 | 514.27 |

This measured **1.118 times** throughput from overlapping CPU writes with
QAT work. Resident hashing in the corresponding runs stayed at approximately
441.5 ms. All digests matched Go SHA-256. The input is an unpaced synthetic
memory write, not a network/storage benchmark. It demonstrates producer/QAT
overlap; the card's internal DMA and compute stages were not timed separately.

## Allocate per blob or retain the buffer?

`qatalloc` runs a simple experiment with the engine kept initialized: either
allocate and destroy a one-buffer pool for each blob, or acquire/release a
buffer from one retained pool. Both paths fill all bytes, create a SHA-256
session, submit the blob, wait for completion and close the session. Every
digest is checked against Go's SHA-256 reference outside the timed interval.

```sh
sudo taskset -c 0,2 ./qatalloc -iterations 7 -warmup 1 -json allocation.json
```

[`allocation-256mib.json`](allocation-256mib.json) records this host's experiment:
256 MiB blobs, 4 MiB allocations/requests, 250 microsecond polling, seven
measured rounds after one warmup. Fresh/reuse order alternated each round.

| Mean per blob | Retained pool | Fresh allocation/free |
| --- | ---: | ---: |
| Allocate DMA storage and map contiguous slice | — | 54.009 ms |
| Free DMA storage and unmap | — | 17.344 ms |
| Acquire, obtain slice and release lease | 0.004 ms | 0.011 ms |
| Synthetic fill of all 256 MiB | 69.047 ms | 85.522 ms |
| SHA-256 including session setup/close | 442.551 ms | 442.276 ms |
| Total | **511.604 ms** | **599.164 ms** |

Fresh allocation/free added **71.354 ms** directly. The measured whole-blob
total increased **87.561 ms (17.11%)**, including a difference in synthetic
fill time; the whole difference should not be attributed to allocator calls.
Retaining a bounded pool is the measured faster choice for repeated blobs.
Freeing an idle buffer remains possible when reclaiming RAM matters more
than that per-blob cost.

The retained pool's one-time allocation/free measured 59.194/7.926 ms and is
excluded from its per-blob row. The first fresh pool after engine startup
measured 47.177/24.227 ms for allocation/free, separately from the averages;
this is not a cold-boot measurement. Engine startup/shutdown is excluded.
The fill is a synthetic memory write rather than network I/O. At most two
full-size payload buffers coexist during the comparison, about 512 MiB;
normal reuse can use one. Raw samples and all timing boundaries are available
in [`cmd/qatalloc/main.go`](cmd/qatalloc/main.go).

## Measured defaults on this host

The defaults use **4 MiB physical allocations, 4 MiB QAT requests and receive
ranges, queue depth 2**, and a **250 microsecond poll delay** with
`Open(DefaultOptions())`. Explicit `Open(Options{})` retains busy polling.
These settings preserve one contiguous 256 MiB application slice.

`tuning-256mib.json` records the 13-configuration shortlist (3 measured runs
and 1 warmup per backend). `balanced-4mib.json` confirms the selected settings
with 5 measured runs and 1 warmup, using only one full-size buffer:

| Path | Wall ms/blob | Process CPU ms/blob | MiB/s |
| --- | ---: | ---: | ---: |
| Go SHA-256, data ready in RAM | 729.084 | 730.926 | 351.13 |
| QAT, data ready in DMA memory | 441.842 | 22.216 | 579.39 |
| Receive synthetic 4 MiB ranges and hash on QAT | 445.800 | 88.352 | 574.25 |

The last row includes writing all 256 MiB into the application's buffer; it
is an unpaced receive simulation rather than network I/O. All digests matched.
Compared with approximately 436 ms/438 CPU ms for busy polling, the selected
poll delay spends about 22 CPU ms at about 442 ms elapsed for ready data.
The 1 MiB receive-range variant measured about 488 ms with this poll delay;
4 MiB ranges measured about 446 ms. Two MiB allocations/requests also work,
measuring about 445 ms ready and 453 ms including synthetic receive writes.

Runs were restricted to node 0 CPUs 0 and 2 with `taskset`, using the node 0
VF `3d:01.0`, Xeon Gold 6132, Go 1.27.4, QAT driver 4.28.0 and Linux
7.0.0-43-generic. Process CPU measurements include the Go runtime and C
worker. Larger receive batches add startup latency; tune them with the real
reader rather than treating this host's shortlist as a universal optimum.

Background: [cgo pointer rules](https://pkg.go.dev/cmd/cgo#hdr-Passing_pointers)
and [Intel QAT buffer models](https://intel.github.io/quickassist/API_PG/baseAPI.html).
