#define _POSIX_C_SOURCE 200809L
#include "native.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "icp_sal_poll.h"
#include "icp_sal_user.h"
#include "qae_mem.h"

/* These lifecycle functions are exported by the legacy USDM library but
 * omitted from its public qae_mem.h, as in Intel's functional samples. */
extern int32_t qaeMemInit(void);
extern void qaeMemDestroy(void);

#define QG_MAX_BUFFER (4U * 1024U * 1024U)
#define QG_MAX_HASH_BYTES (UINT32_MAX - UINT64_C(64))
#define QG_WAIT_SECONDS 30.0

struct qg_engine {
    pthread_mutex_t mutex;
    CpaInstanceHandle instance;
    CpaInstanceInfo2 info;
    struct qg_engine *runtime_next;
    size_t buffers, hashes;
    unsigned poll_us;
    bool instance_started, poisoned;
};

/* SAL and USDM are process-wide services. Only their startup, shutdown and
 * instance ownership registry share this lock; DMA work holds the selected
 * engine's mutex, so independent instances can submit and poll concurrently.
 * When both locks are needed, acquire runtime_mutex before engine->mutex. */
static pthread_mutex_t runtime_mutex = PTHREAD_MUTEX_INITIALIZER;
static qg_engine *runtime_engines;
static size_t runtime_users;
static bool runtime_mem_started, runtime_sal_started;

struct qg_buffer {
    qg_engine *engine;
    void *data;
    size_t bytes;
    unsigned references;
    bool released;
};

struct qg_hash {
    qg_engine *engine;
    CpaCySymSessionCtx session;
    Cpa8U *digest, *empty;
    CpaBufferList list;
    CpaFlatBuffer flat;
    CpaCySymOpData op;
    qg_buffer *pending_buffer;
    uint64_t bytes;
    atomic_uint_fast64_t submitted, completed;
    atomic_bool cancel_requested;
    bool session_started, started, finished, failed, pending;
    volatile bool done;
    CpaStatus completion_status;
};

static int error(char *err, size_t len, const char *format, ...)
{
    if (err && len) {
        va_list args;
        va_start(args, format);
        vsnprintf(err, len, format, args);
        va_end(args);
    }
    return -1;
}

static int status_error(char *err, size_t len, const char *operation,
                        CpaStatus status)
{
    return error(err, len, "%s: QAT status %d", operation, (int)status);
}

/* Called with runtime_mutex held and no registered engines. Keep a failed SAL
 * stop initialized: destroying its allocator could invalidate retained state.
 * A later open can reuse the runtime and a later final close retries cleanup. */
static CpaStatus runtime_stop_unused(void)
{
    if (runtime_users) return CPA_STATUS_SUCCESS;
    if (runtime_sal_started) {
        CpaStatus status = icp_sal_userStop();
        if (status != CPA_STATUS_SUCCESS) return status;
        runtime_sal_started = false;
    }
    if (runtime_mem_started) {
        qaeMemDestroy();
        runtime_mem_started = false;
    }
    return CPA_STATUS_SUCCESS;
}

static double monotonic_seconds(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + (double)now.tv_nsec * 1e-9;
}

static void poll_pause(qg_engine *engine)
{
    if (engine->poll_us) {
        struct timespec delay = {
            .tv_sec = engine->poll_us / 1000000U,
            .tv_nsec = (long)(engine->poll_us % 1000000U) * 1000L
        };
        nanosleep(&delay, NULL);
    }
}

static bool poll_ok(CpaStatus status)
{
    return status == CPA_STATUS_SUCCESS || status == CPA_STATUS_RETRY;
}

static void *dma_alloc(qg_engine *engine, size_t bytes)
{
    return qaeMemAllocNUMA(bytes ? bytes : 1, engine->info.nodeAffinity, 64);
}

static void buffer_destroy_locked(qg_buffer *buffer)
{
    qaeMemFreeNUMA(&buffer->data);
    --buffer->engine->buffers;
    free(buffer);
}

/* Called only after the completion callback has run. */
static void release_pending_locked(qg_hash *hash)
{
    hash->pending = false;
    if (hash->pending_buffer) {
        qg_buffer *buffer = hash->pending_buffer;
        hash->pending_buffer = NULL;
        --buffer->references;
        if (!buffer->references && buffer->released)
            buffer_destroy_locked(buffer);
    }
}

static void completion(void *tag, CpaStatus status,
                       const CpaCySymOp operation, void *op_data,
                       CpaBufferList *destination, CpaBoolean verified)
{
    (void)operation;
    (void)op_data;
    (void)destination;
    (void)verified;
    qg_hash *hash = tag;
    hash->completion_status = status;
    atomic_fetch_add_explicit(&hash->completed, 1, memory_order_release);
    hash->done = true;
}

int qg_open(unsigned index, unsigned poll_us, qg_engine **out,
            char *err, size_t errlen)
{
    if (!out) return error(err, errlen, "nil engine output");
    *out = NULL;
    qg_engine *engine = calloc(1, sizeof(*engine));
    if (!engine) return error(err, errlen, "cannot allocate engine");
    int mutex_status = pthread_mutex_init(&engine->mutex, NULL);
    if (mutex_status) {
        free(engine);
        return error(err, errlen, "cannot initialize engine mutex: %d", mutex_status);
    }
    engine->poll_us = poll_us;
    CpaInstanceHandle *instances = NULL;
    CpaStatus status;
    pthread_mutex_lock(&runtime_mutex);
    for (qg_engine *current = runtime_engines; current;
         current = current->runtime_next) {
        if (!current->instance_started) {
            error(err, errlen, "QAT runtime shutdown is incomplete; retry closing its stopped engine");
            goto fail;
        }
    }
    if (!runtime_mem_started) {
        if (qaeMemInit()) {
            error(err, errlen, "cannot initialize QAT USDM allocator; check driver access/root permissions");
            goto fail;
        }
        runtime_mem_started = true;
    }
    if (!runtime_sal_started) {
        status = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
        if (status != CPA_STATUS_SUCCESS) {
            status_error(err, errlen, "start SSL application", status);
            goto fail;
        }
        runtime_sal_started = true;
    }
    Cpa16U count = 0;
    status = cpaCyGetNumInstances(&count);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "get crypto instance count", status);
        goto fail;
    }
    if (index >= count) {
        error(err, errlen, "crypto instance %u unavailable (count %u)", index, count);
        goto fail;
    }
    instances = calloc(count, sizeof(*instances));
    if (!instances) {
        error(err, errlen, "cannot allocate crypto instance list");
        goto fail;
    }
    status = cpaCyGetInstances(count, instances);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "get crypto instances", status);
        goto fail;
    }
    engine->instance = instances[index];
    free(instances);
    instances = NULL;
    for (qg_engine *current = runtime_engines; current;
         current = current->runtime_next) {
        if (current->instance == engine->instance) {
            error(err, errlen, "crypto instance %u is already open", index);
            goto fail;
        }
    }
    status = cpaCyInstanceGetInfo2(engine->instance, &engine->info);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "query crypto instance", status);
        goto fail;
    }
    if (!engine->info.isPolled) {
        error(err, errlen, "selected crypto instance is not polled");
        goto fail;
    }
    CpaCySymCapabilitiesInfo caps = {0};
    status = cpaCySymQueryCapabilities(engine->instance, &caps);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "query crypto capabilities", status);
        goto fail;
    }
    if (!caps.partialPacketSupported ||
        !CPA_BITMAP_BIT_TEST(caps.hashes, CPA_CY_SYM_HASH_SHA256)) {
        error(err, errlen, "instance does not support streaming SHA256");
        goto fail;
    }
    status = cpaCySetAddressTranslation(engine->instance, qaeVirtToPhysNUMA);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "set DMA address translation", status);
        goto fail;
    }
    status = cpaCyStartInstance(engine->instance);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "start crypto instance", status);
        goto fail;
    }
    engine->instance_started = true;
    engine->runtime_next = runtime_engines;
    runtime_engines = engine;
    ++runtime_users;
    *out = engine;
    pthread_mutex_unlock(&runtime_mutex);
    return 0;

fail:
    free(instances);
    /* No failing work follows a successful instance start, so this engine
     * cannot own a running instance here. Existing engines remain untouched. */
    (void)runtime_stop_unused();
    pthread_mutex_unlock(&runtime_mutex);
    pthread_mutex_destroy(&engine->mutex);
    free(engine);
    return -1;
}

void qg_info(qg_engine *engine, unsigned *node, unsigned *bdf)
{
    if (node) *node = engine->info.nodeAffinity;
    if (bdf) *bdf = engine->info.physInstId.busAddress;
}

int qg_close(qg_engine *engine, char *err, size_t errlen)
{
    if (!engine) return 0;
    pthread_mutex_lock(&runtime_mutex);
    pthread_mutex_lock(&engine->mutex);
    if (engine->hashes || engine->buffers) {
        size_t hashes = engine->hashes, buffers = engine->buffers;
        pthread_mutex_unlock(&engine->mutex);
        pthread_mutex_unlock(&runtime_mutex);
        return error(err, errlen, "engine still owns %zu hashes and %zu DMA buffers", hashes, buffers);
    }
    CpaStatus status;
    if (engine->instance_started) {
        status = cpaCyStopInstance(engine->instance);
        if (status != CPA_STATUS_SUCCESS) {
            pthread_mutex_unlock(&engine->mutex);
            pthread_mutex_unlock(&runtime_mutex);
            return status_error(err, errlen, "stop crypto instance", status);
        }
        engine->instance_started = false;
    }
    if (runtime_users == 1 && runtime_sal_started) {
        status = icp_sal_userStop();
        if (status != CPA_STATUS_SUCCESS) {
            pthread_mutex_unlock(&engine->mutex);
            pthread_mutex_unlock(&runtime_mutex);
            return status_error(err, errlen, "stop SSL application", status);
        }
        runtime_sal_started = false;
    }
    qg_engine **link = &runtime_engines;
    while (*link != engine) link = &(*link)->runtime_next;
    *link = engine->runtime_next;
    --runtime_users;
    (void)runtime_stop_unused();
    pthread_mutex_unlock(&engine->mutex);
    pthread_mutex_unlock(&runtime_mutex);
    pthread_mutex_destroy(&engine->mutex);
    free(engine);
    return 0;
}

int qg_buffer_alloc(qg_engine *engine, size_t bytes, qg_buffer **out,
                    char *err, size_t errlen)
{
    if (!engine || !out) return error(err, errlen, "nil engine or buffer output");
    *out = NULL;
    if (!bytes || bytes > QG_MAX_BUFFER)
        return error(err, errlen, "DMA allocation must contain 1..%u bytes", QG_MAX_BUFFER);
    pthread_mutex_lock(&engine->mutex);
    if (!engine->instance_started) {
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "QAT instance is stopped; retry engine close");
    }
    if (engine->poisoned) {
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "QAT engine is quarantined after a polling failure or timeout");
    }
    qg_buffer *buffer = calloc(1, sizeof(*buffer));
    if (buffer) {
        buffer->engine = engine;
        buffer->bytes = bytes;
        buffer->data = dma_alloc(engine, bytes);
    }
    if (!buffer || !buffer->data) {
        free(buffer);
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "cannot allocate %zu bytes of QAT DMA memory", bytes);
    }
    ++engine->buffers;
    *out = buffer;
    pthread_mutex_unlock(&engine->mutex);
    return 0;
}

void *qg_buffer_data(qg_buffer *buffer)
{
    return buffer ? buffer->data : NULL;
}

void qg_buffer_free(qg_buffer *buffer)
{
    if (!buffer) return;
    qg_engine *engine = buffer->engine;
    pthread_mutex_lock(&engine->mutex);
    if (buffer->references)
        buffer->released = true;
    else
        buffer_destroy_locked(buffer);
    pthread_mutex_unlock(&engine->mutex);
}

static void hash_destroy_dma(qg_hash *hash)
{
    if (hash->session) qaeMemFreeNUMA((void **)&hash->session);
    if (hash->list.pPrivateMetaData) qaeMemFreeNUMA(&hash->list.pPrivateMetaData);
    if (hash->digest) qaeMemFreeNUMA((void **)&hash->digest);
    if (hash->empty) qaeMemFreeNUMA((void **)&hash->empty);
}

int qg_hash_new(qg_engine *engine, qg_hash **out, char *err, size_t errlen)
{
    if (!engine || !out) return error(err, errlen, "nil engine or hash output");
    *out = NULL;
    pthread_mutex_lock(&engine->mutex);
    if (!engine->instance_started) {
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "QAT instance is stopped; retry engine close");
    }
    if (engine->poisoned) {
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "QAT engine is quarantined after a polling failure or timeout");
    }
    qg_hash *hash = calloc(1, sizeof(*hash));
    if (!hash) {
        pthread_mutex_unlock(&engine->mutex);
        return error(err, errlen, "cannot allocate SHA256 state");
    }
    hash->engine = engine;
    atomic_init(&hash->submitted, 0);
    atomic_init(&hash->completed, 0);
    atomic_init(&hash->cancel_requested, false);
    CpaCySymSessionSetupData setup = {0};
    setup.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    setup.symOperation = CPA_CY_SYM_OP_HASH;
    setup.hashSetupData.hashAlgorithm = CPA_CY_SYM_HASH_SHA256;
    setup.hashSetupData.hashMode = CPA_CY_SYM_HASH_MODE_PLAIN;
    setup.hashSetupData.digestResultLenInBytes = 32;
    setup.partialsNotRequired = CPA_FALSE;
    setup.digestIsAppended = CPA_FALSE;
    setup.verifyDigest = CPA_FALSE;
    Cpa32U session_bytes = 0, meta_bytes = 0;
    CpaStatus status = cpaCySymSessionCtxGetSize(engine->instance, &setup, &session_bytes);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "query SHA256 session size", status);
        goto fail;
    }
    status = cpaCyBufferListGetMetaSize(engine->instance, 1, &meta_bytes);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "query buffer metadata size", status);
        goto fail;
    }
    hash->session = dma_alloc(engine, session_bytes);
    hash->list.pPrivateMetaData = dma_alloc(engine, meta_bytes);
    hash->digest = dma_alloc(engine, 32);
    hash->empty = dma_alloc(engine, 64);
    if (!hash->session || !hash->list.pPrivateMetaData || !hash->digest || !hash->empty) {
        error(err, errlen, "cannot allocate SHA256 DMA state");
        goto fail;
    }
    memset(hash->session, 0, session_bytes);
    memset(hash->empty, 0, 64);
    hash->list.numBuffers = 1;
    hash->list.pBuffers = &hash->flat;
    status = cpaCySymInitSession(engine->instance, completion, &setup, hash->session);
    if (status != CPA_STATUS_SUCCESS) {
        status_error(err, errlen, "initialize SHA256 session", status);
        goto fail;
    }
    hash->session_started = true;
    ++engine->hashes;
    *out = hash;
    pthread_mutex_unlock(&engine->mutex);
    return 0;

fail:
    hash_destroy_dma(hash);
    free(hash);
    pthread_mutex_unlock(&engine->mutex);
    return -1;
}

int qg_hash_update(qg_hash *hash, qg_buffer *buffer, size_t offset,
                   size_t length, int final, unsigned char digest[32],
                   char *err, size_t errlen)
{
    if (!hash) return error(err, errlen, "nil SHA256 state");
    qg_engine *engine = hash->engine;
    pthread_mutex_lock(&engine->mutex);
    int result = -1;
    if (engine->poisoned) {
        error(err, errlen, "QAT engine is quarantined after a polling failure or timeout");
        goto out;
    }
    if (hash->finished || hash->failed || hash->pending) {
        error(err, errlen, "SHA256 state is already finalized, failed, or pending");
        goto out;
    }
    if ((!final && (!length || length % 64)) || (final && !digest)) {
        error(err, errlen, "nonfinal SHA256 updates require positive multiples of 64; final requires digest output");
        goto out;
    }
    if (length && (!buffer || buffer->engine != engine || buffer->released ||
                   offset > buffer->bytes || length > buffer->bytes - offset)) {
        error(err, errlen, "SHA256 update is outside its DMA buffer or uses a different engine");
        goto out;
    }
    if (length > QG_MAX_BUFFER || hash->bytes + length > QG_MAX_HASH_BYTES) {
        error(err, errlen, "SHA256 request exceeds the per-buffer or legacy partial-hash size limit");
        goto out;
    }
    hash->flat.pData = length ? (Cpa8U *)buffer->data + offset : hash->empty;
    hash->flat.dataLenInBytes = length ? (Cpa32U)length : 64;
    memset(&hash->op, 0, sizeof(hash->op));
    hash->op.sessionCtx = hash->session;
    hash->op.packetType = final ? (hash->started ? CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL
                                               : CPA_CY_SYM_PACKET_TYPE_FULL)
                                : CPA_CY_SYM_PACKET_TYPE_PARTIAL;
    hash->op.messageLenToHashInBytes = (Cpa32U)length;
    hash->op.pDigestResult = hash->digest;
    hash->done = false;
    hash->completion_status = CPA_STATUS_FAIL;
    double deadline = monotonic_seconds() + QG_WAIT_SECONDS;
    CpaStatus status;
    for (;;) {
        /* Recheck after waiting for the engine gate and on submission retry.
         * This flag has no effect once CPA has accepted the request. */
        if (atomic_load_explicit(&hash->cancel_requested, memory_order_acquire)) {
            result = 1;
            goto out;
        }
        status = cpaCySymPerformOp(engine->instance, hash, &hash->op,
                                   &hash->list, &hash->list, NULL);
        if (status != CPA_STATUS_RETRY) break;
        CpaStatus poll_status = icp_sal_CyPollInstance(engine->instance, 0);
        if (!poll_ok(poll_status)) {
            engine->poisoned = true;
            hash->failed = true;
            status_error(err, errlen, "poll during SHA256 submission", poll_status);
            goto out;
        }
        if (monotonic_seconds() >= deadline) {
            hash->failed = true;
            error(err, errlen, "SHA256 submission timed out after 30 seconds");
            goto out;
        }
        poll_pause(engine);
    }
    if (status != CPA_STATUS_SUCCESS) {
        hash->failed = true;
        status_error(err, errlen, "submit SHA256 update", status);
        goto out;
    }
    hash->pending = true;
    if (length) {
        hash->pending_buffer = buffer;
        ++buffer->references;
    }
    atomic_fetch_add_explicit(&hash->submitted, 1, memory_order_release);
    while (!hash->done) {
        status = icp_sal_CyPollInstance(engine->instance, 0);
        if (!poll_ok(status)) {
            engine->poisoned = true;
            hash->failed = true;
            status_error(err, errlen, "poll SHA256 completion; DMA state retained", status);
            goto out;
        }
        if (!hash->done && monotonic_seconds() >= deadline) {
            engine->poisoned = true;
            hash->failed = true;
            error(err, errlen, "SHA256 completion timed out after 30 seconds; DMA state retained");
            goto out;
        }
        if (!hash->done) poll_pause(engine);
    }
    release_pending_locked(hash);
    if (hash->completion_status != CPA_STATUS_SUCCESS) {
        hash->failed = true;
        status_error(err, errlen, "complete SHA256 update", hash->completion_status);
        goto out;
    }
    hash->bytes += length;
    hash->started = true;
    if (final) {
        hash->finished = true;
        memcpy(digest, hash->digest, 32);
    }
    result = 0;
out:
    pthread_mutex_unlock(&engine->mutex);
    return result;
}

void qg_hash_progress(qg_hash *hash, uint64_t *submitted, uint64_t *completed)
{
    /* Completion callbacks run only when this module polls the instance, so
     * acceptance is recorded before any callback can run. Read completed first
     * to avoid reporting completed > submitted across an update boundary. */
    if (completed)
        *completed = atomic_load_explicit(&hash->completed, memory_order_acquire);
    if (submitted)
        *submitted = atomic_load_explicit(&hash->submitted, memory_order_acquire);
}

void qg_hash_request_cancel(qg_hash *hash)
{
    atomic_store_explicit(&hash->cancel_requested, true, memory_order_release);
}

int qg_hash_free(qg_hash *hash, uint64_t *submitted, uint64_t *completed,
                 char *err, size_t errlen)
{
    if (!hash) return 0;
    qg_engine *engine = hash->engine;
    pthread_mutex_lock(&engine->mutex);
    if (hash->pending) {
        CpaStatus status = icp_sal_CyPollInstance(engine->instance, 0);
        if (!hash->done) {
            pthread_mutex_unlock(&engine->mutex);
            return error(err, errlen, "SHA256 request remains in flight (poll status %d); DMA state retained", (int)status);
        }
        release_pending_locked(hash);
    }
    if (hash->session_started) {
        CpaStatus status = cpaCySymRemoveSession(engine->instance, hash->session);
        if (status != CPA_STATUS_SUCCESS) {
            pthread_mutex_unlock(&engine->mutex);
            return status_error(err, errlen, "remove SHA256 session; DMA state retained", status);
        }
    }
    qg_hash_progress(hash, submitted, completed);
    hash_destroy_dma(hash);
    --engine->hashes;
    free(hash);
    pthread_mutex_unlock(&engine->mutex);
    return 0;
}
