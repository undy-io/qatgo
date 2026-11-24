#ifndef QATGO_NATIVE_H
#define QATGO_NATIVE_H

#include <stddef.h>
#include <stdint.h>

typedef struct qg_engine qg_engine;
typedef struct qg_hash qg_hash;
typedef struct qg_buffer qg_buffer;

/* Functions return zero on success, minus one and a diagnostic on error,
 * except update also returns one for cooperative cancellation before submit.
 * All handles and DMA storage belong to C; no Go pointer is retained. */
/* Distinct instance handles share one process-wide SAL/USDM runtime. Opening
 * an already-owned instance fails. Each engine submits and polls independently;
 * close stops global services only after the final engine has closed. */
int qg_open(unsigned instance, unsigned poll_us, qg_engine **out,
            char *err, size_t errlen);
int qg_close(qg_engine *engine, char *err, size_t errlen);
void qg_info(qg_engine *engine, unsigned *node, unsigned *bdf);

int qg_buffer_alloc(qg_engine *engine, size_t bytes, qg_buffer **out,
                    char *err, size_t errlen);
void *qg_buffer_data(qg_buffer *buffer);
void qg_buffer_free(qg_buffer *buffer);

int qg_hash_new(qg_engine *engine, qg_hash **out, char *err, size_t errlen);
/* Nonfinal updates must be positive multiples of SHA256's 64-byte block.
 * Final updates may be empty. Buffer may be NULL only when length is zero.
 * A digest is returned only for final updates. Calls wait for completion.
 * Return one means canceled before acceptance, with no request outstanding.
 * On error the caller must not reuse the submitted buffer until hash_free
 * succeeds. A failed hash cannot be updated again. */
int qg_hash_update(qg_hash *hash, qg_buffer *buffer, size_t offset,
                   size_t length, int final, unsigned char digest[32],
                   char *err, size_t errlen);
/* Observational counters; do not imply that a buffer lease can be released.
 * Safe during update, but the caller must prevent concurrent hash_free. */
void qg_hash_progress(qg_hash *hash, uint64_t *submitted, uint64_t *completed);
/* Stops future attempts; never aborts an accepted request. */
void qg_hash_request_cancel(qg_hash *hash);
/* A failure preserves the hash and its DMA allocations; retry is permitted. */
int qg_hash_free(qg_hash *hash, uint64_t *submitted, uint64_t *completed,
                 char *err, size_t errlen);

#endif
