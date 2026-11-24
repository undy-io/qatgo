#ifndef QATGO_ALIAS_H
#define QATGO_ALIAS_H

#include "native.h"

/* Map whole 2 MiB or 4 MiB qae NUMA allocations into one contiguous virtual
 * address range. The caller retains ownership of every original block and
 * must keep them alive until qg_alias_destroy succeeds. These mappings are
 * additional views of the same DMA memory; they do not copy its contents.
 * On success, mapped_bytes is count * block_bytes and base is page aligned.
 * On failure, both outputs are cleared and the originals remain untouched. */
int qg_alias_create(qg_buffer **blocks, size_t count, size_t block_bytes,
                     void **base, size_t *mapped_bytes,
                     char *err, size_t errlen);

/* Unmap the alias range before freeing any original block. A failed unmap
 * preserves ownership of the range. Passing NULL and zero is a no-op. */
int qg_alias_destroy(void *base, size_t mapped_bytes,
                      char *err, size_t errlen);

#endif
