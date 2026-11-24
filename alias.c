#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "alias.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "qae_mem.h"

#define QG_MIB ((size_t)1024 * 1024)

static int alias_error(char *err, size_t len, const char *format, ...)
{
    if (err && len) {
        va_list args;
        va_start(args, format);
        vsnprintf(err, len, format, args);
        va_end(args);
    }
    return -1;
}

int qg_alias_create(qg_buffer **blocks, size_t count, size_t block_bytes,
                     void **base, size_t *mapped_bytes,
                     char *err, size_t errlen)
{
    if (base)
        *base = NULL;
    if (mapped_bytes)
        *mapped_bytes = 0;
    if (!base || !mapped_bytes || !blocks || !count)
        return alias_error(err, errlen, "DMA alias requires blocks and output pointers");
    if (block_bytes != 2 * QG_MIB && block_bytes != 4 * QG_MIB)
        return alias_error(err, errlen, "DMA alias block size must be exactly 2 MiB or 4 MiB");
    if (count > SIZE_MAX / block_bytes)
        return alias_error(err, errlen, "DMA alias size overflows size_t");

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || block_bytes % (size_t)page_size)
        return alias_error(err, errlen, "DMA alias requires a compatible system page size");

    /* Validate every handle before reserving or replacing any virtual pages.
     * Whole LARGE allocations start at the mmap handle returned by USDM. */
    for (size_t i = 0; i < count; ++i) {
        void *original = qg_buffer_data(blocks[i]);
        if (!original || (uintptr_t)original % (size_t)page_size)
            return alias_error(err, errlen, "DMA alias block %zu is not page aligned", i);
        uint64_t handle = qaeVirtToPhysNUMA(original);
        if (!handle || handle % (size_t)page_size ||
            (off_t)handle < 0 || (uint64_t)(off_t)handle != handle)
            return alias_error(err, errlen, "DMA alias block %zu has an invalid USDM mmap handle", i);
    }

    int fd = open("/dev/usdm_drv", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return alias_error(err, errlen, "open /dev/usdm_drv for DMA alias: %s", strerror(errno));

    size_t bytes = count * block_bytes;
    void *reserved = mmap(NULL, bytes, PROT_NONE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserved == MAP_FAILED) {
        int saved_errno = errno;
        close(fd);
        return alias_error(err, errlen, "reserve DMA alias virtual memory: %s", strerror(saved_errno));
    }

    /* MAP_FIXED is restricted to the range reserved above. Each replacement
     * is a separate mapping of the original allocation's backing pages. */
    for (size_t i = 0; i < count; ++i) {
        void *target = (unsigned char *)reserved + i * block_bytes;
        uint64_t handle = qaeVirtToPhysNUMA(qg_buffer_data(blocks[i]));
        void *alias = mmap(target, block_bytes, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_FIXED, fd, (off_t)handle);
        if (alias == MAP_FAILED) {
            int saved_errno = errno;
            munmap(reserved, bytes);
            close(fd);
            return alias_error(err, errlen, "map DMA alias block %zu: %s", i, strerror(saved_errno));
        }
        if (madvise(alias, block_bytes, MADV_DONTFORK)) {
            int saved_errno = errno;
            munmap(reserved, bytes);
            close(fd);
            return alias_error(err, errlen, "protect DMA alias block %zu from fork: %s", i, strerror(saved_errno));
        }
    }

    close(fd);
    *base = reserved;
    *mapped_bytes = bytes;
    return 0;
}

int qg_alias_destroy(void *base, size_t mapped_bytes,
                      char *err, size_t errlen)
{
    if (!base && !mapped_bytes)
        return 0;
    long page_size = sysconf(_SC_PAGESIZE);
    if (!base || !mapped_bytes || page_size <= 0 ||
        (uintptr_t)base % (size_t)page_size ||
        mapped_bytes % (size_t)page_size)
        return alias_error(err, errlen, "invalid DMA alias range");
    if (munmap(base, mapped_bytes))
        return alias_error(err, errlen, "unmap DMA alias: %s", strerror(errno));
    return 0;
}
