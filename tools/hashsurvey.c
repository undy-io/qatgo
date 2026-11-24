#define _POSIX_C_SOURCE 200809L
/* Standalone survey for the installed legacy driver. No Go API is changed.
 * Enumerate capabilities and verify supported plain/HMAC full/partial hashes
 * against OpenSSL. Never free request memory before its callback. */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "cpa.h"
#include "cpa_cy_im.h"
#include "cpa_cy_sym.h"
#include "icp_sal_user.h"
#include "icp_sal_poll.h"
#include "qae_mem.h"

extern int32_t qaeMemInit(void);
extern void qaeMemDestroy(void);
extern Cpa32S icp_adf_cfgGetDomainAddress(Cpa16U accelId);

typedef struct {
    CpaCySymHashAlgorithm id;
    const char *name;
    const EVP_MD *(*md)(void);
    unsigned digest_bytes, block_bytes;
} algorithm;

static const algorithm algorithms[] = {
    {CPA_CY_SYM_HASH_MD5, "MD5", EVP_md5, 16, 64},
    {CPA_CY_SYM_HASH_SHA1, "SHA-1", EVP_sha1, 20, 64},
    {CPA_CY_SYM_HASH_SHA224, "SHA-224", EVP_sha224, 28, 64},
    {CPA_CY_SYM_HASH_SHA256, "SHA-256", EVP_sha256, 32, 64},
    {CPA_CY_SYM_HASH_SHA384, "SHA-384", EVP_sha384, 48, 128},
    {CPA_CY_SYM_HASH_SHA512, "SHA-512", EVP_sha512, 64, 128},
    {CPA_CY_SYM_HASH_SHA3_224, "SHA3-224", EVP_sha3_224, 28, 144},
    {CPA_CY_SYM_HASH_SHA3_256, "SHA3-256", EVP_sha3_256, 32, 136},
    {CPA_CY_SYM_HASH_SHA3_384, "SHA3-384", EVP_sha3_384, 48, 104},
    {CPA_CY_SYM_HASH_SHA3_512, "SHA3-512", EVP_sha3_512, 64, 72},
    {CPA_CY_SYM_HASH_SM3, "SM3", EVP_sm3, 32, 64},
};

static const char *hash_names[] = {
    "NONE", "MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512",
    "AES-XCBC", "AES-CCM", "AES-GCM", "KASUMI-F9", "SNOW3G-UIA2",
    "AES-CMAC", "AES-GMAC", "AES-CBC-MAC", "ZUC-EIA3", "SHA3-256",
    "SHA3-224", "SHA3-384", "SHA3-512", "SHAKE128", "SHAKE256",
    "Poly1305", "SM3"
};

typedef struct { bool done; CpaStatus status; } completion_state;

static void completed(void *tag, CpaStatus status, CpaCySymOp operation,
                      void *op, CpaBufferList *dst, CpaBoolean verified)
{
    (void)operation; (void)op; (void)dst; (void)verified;
    completion_state *state = tag;
    state->status = status;
    state->done = true;
}

static void pause_poll(void)
{
    struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000};
    nanosleep(&delay, NULL);
}

static CpaStatus perform(CpaInstanceHandle instance, CpaCySymSessionCtx session,
                         Cpa8U *data, unsigned length, Cpa8U *digest,
                         CpaCySymPacketType packet)
{
    completion_state state = {false, CPA_STATUS_FAIL};
    Cpa32U meta_bytes = 0;
    CpaStatus status = cpaCyBufferListGetMetaSize(instance, 1, &meta_bytes);
    if (status) return status;
    CpaFlatBuffer flat = {.pData = data, .dataLenInBytes = length};
    CpaBufferList list = {.numBuffers = 1, .pBuffers = &flat};
    list.pPrivateMetaData = qaeMemAllocNUMA(meta_bytes, 0, 64);
    if (!list.pPrivateMetaData) return CPA_STATUS_RESOURCE;
    CpaCySymOpData op = {0};
    op.sessionCtx = session;
    op.packetType = packet;
    op.messageLenToHashInBytes = length;
    op.pDigestResult = digest;
    do {
        status = cpaCySymPerformOp(instance, &state, &op, &list, &list, NULL);
        if (status == CPA_STATUS_RETRY) {
            (void)icp_sal_CyPollInstance(instance, 0);
            pause_poll();
        }
    } while (status == CPA_STATUS_RETRY);
    if (status == CPA_STATUS_SUCCESS) {
        /* Keep polling until actual callback delivery. In a stalled-device
         * case this deliberately retains all stack/native/DMA state. */
        while (!state.done) {
            (void)icp_sal_CyPollInstance(instance, 0);
            if (!state.done) pause_poll();
        }
        status = state.status;
    }
    qaeMemFreeNUMA(&list.pPrivateMetaData);
    return status;
}

static int test_hash(CpaInstanceHandle instance, const char *pf,
                      const algorithm *a, bool auth, bool partial)
{
    CpaCySymSessionSetupData setup = {0};
    CpaCySymSessionCtx session = NULL;
    Cpa8U key[16];
    memset(key, 0x5a, sizeof(key));
    setup.sessionPriority = CPA_CY_PRIORITY_NORMAL;
    setup.symOperation = CPA_CY_SYM_OP_HASH;
    setup.hashSetupData.hashAlgorithm = a->id;
    setup.hashSetupData.hashMode = auth ? CPA_CY_SYM_HASH_MODE_AUTH : CPA_CY_SYM_HASH_MODE_PLAIN;
    setup.hashSetupData.digestResultLenInBytes = a->digest_bytes;
    setup.partialsNotRequired = partial ? CPA_FALSE : CPA_TRUE;
    if (auth) {
        setup.hashSetupData.authModeSetupData.authKey = key;
        setup.hashSetupData.authModeSetupData.authKeyLenInBytes = sizeof(key);
    }
    Cpa32U session_bytes = 0;
    CpaStatus status = cpaCySymSessionCtxGetSize(instance, &setup, &session_bytes);
    bool initialized = false, matched = false;
    const char *stage = "session_size";
    Cpa8U *data = NULL, *digest = NULL;
    if (status) goto result;
    session = qaeMemAllocNUMA(session_bytes, 0, 64);
    if (!session) { status = CPA_STATUS_RESOURCE; goto result; }
    memset(session, 0, session_bytes);
    stage = "dma_alloc";
    data = qaeMemAllocNUMA(1024, 0, 64);
    digest = qaeMemAllocNUMA(64, 0, 64);
    if (!data || !digest) { status = CPA_STATUS_RESOURCE; goto result; }
    stage = "session_init";
    status = cpaCySymInitSession(instance, completed, &setup, session);
    if (status) goto result;
    initialized = true;
    for (unsigned i = 0; i < 529; ++i) data[i] = (Cpa8U)(i * 131U + i / 7U);
    memset(digest, 0, 64);
    stage = partial ? "partial_request" : "full_request";
    if (partial) {
        unsigned first = 2 * a->block_bytes;
        status = perform(instance, session, data, first, digest, CPA_CY_SYM_PACKET_TYPE_PARTIAL);
        if (status) goto result;
        stage = "last_partial_request";
        status = perform(instance, session, data + first, 529 - first, digest, CPA_CY_SYM_PACKET_TYPE_LAST_PARTIAL);
    } else {
        status = perform(instance, session, data, 529, digest, CPA_CY_SYM_PACKET_TYPE_FULL);
    }
    if (status) goto result;
    unsigned char reference[EVP_MAX_MD_SIZE];
    unsigned reference_len = 0;
    if (auth) {
        if (!HMAC(a->md(), key, sizeof(key), data, 529, reference, &reference_len)) {
            status = CPA_STATUS_FAIL; stage = "openssl_reference"; goto result;
        }
    } else if (!EVP_Digest(data, 529, reference, &reference_len, a->md(), NULL)) {
        status = CPA_STATUS_FAIL; stage = "openssl_reference"; goto result;
    }
    matched = reference_len == a->digest_bytes && !memcmp(digest, reference, reference_len);
    stage = matched ? "verified" : "digest_mismatch";
    if (!matched) status = CPA_STATUS_FAIL;
result:
    if (initialized) {
        CpaBoolean in_use;
        do {
            CpaStatus use_status = cpaCySymSessionInUse(session, &in_use);
            if (use_status) { fprintf(stderr, "session state error; retaining DMA\n"); exit(2); }
            if (in_use) { (void)icp_sal_CyPollInstance(instance, 0); pause_poll(); }
        } while (in_use);
        CpaStatus removed = cpaCySymRemoveSession(instance, session);
        if (removed) { fprintf(stderr, "session removal failed; retaining DMA\n"); exit(2); }
    }
    if (data) qaeMemFreeNUMA((void **)&data);
    if (digest) qaeMemFreeNUMA((void **)&digest);
    if (session) qaeMemFreeNUMA(&session);
    printf("{\"kind\":\"test\",\"pf\":\"%s\",\"algorithm\":\"%s\",\"mode\":\"%s\",\"partial\":%s,\"status\":%d,\"stage\":\"%s\",\"verified\":%s}\n",
           pf, a->name, auth ? "HMAC" : "plain", partial ? "true" : "false",
           status, stage, matched ? "true" : "false");
    /* This C62x survey intentionally attempts unsupported SHA3 partials.
     * All other failures, including digest mismatches, fail the command. */
    bool expected_rejection = partial && a->id == CPA_CY_SYM_HASH_SHA3_256 &&
        status == CPA_STATUS_INVALID_PARAM && !strcmp(stage, "partial_request");
    return matched || expected_rejection ? 0 : 1;
}

int main(void)
{
    if (qaeMemInit()) return 2;
    if (icp_sal_userStartMultiProcess("SSL", CPA_FALSE)) return 2;
    Cpa16U count = 0;
    if (cpaCyGetNumInstances(&count)) return 2;
    CpaInstanceHandle *instances = calloc(count, sizeof(*instances));
    if (!instances || cpaCyGetInstances(count, instances)) return 2;
    char seen[96][64];
    unsigned seen_count = 0;
    unsigned failures = 0;
    printf("{\"kind\":\"inventory\",\"instance_count\":%u}\n", count);
    for (unsigned i = 0; i < count; ++i) {
        CpaInstanceInfo2 info;
        if (cpaCyInstanceGetInfo2(instances[i], &info)) return 2;
        int domain = icp_adf_cfgGetDomainAddress(info.physInstId.packageId);
        if (domain < 0) return 2;
        unsigned bdf = info.physInstId.busAddress;
        char pci[32], path[128], parent[256], pf[64];
        snprintf(pci, sizeof(pci), "%04x:%02x:%02x.%x", domain, bdf >> 8, (bdf >> 3) & 31, bdf & 7);
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/physfn", pci);
        ssize_t n = readlink(path, parent, sizeof(parent) - 1);
        if (n < 0) snprintf(pf, sizeof(pf), "%s", pci);
        else {
            parent[n] = 0;
            const char *last = strrchr(parent, '/');
            const char *name = last ? last + 1 : parent;
            if (strlen(name) >= sizeof(pf)) return 2;
            memcpy(pf, name, strlen(name) + 1);
        }
        if (cpaCySetAddressTranslation(instances[i], qaeVirtToPhysNUMA) || cpaCyStartInstance(instances[i])) return 2;
        CpaCySymCapabilitiesInfo caps = {0};
        if (cpaCySymQueryCapabilities(instances[i], &caps)) return 2;
        printf("{\"kind\":\"instance\",\"index\":%u,\"pci\":\"%s\",\"pf\":\"%s\",\"hash_mask\":%u,\"partial_flag\":%s}\n", i, pci, pf, caps.hashes[0], caps.partialPacketSupported ? "true" : "false");
        bool first = true;
        for (unsigned j = 0; j < seen_count; ++j) if (!strcmp(seen[j], pf)) first = false;
        if (first) {
            if (seen_count == 96) return 2;
            snprintf(seen[seen_count++], sizeof(seen[0]), "%s", pf);
            for (unsigned h = 1; h < sizeof(hash_names) / sizeof(hash_names[0]); ++h)
                printf("{\"kind\":\"capability\",\"pf\":\"%s\",\"algorithm\":\"%s\",\"advertised\":%s}\n", pf, hash_names[h], CPA_BITMAP_BIT_TEST(caps.hashes, h) ? "true" : "false");
            for (unsigned a = 0; a < sizeof(algorithms) / sizeof(algorithms[0]); ++a) {
                if (!CPA_BITMAP_BIT_TEST(caps.hashes, algorithms[a].id)) continue;
                for (unsigned auth = 0; auth < 2; ++auth)
                    for (unsigned partial = 0; partial < 2; ++partial)
                        failures += test_hash(instances[i], pf, &algorithms[a], auth, partial);
            }
        }
        if (cpaCyStopInstance(instances[i])) return 2;
    }
    free(instances);
    if (icp_sal_userStop()) return 2;
    qaeMemDestroy();
    printf("{\"kind\":\"summary\",\"unexpected_failures\":%u}\n", failures);
    return failures ? 1 : 0;
}
