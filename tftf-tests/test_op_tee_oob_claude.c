/*
 * Baseline: FFA_MEM_SHARE usando structs EXATAS do OP-TEE
 * Fonte: optee_os/core/arch/arm/include/ffa.h
 * NÃO usa helper do TFTF (gera layout incompatível com OP-TEE)
 */

#include <spm_common.h>
#include <spm_test_helpers.h>
#include <test_helpers.h>
#include <tftf_lib.h>
#include <ffa_svc.h>
#include <xlat_tables_defs.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define OPTEE_ID    0x8001U
#define SENDER      HYP_ID

/* --- Structs copiadas de optee_os/core/arch/arm/include/ffa.h --- */

struct optee_ffa_address_range {
    uint64_t address;
    uint32_t page_count;
    uint32_t reserved;
};  /* 16 bytes */

struct optee_ffa_mem_region {
    uint32_t total_page_count;
    uint32_t address_range_count;
    uint64_t reserved;
    /* struct optee_ffa_address_range ranges[]; */
};  /* 16 bytes header */

struct optee_ffa_mem_access_perm {
    uint16_t endpoint_id;
    uint8_t  perm;
    uint8_t  flags;
};  /* 4 bytes */

struct optee_ffa_mem_access {
    struct optee_ffa_mem_access_perm access_perm;
    uint32_t region_offs;
    uint64_t reserved;
};  /* 16 bytes */

struct optee_ffa_mem_transaction_1_1 {
    uint16_t sender_id;
    uint16_t mem_reg_attr;
    uint32_t flags;
    uint64_t global_handle;
    uint64_t tag;
    uint32_t mem_access_size;
    uint32_t mem_access_count;
    uint32_t mem_access_offs;
    uint8_t  reserved[12];
};  /* 48 bytes */

/* Constantes do OP-TEE (ffa.h) */
#define OPTEE_FFA_NORMAL_MEM_REG_ATTR   0x2fU   /* Normal, WB, Inner Shareable */
#define OPTEE_FFA_MEM_PERM_RW           0x1U    /* bits[1:0] = 01 */
#define OPTEE_FFA_MEM_TYPE_SHARE        (1U << 3)

/*
 * Layout no TX buffer (96 bytes total):
 *   [0..47]  optee_ffa_mem_transaction_1_1  (48 bytes)
 *   [48..63] optee_ffa_mem_access           (16 bytes)
 *   [64..79] optee_ffa_mem_region header    (16 bytes)
 *   [80..95] optee_ffa_address_range        (16 bytes)
 */
#define HDROFF  0U
#define ACCOFF  48U
#define REGOFF  64U
#define RNGOFF  80U
#define TOTAL   96U

test_result_t test_op_tee_region_offs_oob(void)
{
    struct mailbox_buffers mb;
    struct ffa_value ret;

    printf("[baseline] Iniciando FFA_MEM_SHARE com structs do OP-TEE...\n");

    GET_TFTF_MAILBOX(mb);
    memset(mb.send, 0, TOTAL);

    /* 1. Header: ffa_mem_transaction_1_1 em [0..47] */
    struct optee_ffa_mem_transaction_1_1 *hdr =
        (struct optee_ffa_mem_transaction_1_1 *)((uint8_t *)mb.send + HDROFF);
    hdr->sender_id        = (uint16_t)SENDER;
    hdr->mem_reg_attr     = (uint16_t)OPTEE_FFA_NORMAL_MEM_REG_ATTR;
    hdr->flags            = OPTEE_FFA_MEM_TYPE_SHARE;
    hdr->global_handle    = 0ULL;
    hdr->tag              = 0ULL;
    hdr->mem_access_size  = (uint32_t)sizeof(struct optee_ffa_mem_access); /* 16 */
    hdr->mem_access_count = 1U;
    hdr->mem_access_offs  = ACCOFF;  /* 48: offset do mem_access no buffer */

    /* 2. mem_access em [48..63] */
    struct optee_ffa_mem_access *acc =
        (struct optee_ffa_mem_access *)((uint8_t *)mb.send + ACCOFF);
    acc->access_perm.endpoint_id = (uint16_t)OPTEE_ID;
    acc->access_perm.perm        = (uint8_t)OPTEE_FFA_MEM_PERM_RW;
    acc->access_perm.flags       = 0U;
    acc->region_offs             = REGOFF;  /* 64: offset do mem_region no buffer */
    acc->reserved                = 0ULL;

    /* 3. mem_region header em [64..79] */
    struct optee_ffa_mem_region *reg =
        (struct optee_ffa_mem_region *)((uint8_t *)mb.send + REGOFF);
    reg->total_page_count    = 1U;
    reg->address_range_count = 1U;
    reg->reserved            = 0ULL;

    /* 4. address_range em [80..95] */
    struct optee_ffa_address_range *rng =
        (struct optee_ffa_address_range *)((uint8_t *)mb.send + RNGOFF);
    rng->address    = 0x88000000ULL;
    rng->page_count = 1U;
    rng->reserved   = 0U;

    printf("[baseline] Descriptor montado: total=%u bytes\n", TOTAL);

    /* 5. FFA_MEM_SHARE */
    ret = ffa_mem_share(TOTAL, TOTAL);

    if (ret.fid == FFA_ERROR) {
        printf("[baseline] FALHOU: FFA_MEM_SHARE erro=%ld\n", (long)ret.arg2);
        return TEST_RESULT_FAIL;
    }

    ffa_memory_handle_t handle = ffa_mem_success_handle(ret);
    printf("[baseline] PASSOU: handle=0x%llx\n", (unsigned long long)handle);
    printf("[baseline] Ambiente validado — pronto para OOB\n");

    /* 6. Reclaim limpo */
    smc_args reclaim_args = {
        .fid  = FFA_MEM_RECLAIM,
        .arg1 = (uint64_t)(handle & 0xFFFFFFFFULL),
        .arg2 = (uint64_t)(handle >> 32),
        .arg3 = 0ULL,
    };
    tftf_smc(&reclaim_args);

    return TEST_RESULT_SUCCESS;
}
