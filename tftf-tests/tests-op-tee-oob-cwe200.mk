TESTS_SOURCES   +=                                              \
    $(addprefix tftf/tests/runtime_services/secure_service/, \
        ffa_helpers.c                                   \
        spm_common.c                                     \
        spm_test_helpers.c                               \
        aarch64/ffa_arch_helpers.S                        \
        ffa_frag_mismatch/test_op_tee_oob_cwe200.c        \
    )
