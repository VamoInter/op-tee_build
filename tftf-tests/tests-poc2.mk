TESTS_SOURCES   +=                                              \
    $(addprefix tftf/tests/runtime_services/secure_service/, \
        ffa_helpers.c                                   \
        spm_common.c                                     \
        spm_test_helpers.c                               \
        aarch64/ffa_arch_helpers.S                        \
        poc2/poc2.c                                      \
    )
