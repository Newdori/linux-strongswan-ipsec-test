#ifndef TEST_MATRIX_H
#define TEST_MATRIX_H

#include "app_config.h"
#include <stdbool.h>
#include <stddef.h>

#define TEST_MATRIX_MAX_CASES 128

typedef struct {
    char id[64];
    char name[128];
    bool enabled;
    char ike_proposals[512];
    char esp_proposals[512];
    char ike_initiator[512];
    char ike_responder[512];
    char esp_initiator[512];
    char esp_responder[512];
    char ipsec_mode[32];
    char category[64];
    char expected[32];
    bool separate_child_exchange;
    char expected_child_ke[64];
} crypto_test_case_t;

typedef struct {
    crypto_test_case_t cases[TEST_MATRIX_MAX_CASES];
    size_t count;
} crypto_test_matrix_t;

int test_matrix_load(const char *path, crypto_test_matrix_t *matrix,
                     char *error, size_t error_size);
int test_matrix_apply_case(const crypto_test_case_t *test_case,
                           const app_config_t *base,
                           app_config_t *out,
                           char *error, size_t error_size);

#endif
