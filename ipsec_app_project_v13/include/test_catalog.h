#ifndef TEST_CATALOG_H
#define TEST_CATALOG_H

#include "test_matrix.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char keyword[32];
    char observed_name[64];
} catalog_ke_t;

size_t exhaustive_ike_count(void);
size_t exhaustive_esp_count(void);
size_t exhaustive_pair_count(void);

int exhaustive_ike_at(size_t index, char *proposal, size_t proposal_size);
int exhaustive_esp_at(size_t index, char *proposal, size_t proposal_size,
                      bool *separate_child_exchange,
                      char *expected_child_ke, size_t expected_child_ke_size);

bool test_catalog_detect_esp_ke(const char *proposal,
                                char *observed_name, size_t observed_name_size);

#endif
