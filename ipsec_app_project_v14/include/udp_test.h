#ifndef UDP_TEST_H
#define UDP_TEST_H

#include "app_config.h"

typedef struct {
    int sent;
    int received;
    int acknowledgements;
    long long bytes_sent;
    long long bytes_received;
} udp_result_t;

int udp_run_initiator(const app_config_t *cfg, const char *result_dir, udp_result_t *result);
int udp_run_responder(const app_config_t *cfg, const char *result_dir, udp_result_t *result);
int udp_lifecycle_barrier(const app_config_t *cfg, const char *result_dir);
int udp_matrix_ready_barrier(const app_config_t *cfg, const char *result_dir, const char *case_id);
int udp_matrix_phase_barrier(const app_config_t *cfg, const char *result_dir,
                             const char *case_id, const char *phase);

#endif
