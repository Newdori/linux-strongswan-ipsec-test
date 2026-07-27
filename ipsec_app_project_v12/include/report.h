#ifndef REPORT_H
#define REPORT_H

#include "app_config.h"
#include "capture.h"
#include "udp_test.h"
#include "xfrm.h"
#include <stdbool.h>

typedef struct {
    bool data_path_evaluated;
    bool ike_child_ok;
    bool child_ke_evaluated;
    bool child_ke_ok;
    bool udp_ok;
    bool xfrm_counter_ok;
    bool xfrm_error_ok;
    bool data_path_pass;
    bool capture_pass;
    bool lifecycle_pass;
    bool overall_pass;
} test_verdict_t;

int report_write(const app_config_t *cfg, const char *result_dir,
                 const udp_result_t *udp,
                 const xfrm_snapshot_t *before,
                 const xfrm_snapshot_t *after,
                 const capture_result_t *capture,
                 const test_verdict_t *verdict);

#endif
