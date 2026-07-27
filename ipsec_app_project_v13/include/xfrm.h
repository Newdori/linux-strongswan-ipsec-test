#ifndef XFRM_H
#define XFRM_H

#include "app_config.h"
#include <stdbool.h>

typedef struct {
    long long packets;
    long long bytes;
    long long error_total;
    bool scoped_to_reqid;
    unsigned int reqid;
} xfrm_snapshot_t;

int xfrm_take_snapshot(const app_config_t *cfg, const char *result_dir,
                       const char *phase, xfrm_snapshot_t *snapshot);
int xfrm_take_snapshot_for_reqid(const app_config_t *cfg, const char *result_dir,
                                 const char *phase, unsigned int reqid,
                                 xfrm_snapshot_t *snapshot);
bool xfrm_counters_increased(const xfrm_snapshot_t *before, const xfrm_snapshot_t *after);
int xfrm_wait_for_reqid_absent(const app_config_t *cfg, const char *result_dir,
                               const char *phase, unsigned int reqid, int timeout_sec);

#endif
