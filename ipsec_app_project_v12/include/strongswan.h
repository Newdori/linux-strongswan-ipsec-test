#ifndef STRONGSWAN_H
#define STRONGSWAN_H

#include "app_config.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool ike_present;
    bool ike_established;
    bool child_present;
    bool ready;
    bool reqid_valid;
    unsigned int reqid;
    char child_algorithms[256];
} strongswan_sa_info_t;

int strongswan_ensure_ready(const app_config_t *cfg, const char *result_dir);
int strongswan_load_configuration(const app_config_t *cfg, const char *result_dir);
int strongswan_initiate(const app_config_t *cfg, const char *result_dir);
int strongswan_initiate_ike_only(const app_config_t *cfg, const char *result_dir);
int strongswan_initiate_child(const app_config_t *cfg, const char *result_dir);
int strongswan_wait_for_ike(const app_config_t *cfg, const char *result_dir);
int strongswan_wait_for_sa(const app_config_t *cfg, const char *result_dir);
int strongswan_get_sa_info(const app_config_t *cfg, const char *result_dir,
                           const char *phase, strongswan_sa_info_t *info);
int strongswan_cleanup_target_sa(const app_config_t *cfg, const char *result_dir,
                                 const char *phase, strongswan_sa_info_t *previous_info);
int strongswan_snapshot(const app_config_t *cfg, const char *result_dir, const char *phase);
bool strongswan_sa_has_child_ke(const strongswan_sa_info_t *info, const char *expected_ke);

#endif
