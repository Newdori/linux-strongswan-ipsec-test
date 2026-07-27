#ifndef FIREWALL_H
#define FIREWALL_H

#include "app_config.h"

int firewall_apply(const app_config_t *cfg, const char *result_dir);
int firewall_remove(const app_config_t *cfg, const char *result_dir);

#endif
