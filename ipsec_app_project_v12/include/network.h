#ifndef NETWORK_H
#define NETWORK_H

#include "app_config.h"

int network_prepare(const app_config_t *cfg, const char *result_dir);
int network_validate_route(const app_config_t *cfg, const char *result_dir);

#endif
