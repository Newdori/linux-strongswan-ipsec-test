#include "network.h"
#include "logger.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int run_and_save(char *const argv[], const char *result_dir, const char *file)
{
    char path[1024]; join_path(path, sizeof(path), result_dir, file);
    return process_run_to_file(argv, path);
}

int network_prepare(const app_config_t *cfg, const char *result_dir)
{
    char *out = NULL;
    char *show_link[] = {"ip", "link", "show", "dev", (char *)cfg->interface_name, NULL};
    int rc = process_run(show_link, &out);
    if (rc != 0) { log_error("interface %s not found: %s", cfg->interface_name, out ? out : ""); free(out); return -1; }
    free(out);

    char *link_up[] = {"ip", "link", "set", "dev", (char *)cfg->interface_name, "up", NULL};
    if (process_run(link_up, &out) != 0) { log_error("failed to set %s UP: %s", cfg->interface_name, out ? out : ""); free(out); return -1; }
    free(out);

    if (cfg->configure_address) {
        char *addr_replace[] = {"ip", "addr", "replace", (char *)cfg->local_cidr, "dev", (char *)cfg->interface_name, NULL};
        if (process_run(addr_replace, &out) != 0) { log_error("failed to configure %s on %s: %s", cfg->local_cidr, cfg->interface_name, out ? out : ""); free(out); return -1; }
        free(out);
        log_pass("configured address %s on %s", cfg->local_cidr, cfg->interface_name);
    }

    char *addr_show[] = {"ip", "-br", "addr", "show", "dev", (char *)cfg->interface_name, NULL};
    run_and_save(addr_show, result_dir, "network_address.txt");
    return network_validate_route(cfg, result_dir);
}

int network_validate_route(const app_config_t *cfg, const char *result_dir)
{
    char *argv[] = {"ip", "route", "get", (char *)cfg->remote_ip, "from", (char *)cfg->local_ip, NULL};
    char *out = NULL;
    int rc = process_run(argv, &out);
    char path[1024]; join_path(path, sizeof(path), result_dir, "network_route.txt");
    write_text_file(path, out ? out : "", 0640);
    if (rc != 0 || !out || !strstr(out, cfg->interface_name)) {
        log_error("route to %s does not use %s: %s", cfg->remote_ip, cfg->interface_name, out ? out : "");
        free(out); return -1;
    }
    if (!strstr(out, cfg->local_ip)) log_warn("route output does not explicitly show source %s: %s", cfg->local_ip, out);
    else log_pass("route to %s uses %s with source %s", cfg->remote_ip, cfg->interface_name, cfg->local_ip);
    free(out);
    return 0;
}
