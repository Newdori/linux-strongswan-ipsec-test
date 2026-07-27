#include "firewall.h"
#include "logger.h"
#include "process.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int rule(const app_config_t *cfg, const char *action, const char *protocol,
                const char *dport, const char *log_path)
{
    char *argv[20]; int n = 0;
    argv[n++] = "iptables"; argv[n++] = (char *)action; argv[n++] = "INPUT";
    if (!strcmp(action, "-I")) argv[n++] = "1";
    argv[n++] = "-i"; argv[n++] = (char *)cfg->interface_name;
    argv[n++] = "-s"; argv[n++] = (char *)cfg->remote_ip;
    argv[n++] = "-p"; argv[n++] = (char *)protocol;
    if (dport) { argv[n++] = "--dport"; argv[n++] = (char *)dport; }
    argv[n++] = "-j"; argv[n++] = "ACCEPT"; argv[n] = NULL;
    return process_run_to_file(argv, log_path);
}

static int apply_or_remove(const app_config_t *cfg, const char *result_dir, int apply)
{
    if (!cfg->manage_firewall) return 0;
    if (!command_exists("iptables")) { log_error("manage_firewall=true but iptables was not found"); return -1; }
    char base[1024]; join_path(base, sizeof(base), result_dir, apply ? "firewall_apply.log" : "firewall_remove.log");
    const char *action = apply ? "-I" : "-D";
    char p500[16] = "500", p4500[16] = "4500", app_port[16], matrix_port[16];
    snprintf(app_port, sizeof(app_port), "%d", cfg->udp_port);
    snprintf(matrix_port, sizeof(matrix_port), "%d", cfg->matrix_control_port);
    int rc = 0;
    rc |= rule(cfg, action, "udp", p500, base);
    rc |= rule(cfg, action, "udp", p4500, base);
    rc |= rule(cfg, action, "esp", NULL, base);
    rc |= rule(cfg, action, "udp", app_port, base);
    rc |= rule(cfg, action, "udp", matrix_port, base);
    if (rc == 0) log_pass("firewall rules %s by application", apply ? "applied" : "removed");
    else if (apply) log_error("failed to apply one or more firewall rules");
    return rc == 0 ? 0 : -1;
}

int firewall_apply(const app_config_t *cfg, const char *result_dir) { return apply_or_remove(cfg, result_dir, 1); }
int firewall_remove(const app_config_t *cfg, const char *result_dir) { return apply_or_remove(cfg, result_dir, 0); }
