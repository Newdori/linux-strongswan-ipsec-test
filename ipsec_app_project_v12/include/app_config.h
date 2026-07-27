#ifndef APP_CONFIG_H
#define APP_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    ROLE_INITIATOR = 0,
    ROLE_RESPONDER = 1
} app_role_t;

typedef struct {
    app_role_t role;
    char local_ip[64];
    char remote_ip[64];
    char local_cidr[64];
    char local_id[128];
    char remote_id[128];
    char interface_name[64];
    char psk_file[512];
    char service_name[128];
    char vici_uri[256];
    char connection_name[128];
    char child_name[128];
    char output_root[512];
    char ike_proposals[512];
    char esp_proposals[512];
    char ipsec_mode[32];
    int udp_port;
    int matrix_control_port;
    int packet_count;
    int payload_size;
    int timeout_sec;
    int capture_drain_ms;
    int capture_buffer_kib;
    int measurement_guard_ms;
    bool capture_enabled;
    bool manage_firewall;
    bool configure_address;
    bool cleanup_existing_sa;
    bool terminate_on_exit;
    bool childless_ike;
} app_config_t;

void app_config_defaults(app_config_t *cfg);
int app_config_load(const char *path, app_config_t *cfg, char *error, size_t error_size);
int app_config_validate(const app_config_t *cfg, char *error, size_t error_size);
const char *app_role_name(app_role_t role);

#endif
