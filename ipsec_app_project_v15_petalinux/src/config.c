#define _POSIX_C_SOURCE 200809L
#include "app_config.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static char *trim(char *text)
{
    while (*text && isspace((unsigned char)*text)) ++text;
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return text;
}

static int parse_bool(const char *value, bool *result)
{
    if (!strcasecmp(value, "true") || !strcmp(value, "1") || !strcasecmp(value, "yes")) {
        *result = true;
        return 0;
    }
    if (!strcasecmp(value, "false") || !strcmp(value, "0") || !strcasecmp(value, "no")) {
        *result = false;
        return 0;
    }
    return -1;
}

static int copy_value(char *dest, size_t size, const char *value)
{
    if (strlen(value) >= size) return -1;
    strcpy(dest, value);
    return 0;
}

void app_config_defaults(app_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->role = ROLE_INITIATOR;
    strcpy(cfg->service_name, "ipsec");
    strcpy(cfg->connection_name, "app-test");
    strcpy(cfg->child_name, "app-test-child");
    strcpy(cfg->output_root, "./results");
    strcpy(cfg->ike_proposals, "aes256-sha256-prfsha256-modp2048");
    strcpy(cfg->esp_proposals, "aes256-sha256");
    strcpy(cfg->ipsec_mode, "transport");
    cfg->udp_port = 9000;
    cfg->matrix_control_port = 9001;
    cfg->packet_count = 20;
    cfg->payload_size = 256;
    cfg->timeout_sec = 60;
    cfg->capture_drain_ms = 1000;
    cfg->capture_buffer_kib = 16384;
    cfg->measurement_guard_ms = 250;
    cfg->capture_enabled = true;
    cfg->manage_firewall = false;
    cfg->configure_address = false;
    cfg->cleanup_existing_sa = false;
    cfg->terminate_on_exit = false;
    cfg->childless_ike = false;
}

const char *app_role_name(app_role_t role)
{
    return role == ROLE_INITIATOR ? "initiator" : "responder";
}

int app_config_load(const char *path, app_config_t *cfg, char *error, size_t error_size)
{
    app_config_defaults(cfg);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(error, error_size, "cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    char line[2048];
    int line_number = 0;
    while (fgets(line, sizeof(line), fp)) {
        ++line_number;
        char *text = trim(line);
        if (!*text || *text == '#') continue;
        char *equal = strchr(text, '=');
        if (!equal) {
            snprintf(error, error_size, "%s:%d missing '='", path, line_number);
            fclose(fp);
            return -1;
        }
        *equal = '\0';
        char *key = trim(text);
        char *value = trim(equal + 1);
        int rc = 0;

        if (!strcmp(key, "role")) {
            if (!strcmp(value, "initiator")) cfg->role = ROLE_INITIATOR;
            else if (!strcmp(value, "responder")) cfg->role = ROLE_RESPONDER;
            else rc = -1;
        } else if (!strcmp(key, "local_ip")) rc = copy_value(cfg->local_ip, sizeof(cfg->local_ip), value);
        else if (!strcmp(key, "remote_ip")) rc = copy_value(cfg->remote_ip, sizeof(cfg->remote_ip), value);
        else if (!strcmp(key, "local_cidr")) rc = copy_value(cfg->local_cidr, sizeof(cfg->local_cidr), value);
        else if (!strcmp(key, "local_id")) rc = copy_value(cfg->local_id, sizeof(cfg->local_id), value);
        else if (!strcmp(key, "remote_id")) rc = copy_value(cfg->remote_id, sizeof(cfg->remote_id), value);
        else if (!strcmp(key, "interface")) rc = copy_value(cfg->interface_name, sizeof(cfg->interface_name), value);
        else if (!strcmp(key, "psk_file")) rc = copy_value(cfg->psk_file, sizeof(cfg->psk_file), value);
        else if (!strcmp(key, "service_name")) rc = copy_value(cfg->service_name, sizeof(cfg->service_name), value);
        else if (!strcmp(key, "vici_uri")) rc = copy_value(cfg->vici_uri, sizeof(cfg->vici_uri), value);
        else if (!strcmp(key, "connection_name")) rc = copy_value(cfg->connection_name, sizeof(cfg->connection_name), value);
        else if (!strcmp(key, "child_name")) rc = copy_value(cfg->child_name, sizeof(cfg->child_name), value);
        else if (!strcmp(key, "output_root")) rc = copy_value(cfg->output_root, sizeof(cfg->output_root), value);
        else if (!strcmp(key, "ike_proposals")) rc = copy_value(cfg->ike_proposals, sizeof(cfg->ike_proposals), value);
        else if (!strcmp(key, "esp_proposals")) rc = copy_value(cfg->esp_proposals, sizeof(cfg->esp_proposals), value);
        else if (!strcmp(key, "ipsec_mode")) rc = copy_value(cfg->ipsec_mode, sizeof(cfg->ipsec_mode), value);
        else if (!strcmp(key, "udp_port")) cfg->udp_port = atoi(value);
        else if (!strcmp(key, "matrix_control_port")) cfg->matrix_control_port = atoi(value);
        else if (!strcmp(key, "packet_count")) cfg->packet_count = atoi(value);
        else if (!strcmp(key, "payload_size")) cfg->payload_size = atoi(value);
        else if (!strcmp(key, "timeout_sec")) cfg->timeout_sec = atoi(value);
        else if (!strcmp(key, "capture_drain_ms")) cfg->capture_drain_ms = atoi(value);
        else if (!strcmp(key, "capture_buffer_kib")) cfg->capture_buffer_kib = atoi(value);
        else if (!strcmp(key, "measurement_guard_ms")) cfg->measurement_guard_ms = atoi(value);
        else if (!strcmp(key, "capture_enabled")) rc = parse_bool(value, &cfg->capture_enabled);
        else if (!strcmp(key, "manage_firewall")) rc = parse_bool(value, &cfg->manage_firewall);
        else if (!strcmp(key, "configure_address")) rc = parse_bool(value, &cfg->configure_address);
        else if (!strcmp(key, "cleanup_existing_sa")) rc = parse_bool(value, &cfg->cleanup_existing_sa);
        else if (!strcmp(key, "terminate_on_exit")) rc = parse_bool(value, &cfg->terminate_on_exit);
        else if (!strcmp(key, "childless_ike")) rc = parse_bool(value, &cfg->childless_ike);
        else {
            snprintf(error, error_size, "%s:%d unknown key '%s'", path, line_number, key);
            fclose(fp);
            return -1;
        }

        if (rc != 0) {
            snprintf(error, error_size, "%s:%d invalid value for '%s'", path, line_number, key);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return app_config_validate(cfg, error, error_size);
}

static int valid_ipv4(const char *value)
{
    struct in_addr addr;
    return value[0] && inet_pton(AF_INET, value, &addr) == 1;
}

static int safe_text(const char *value)
{
    if (!value[0]) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (*p < 0x21 || strchr("{}#\"'\\", *p)) return 0;
    }
    return 1;
}

static int safe_proposal(const char *value)
{
    if (!value[0]) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        if (!(isalnum(*p) || *p == '-' || *p == '_' || *p == ',')) return 0;
    }
    return 1;
}

int app_config_validate(const app_config_t *cfg, char *error, size_t error_size)
{
    if (!valid_ipv4(cfg->local_ip) || !valid_ipv4(cfg->remote_ip)) {
        snprintf(error, error_size, "local_ip and remote_ip must be valid IPv4 addresses");
        return -1;
    }
    if (!safe_text(cfg->local_id) || !safe_text(cfg->remote_id) ||
        !safe_text(cfg->interface_name) || !safe_text(cfg->connection_name) || !safe_text(cfg->child_name)) {
        snprintf(error, error_size, "ID, interface, connection or child contains unsafe characters");
        return -1;
    }
    if (!safe_proposal(cfg->ike_proposals) || !safe_proposal(cfg->esp_proposals)) {
        snprintf(error, error_size, "IKE/ESP proposal contains unsupported characters");
        return -1;
    }
    if (strcmp(cfg->ipsec_mode, "transport") != 0 && strcmp(cfg->ipsec_mode, "tunnel") != 0) {
        snprintf(error, error_size, "ipsec_mode must be transport or tunnel");
        return -1;
    }
    if (!cfg->psk_file[0]) {
        snprintf(error, error_size, "psk_file is required");
        return -1;
    }
    if (cfg->configure_address && !cfg->local_cidr[0]) {
        snprintf(error, error_size, "local_cidr is required when configure_address=true");
        return -1;
    }
    if (cfg->udp_port < 1024 || cfg->udp_port > 65535 ||
        cfg->matrix_control_port < 1024 || cfg->matrix_control_port > 65535 ||
        cfg->matrix_control_port == cfg->udp_port || cfg->packet_count < 1 ||
        cfg->payload_size < 64 || cfg->payload_size > 65507 ||
        cfg->timeout_sec < 1 || cfg->timeout_sec > 3600 ||
        cfg->capture_drain_ms < 0 || cfg->capture_drain_ms > 10000 ||
        cfg->capture_buffer_kib < 64 || cfg->capture_buffer_kib > 65536 ||
        cfg->measurement_guard_ms < 0 || cfg->measurement_guard_ms > 5000) {
        snprintf(error, error_size, "numeric setting out of allowed range");
        return -1;
    }
    return 0;
}
