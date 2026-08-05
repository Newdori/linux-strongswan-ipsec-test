#ifndef CAPTURE_H
#define CAPTURE_H

#include "app_config.h"
#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    char pcap_path[1024];
    char stderr_path[1024];
    int stderr_fd;
    int stderr_log_fd;
    bool active;
    bool ready;
    bool measurement_window_valid;
    long long measurement_start_us;
    long long measurement_end_us;
} capture_session_t;

typedef struct {
    bool enabled;
    bool ready;
    bool analysis_ok;
    bool outbound_esp_seen;
    bool plaintext_udp_seen;
    int outbound_esp_packets;
    int plaintext_udp_packets;
    bool stats_known;
    bool lossless;
    int packets_captured;
    int packets_received_by_filter;
    int packets_dropped_by_kernel;
    bool measurement_window_known;
    int measurement_total_esp_packets;
    bool xfrm_capture_count_comparable;
    bool xfrm_capture_count_match;
} capture_result_t;

int capture_start(const app_config_t *cfg, const char *result_dir, capture_session_t *session);
int capture_stop(capture_session_t *session);
void capture_mark_measurement_start(capture_session_t *session);
void capture_mark_measurement_end(capture_session_t *session);
int capture_analyze(const app_config_t *cfg, const char *result_dir,
                    const capture_session_t *session, capture_result_t *result);

#endif
