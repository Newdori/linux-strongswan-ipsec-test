#define _POSIX_C_SOURCE 200809L
#include "app_config.h"
#include "capture.h"
#include "firewall.h"
#include "logger.h"
#include "network.h"
#include "process.h"
#include "report.h"
#include "strongswan.h"
#include "test_matrix.h"
#include "udp_test.h"
#include "xfrm.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t g_interrupted = 0;
static capture_session_t g_capture;

typedef struct {
    test_verdict_t verdict;
    bool expected_match;
    bool sa_observed;
    bool separate_child_exchange;
    bool child_ke_verified;
    strongswan_sa_info_t observed_sa;
    udp_result_t udp;
    xfrm_snapshot_t before;
    xfrm_snapshot_t after;
    capture_result_t capture;
} case_result_t;

static void signal_handler(int signal_number)
{
    (void)signal_number;
    g_interrupted = 1;
    if (g_capture.active && g_capture.pid > 0) kill(g_capture.pid, SIGINT);
}

static void usage(const char *program)
{
    fprintf(stderr,
        "Usage:\n"
        "  sudo %s --config FILE\n"
        "  sudo %s --config FILE --matrix MATRIX.conf [--case CASE_ID]\n"
        "  sudo %s --check --config FILE\n"
        "  sudo %s --cleanup --config FILE\n"
        "  %s --generate-psk FILE\n",
        program, program, program, program, program);
}

static int generate_psk(const char *path)
{
    unsigned char raw[48];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t done = 0;
    while (done < sizeof(raw)) {
        ssize_t n = read(fd, raw + done, sizeof(raw) - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    close(fd);

    static const char hex[] = "0123456789abcdef";
    char text[sizeof(raw) * 2 + 2];
    for (size_t i = 0; i < sizeof(raw); ++i) {
        text[i * 2] = hex[raw[i] >> 4];
        text[i * 2 + 1] = hex[raw[i] & 15];
    }
    text[sizeof(raw) * 2] = '\n';
    text[sizeof(raw) * 2 + 1] = '\0';
    if (write_text_file(path, text, 0600) != 0) return -1;
    chmod(path, 0600);
    printf("PSK generated: %s\n", path);
    return 0;
}

static int create_result_dir(const app_config_t *cfg, const char *prefix,
                             char *path, size_t path_size)
{
    time_t now = time(NULL);
    struct tm tm_value;
    localtime_r(&now, &tm_value);
    char stamp[64];
    strftime(stamp, sizeof(stamp), "%Y%m%d_%H%M%S", &tm_value);
    snprintf(path, path_size, "%s/%s_%s_%s",
             cfg->output_root, prefix, stamp, app_role_name(cfg->role));
    return mkdir_recursive(path, 0750);
}

static void sanitize_component(const char *input, char *output, size_t output_size)
{
    size_t used = 0;
    if (output_size == 0) return;
    for (const unsigned char *p = (const unsigned char *)input;
         *p && used + 1U < output_size; ++p) {
        unsigned char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_') {
            output[used++] = (char)c;
        } else {
            output[used++] = '_';
        }
    }
    output[used] = '\0';
}

static int create_case_dir(const char *root, size_t index,
                           const crypto_test_case_t *test_case,
                           char *path, size_t path_size)
{
    char safe_id[96];
    sanitize_component(test_case->id, safe_id, sizeof(safe_id));
    int n = snprintf(path, path_size, "%s/case_%03zu_%s", root, index + 1U, safe_id);
    if (n < 0 || (size_t)n >= path_size) return -1;
    return mkdir_recursive(path, 0750);
}

static int verify_commands(const app_config_t *cfg)
{
    const char *required[] = {"systemctl", "swanctl", "ip", "cat", NULL};
    for (int i = 0; required[i]; ++i) {
        if (!command_exists(required[i])) {
            fprintf(stderr, "required command not found: %s\n", required[i]);
            return -1;
        }
    }
    if (cfg->capture_enabled && !command_exists("tcpdump")) {
        fprintf(stderr,
                "warning: tcpdump not found; packet capture will be diagnostic FAIL but data-path testing continues\n");
    }
    if (cfg->manage_firewall && !command_exists("iptables")) {
        fprintf(stderr, "manage_firewall=true but iptables not found\n");
        return -1;
    }
    return 0;
}

static int verify_removed_xfrm(const app_config_t *cfg, const char *result_dir,
                               const char *phase, const strongswan_sa_info_t *info)
{
    if (!info->reqid_valid) {
        log_info("no CHILD reqid was available for %s cleanup; target XFRM reqid verification skipped",
                 phase);
        return 0;
    }
    return xfrm_wait_for_reqid_absent(cfg, result_dir, phase, info->reqid, cfg->timeout_sec);
}

static void capture_drain(const app_config_t *cfg)
{
    if (cfg->capture_drain_ms <= 0) return;
    struct timespec delay;
    delay.tv_sec = cfg->capture_drain_ms / 1000;
    delay.tv_nsec = (long)(cfg->capture_drain_ms % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        if (g_interrupted) break;
    }
}

static void sleep_milliseconds(int milliseconds)
{
    if (milliseconds <= 0) return;
    struct timespec delay;
    delay.tv_sec = milliseconds / 1000;
    delay.tv_nsec = (long)(milliseconds % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
        if (g_interrupted) break;
    }
}

static int take_target_xfrm_snapshot(const app_config_t *cfg, const char *result_dir,
                                     const char *phase, const strongswan_sa_info_t *info,
                                     xfrm_snapshot_t *snapshot)
{
    if (info && info->reqid_valid) {
        return xfrm_take_snapshot_for_reqid(cfg, result_dir, phase, info->reqid, snapshot);
    }
    log_warn("target CHILD reqid unavailable for XFRM %s snapshot; falling back to all XFRM states",
             phase);
    return xfrm_take_snapshot(cfg, result_dir, phase, snapshot);
}

static bool expected_sa_matches(const char *expected, const strongswan_sa_info_t *info)
{
    if (!strcmp(expected, "pass")) return info->ready;
    if (!strcmp(expected, "ike_fail")) return !info->ike_present && !info->child_present;
    if (!strcmp(expected, "child_fail")) return info->ike_present && !info->ready;
    return false;
}

static void reset_capture_session(void)
{
    memset(&g_capture, 0, sizeof(g_capture));
    g_capture.pid = -1;
    g_capture.stderr_fd = -1;
    g_capture.stderr_log_fd = -1;
}

static int run_test_case(const app_config_t *cfg, const char *result_dir,
                         const char *case_id, const char *expected,
                         bool matrix_mode, bool separate_child_exchange,
                         const char *expected_child_ke, case_result_t *result)
{
    memset(result, 0, sizeof(*result));
    result->capture.enabled = cfg->capture_enabled;
    result->verdict.lifecycle_pass = true;
    result->verdict.child_ke_evaluated = separate_child_exchange;
    result->verdict.child_ke_ok = !separate_child_exchange;
    result->separate_child_exchange = separate_child_exchange;
    reset_capture_session();

    log_info("testcase=%s role=%s", case_id, app_role_name(cfg->role));
    log_info("IKE proposal: %s", cfg->ike_proposals);
    log_info("ESP proposal: %s", cfg->esp_proposals);
    log_info("IPsec mode: %s", cfg->ipsec_mode);
    if (separate_child_exchange) {
        log_info("PFS verification: childless IKE + separate CREATE_CHILD_SA, expected CHILD KE=%s",
                 expected_child_ke ? expected_child_ke : "<missing>");
    }

    strongswan_sa_info_t active_info = {0};
    strongswan_sa_info_t startup_info = {0};
    bool config_loaded = false;
    bool session_may_exist = false;
    bool expected_positive = strcmp(expected, "pass") == 0;

    if (cfg->cleanup_existing_sa) {
        if (strongswan_cleanup_target_sa(cfg, result_dir, "startup", &startup_info) != 0) {
            result->verdict.lifecycle_pass = false;
            goto finish;
        }
        if (verify_removed_xfrm(cfg, result_dir, "startup", &startup_info) != 0) {
            result->verdict.lifecycle_pass = false;
            goto finish;
        }
    }

    if (strongswan_load_configuration(cfg, result_dir) != 0) goto finish;
    config_loaded = true;
    session_may_exist = true;

    if (matrix_mode && udp_matrix_ready_barrier(cfg, result_dir, case_id) != 0) {
        result->verdict.lifecycle_pass = false;
        goto finish;
    }

    int establish_rc = 0;
    if (separate_child_exchange) {
        if (cfg->role == ROLE_INITIATOR) {
            establish_rc = strongswan_initiate_ike_only(cfg, result_dir);
            if (establish_rc == 0) establish_rc = strongswan_wait_for_ike(cfg, result_dir);
        } else {
            establish_rc = strongswan_wait_for_ike(cfg, result_dir);
        }

        if (establish_rc == 0 && matrix_mode &&
            udp_matrix_phase_barrier(cfg, result_dir, case_id, "IKE_ONLY_READY") != 0) {
            establish_rc = -1;
            result->verdict.lifecycle_pass = false;
        }

        if (establish_rc == 0) {
            if (cfg->role == ROLE_INITIATOR) {
                establish_rc = strongswan_initiate_child(cfg, result_dir);
                if (establish_rc == 0) establish_rc = strongswan_wait_for_sa(cfg, result_dir);
            } else {
                establish_rc = strongswan_wait_for_sa(cfg, result_dir);
            }
        }
    } else if (cfg->role == ROLE_INITIATOR) {
        establish_rc = strongswan_initiate(cfg, result_dir);
        if (establish_rc == 0) establish_rc = strongswan_wait_for_sa(cfg, result_dir);
    } else {
        establish_rc = strongswan_wait_for_sa(cfg, result_dir);
    }

    if (strongswan_get_sa_info(cfg, result_dir, "post_negotiation", &result->observed_sa) == 0) {
        result->sa_observed = true;
    }

    if (!expected_positive) {
        result->expected_match = result->sa_observed &&
                                 expected_sa_matches(expected, &result->observed_sa);
        if (result->expected_match) {
            log_pass("negative testcase matched expected result '%s'", expected);
        } else {
            log_error("negative testcase did not match expected result '%s'", expected);
        }
        goto finish;
    }

    if (establish_rc != 0 || !result->sa_observed || !result->observed_sa.ready) {
        log_error("positive testcase failed to establish expected IKE/CHILD SA");
        goto finish;
    }

    if (separate_child_exchange) {
        result->child_ke_verified = strongswan_sa_has_child_ke(&result->observed_sa, expected_child_ke);
        result->verdict.child_ke_ok = result->child_ke_verified;
        if (!result->child_ke_verified) {
            log_error("PFS CHILD key exchange verification failed: expected=%s observed=%s",
                      expected_child_ke ? expected_child_ke : "<missing>",
                      result->observed_sa.child_algorithms[0] ?
                      result->observed_sa.child_algorithms : "<none>");
            goto finish;
        }
        log_pass("PFS CHILD key exchange verified: %s in %s", expected_child_ke,
                 result->observed_sa.child_algorithms);
    } else {
        result->verdict.child_ke_ok = true;
    }

    result->verdict.ike_child_ok = true;
    active_info = result->observed_sa;

    /* v11 measurement ordering:
     *   capture ready -> peer capture-stage barrier -> XFRM baseline -> UDP.
     * This removes the v10 gap where the XFRM baseline was taken before
     * tcpdump was actually ready. */
    if (cfg->capture_enabled) {
        if (!command_exists("tcpdump")) {
            log_warn("tcpdump unavailable; capture result is diagnostic FAIL only");
        } else if (capture_start(cfg, result_dir, &g_capture) != 0) {
            log_warn("packet capture could not become ready; continuing data-path test");
        } else {
            result->capture.ready = true;
        }
    }

    if (matrix_mode && udp_matrix_phase_barrier(cfg, result_dir, case_id, "CAPTURE_STAGE_READY") != 0) {
        log_error("capture-stage peer synchronization failed");
        result->verdict.lifecycle_pass = false;
        goto finish;
    }

    (void)strongswan_snapshot(cfg, result_dir, "before");
    if (take_target_xfrm_snapshot(cfg, result_dir, "before", &active_info, &result->before) != 0) goto finish;
    if (g_capture.active) capture_mark_measurement_start(&g_capture);

    /* Give the responder enough local time to finish its baseline snapshot and
     * enter recvfrom() before the initiator starts its readiness probes.  This
     * is deliberately local-only so it does not add ESP packets after the
     * XFRM baseline. */
    if (cfg->role == ROLE_INITIATOR) sleep_milliseconds(cfg->measurement_guard_ms);

    int udp_rc = cfg->role == ROLE_INITIATOR ?
        udp_run_initiator(cfg, result_dir, &result->udp) :
        udp_run_responder(cfg, result_dir, &result->udp);

    /* Keep tcpdump alive through the post-test XFRM/SA snapshots and then give
     * libpcap/tcpdump a bounded drain interval before SIGINT. */
    (void)strongswan_snapshot(cfg, result_dir, "after");
    if (take_target_xfrm_snapshot(cfg, result_dir, "after", &active_info, &result->after) != 0) goto finish;
    if (g_capture.active) capture_mark_measurement_end(&g_capture);

    if (g_capture.active) {
        capture_drain(cfg);
        if (capture_stop(&g_capture) != 0) {
            log_warn("tcpdump required forced stop; attempting pcap analysis anyway");
        }
    }
    if (cfg->capture_enabled && result->capture.ready) {
        (void)capture_analyze(cfg, result_dir, &g_capture, &result->capture);
    }

    if (result->capture.measurement_window_known && result->before.scoped_to_reqid &&
        result->after.scoped_to_reqid && result->before.reqid == result->after.reqid) {
        long long xfrm_delta = result->after.packets - result->before.packets;
        result->capture.xfrm_capture_count_comparable = true;
        result->capture.xfrm_capture_count_match =
            xfrm_delta >= 0 && xfrm_delta == (long long)result->capture.measurement_total_esp_packets;
    }

    result->verdict.udp_ok = udp_rc == 0 &&
                             result->udp.sent == cfg->packet_count &&
                             result->udp.acknowledgements == cfg->packet_count;
    result->verdict.xfrm_counter_ok = xfrm_counters_increased(&result->before, &result->after);
    result->verdict.xfrm_error_ok = result->after.error_total == result->before.error_total;
    result->verdict.data_path_evaluated = true;
    result->verdict.data_path_pass = result->verdict.ike_child_ok && result->verdict.child_ke_ok &&
                                     result->verdict.udp_ok &&
                                     result->verdict.xfrm_counter_ok && result->verdict.xfrm_error_ok &&
                                     !g_interrupted;
    result->verdict.capture_pass = !cfg->capture_enabled ||
                                   (result->capture.ready && result->capture.analysis_ok &&
                                    result->capture.outbound_esp_seen &&
                                    !result->capture.plaintext_udp_seen &&
                                    result->capture.stats_known && result->capture.lossless);
    result->expected_match = result->verdict.data_path_pass;

    if (result->verdict.ike_child_ok && result->verdict.udp_ok) {
        if (udp_lifecycle_barrier(cfg, result_dir) != 0) {
            log_error("post-snapshot lifecycle barrier failed");
            result->verdict.lifecycle_pass = false;
        }
    }

finish:
    if (g_capture.active) {
        capture_drain(cfg);
        (void)capture_stop(&g_capture);
    }

    if (cfg->terminate_on_exit && config_loaded && session_may_exist) {
        strongswan_sa_info_t exit_info = {0};
        if (strongswan_cleanup_target_sa(cfg, result_dir, "exit", &exit_info) != 0) {
            result->verdict.lifecycle_pass = false;
        } else {
            const strongswan_sa_info_t *xfrm_info = active_info.reqid_valid ? &active_info : &exit_info;
            if (verify_removed_xfrm(cfg, result_dir, "exit", xfrm_info) != 0) {
                result->verdict.lifecycle_pass = false;
            }
        }
    }

    if (expected_positive) {
        result->verdict.overall_pass = result->verdict.data_path_evaluated &&
                                       result->verdict.data_path_pass &&
                                       result->verdict.lifecycle_pass;
        result->expected_match = result->verdict.overall_pass;
    } else {
        result->verdict.overall_pass = result->expected_match && result->verdict.lifecycle_pass;
    }

    log_info("================ v11 testcase verdict ================");
    log_info("Expected result               : %s", expected);
    log_info("Observed IKE/CHILD ready      : %s",
             result->sa_observed && result->observed_sa.ready ? "YES" : "NO");
    if (expected_positive) {
        log_info("IPsec Data Path / IKE+CHILD  : %s", result->verdict.ike_child_ok ? "PASS" : "FAIL");
        if (separate_child_exchange) {
            log_info("IPsec Data Path / CHILD KE   : %s expected=%s observed=%s",
                     result->verdict.child_ke_ok ? "PASS" : "FAIL",
                     expected_child_ke ? expected_child_ke : "<missing>",
                     result->observed_sa.child_algorithms[0] ?
                     result->observed_sa.child_algorithms : "<none>");
        }
        log_info("IPsec Data Path / UDP        : %s", result->verdict.udp_ok ? "PASS" : "FAIL");
        log_info("IPsec Data Path / XFRM       : %s (packets %+lld, bytes %+lld)",
                 result->verdict.xfrm_counter_ok ? "PASS" : "FAIL",
                 result->after.packets - result->before.packets,
                 result->after.bytes - result->before.bytes);
        log_info("IPsec Data Path / XFRM err   : %s (delta %+lld)",
                 result->verdict.xfrm_error_ok ? "PASS" : "FAIL",
                 result->after.error_total - result->before.error_total);
        log_info("IPSEC DATA PATH              : %s",
                 result->verdict.data_path_evaluated ?
                 (result->verdict.data_path_pass ? "PASS" : "FAIL") : "NOT RUN");
        if (cfg->capture_enabled) {
            log_info("Packet Capture / ready       : %s", result->capture.ready ? "PASS" : "FAIL");
            log_info("Packet Capture / outbound ESP: %s (%d packets)",
                     result->capture.outbound_esp_seen ? "PASS" : "FAIL",
                     result->capture.outbound_esp_packets);
            log_info("Packet Capture / plain UDP   : %s (%d packets)",
                     result->capture.plaintext_udp_seen ? "FAIL" : "PASS",
                     result->capture.plaintext_udp_packets);
            log_info("Packet Capture / kernel drop: %s (%d packets; captured=%d filter=%d)",
                     result->capture.stats_known ?
                     (result->capture.lossless ? "PASS" : "FAIL") : "UNKNOWN",
                     result->capture.packets_dropped_by_kernel,
                     result->capture.packets_captured,
                     result->capture.packets_received_by_filter);
            log_info("Packet Capture / measure ESP: %d packets (window=%s)",
                     result->capture.measurement_total_esp_packets,
                     result->capture.measurement_window_known ? "KNOWN" : "UNKNOWN");
            log_info("Packet Capture / XFRM match : %s (reqid-scoped delta=%+lld)",
                     result->capture.xfrm_capture_count_comparable ?
                         (result->capture.xfrm_capture_count_match ? "PASS" : "MISMATCH") : "N/A",
                     result->after.packets - result->before.packets);
            log_info("PACKET CAPTURE               : %s (diagnostic only)",
                     result->verdict.capture_pass ? "PASS" : "FAIL");
        }
    }
    log_info("Expected outcome match        : %s", result->expected_match ? "PASS" : "FAIL");
    log_info("SA LIFECYCLE                 : %s", result->verdict.lifecycle_pass ? "PASS" : "FAIL");
    log_info("TESTCASE RESULT              : %s", result->verdict.overall_pass ? "PASS" : "FAIL");

    (void)report_write(cfg, result_dir, &result->udp, &result->before, &result->after,
                       &result->capture, &result->verdict);
    return result->verdict.overall_pass ? 0 : -1;
}

static int do_cleanup(const app_config_t *cfg)
{
    char dir[1024];
    if (create_result_dir(cfg, "cleanup", dir, sizeof(dir)) != 0) return -1;
    char log_path[1024];
    join_path(log_path, sizeof(log_path), dir, "application.log");
    if (log_open(log_path) != 0) return -1;

    int rc = -1;
    if (strongswan_ensure_ready(cfg, dir) != 0) goto out;
    strongswan_sa_info_t old_info = {0};
    if (strongswan_cleanup_target_sa(cfg, dir, "manual", &old_info) != 0) goto out;
    if (verify_removed_xfrm(cfg, dir, "manual", &old_info) != 0) goto out;
    log_pass("manual target-SA cleanup completed");
    rc = 0;
out:
    log_info("cleanup logs: %s", dir);
    log_close();
    return rc;
}

static void csv_field(FILE *fp, const char *value)
{
    fputc('"', fp);
    for (const char *p = value ? value : ""; *p; ++p) {
        if (*p == '"') fputc('"', fp);
        fputc(*p, fp);
    }
    fputc('"', fp);
}

static int append_matrix_csv(FILE *fp, const crypto_test_case_t *test_case,
                             const app_config_t *cfg, const case_result_t *result)
{
    csv_field(fp, test_case->id); fputc(',', fp);
    csv_field(fp, test_case->category); fputc(',', fp);
    csv_field(fp, test_case->name); fputc(',', fp);
    csv_field(fp, cfg->ike_proposals); fputc(',', fp);
    csv_field(fp, cfg->esp_proposals); fputc(',', fp);
    csv_field(fp, cfg->ipsec_mode); fputc(',', fp);
    csv_field(fp, test_case->expected); fputc(',', fp);
    fprintf(fp, "%s,", test_case->separate_child_exchange ? "yes" : "no");
    csv_field(fp, test_case->expected_child_ke); fputc(',', fp);
    csv_field(fp, result->observed_sa.child_algorithms); fputc(',', fp);
    fprintf(fp, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%u,%d,%d,%d,%d,%d,%d,%s,%lld,%lld\n",
            result->verdict.child_ke_evaluated ?
                (result->verdict.child_ke_ok ? "PASS" : "FAIL") : "N/A",
            result->verdict.ike_child_ok ? "PASS" : "FAIL",
            result->verdict.udp_ok ? "PASS" : "FAIL",
            result->verdict.xfrm_counter_ok ? "PASS" : "FAIL",
            result->verdict.xfrm_error_ok ? "PASS" : "FAIL",
            cfg->capture_enabled ? (result->verdict.capture_pass ? "PASS" : "FAIL") : "DISABLED",
            result->verdict.lifecycle_pass ? "PASS" : "FAIL",
            result->expected_match ? "PASS" : "FAIL",
            result->before.scoped_to_reqid ? "reqid" : "all-states",
            result->before.scoped_to_reqid ? result->before.reqid : 0U,
            result->capture.outbound_esp_packets,
            result->capture.plaintext_udp_packets,
            result->capture.packets_captured,
            result->capture.packets_received_by_filter,
            result->capture.packets_dropped_by_kernel,
            result->capture.measurement_total_esp_packets,
            result->capture.xfrm_capture_count_comparable ?
                (result->capture.xfrm_capture_count_match ? "PASS" : "MISMATCH") : "N/A",
            result->after.packets - result->before.packets,
            result->after.error_total - result->before.error_total);
    fflush(fp);
    return ferror(fp) ? -1 : 0;
}

static int run_matrix(const app_config_t *base_cfg, const char *matrix_path,
                      const char *selected_case)
{
    crypto_test_matrix_t matrix;
    char error[1024];
    if (test_matrix_load(matrix_path, &matrix, error, sizeof(error)) != 0) {
        fprintf(stderr, "matrix configuration error: %s\n", error);
        return 1;
    }

    char root[1024];
    if (create_result_dir(base_cfg, "ipsec_matrix", root, sizeof(root)) != 0) {
        perror("create matrix result directory");
        return 1;
    }

    char root_log[1024];
    join_path(root_log, sizeof(root_log), root, "matrix_application.log");
    if (log_open(root_log) != 0) {
        perror("log_open");
        return 1;
    }

    log_info("v11 crypto compatibility matrix start: %zu configured cases", matrix.count);
    log_info("matrix file: %s", matrix_path);
    log_info("role=%s local=%s remote=%s", app_role_name(base_cfg->role),
             base_cfg->local_ip, base_cfg->remote_ip);

    if (network_prepare(base_cfg, root) != 0 || strongswan_ensure_ready(base_cfg, root) != 0) {
        log_close();
        return 1;
    }

    bool firewall_installed = false;
    if (base_cfg->manage_firewall) {
        if (firewall_apply(base_cfg, root) != 0) {
            log_close();
            return 1;
        }
        firewall_installed = true;
    }

    char csv_path[1024];
    join_path(csv_path, sizeof(csv_path), root, "matrix_summary.csv");
    FILE *csv = fopen(csv_path, "w");
    if (!csv) {
        log_error("cannot create %s: %s", csv_path, strerror(errno));
        if (firewall_installed) (void)firewall_remove(base_cfg, root);
        log_close();
        return 1;
    }
    fprintf(csv,
            "test_id,category,name,ike_proposals,esp_proposals,mode,expected,"
            "separate_child_exchange,expected_child_ke,observed_child_algorithms,child_ke,"
            "ike_child,udp,xfrm_counter,xfrm_error,capture,lifecycle,expected_match,"
            "xfrm_counter_scope,xfrm_reqid,outbound_esp_packets,plaintext_udp_packets,capture_packets,"
            "capture_received_by_filter,capture_kernel_drops,capture_measurement_esp_packets,"
            "capture_xfrm_count_match,xfrm_packet_delta,xfrm_error_delta\n");

    size_t executed = 0;
    size_t passed = 0;
    size_t failed = 0;

    for (size_t i = 0; i < matrix.count && !g_interrupted; ++i) {
        const crypto_test_case_t *test_case = &matrix.cases[i];
        if (selected_case) {
            if (strcmp(selected_case, test_case->id) != 0) continue;
            if (!test_case->enabled) {
                log_info("explicit --case selection overrides enabled=false for [%s]", test_case->id);
            }
        } else if (!test_case->enabled) {
            continue;
        }

        app_config_t case_cfg;
        if (test_matrix_apply_case(test_case, base_cfg, &case_cfg, error, sizeof(error)) != 0) {
            log_error("cannot apply testcase %s: %s", test_case->id, error);
            ++failed;
            ++executed;
            continue;
        }

        char case_dir[1024];
        if (create_case_dir(root, i, test_case, case_dir, sizeof(case_dir)) != 0) {
            log_error("cannot create testcase directory for %s", test_case->id);
            ++failed;
            ++executed;
            continue;
        }

        log_close();
        char case_log[1024];
        join_path(case_log, sizeof(case_log), case_dir, "application.log");
        if (log_open(case_log) != 0) {
            fprintf(stderr, "cannot open testcase log %s\n", case_log);
            ++failed;
            ++executed;
            (void)log_open(root_log);
            continue;
        }

        log_info("============================================================");
        log_info("MATRIX %zu/%zu [%s] %s", i + 1U, matrix.count,
                 test_case->id, test_case->name);
        log_info("category=%s expected=%s", test_case->category, test_case->expected);

        case_result_t result;
        int case_rc = run_test_case(&case_cfg, case_dir, test_case->id,
                                    test_case->expected, true,
                                    test_case->separate_child_exchange,
                                    test_case->expected_child_ke, &result);
        ++executed;
        if (case_rc == 0) ++passed;
        else ++failed;
        (void)append_matrix_csv(csv, test_case, &case_cfg, &result);

        log_close();
        (void)log_open(root_log);
        log_info("completed testcase [%s]: %s", test_case->id,
                 case_rc == 0 ? "PASS" : "FAIL");
    }

    if (selected_case && executed == 0) {
        log_error("selected testcase '%s' was not found", selected_case);
        failed = 1;
    }

    fclose(csv);
    if (firewall_installed) (void)firewall_remove(base_cfg, root);

    log_info("================ v11 matrix summary ================");
    log_info("executed=%zu passed=%zu failed=%zu", executed, passed, failed);
    log_info("matrix summary CSV: %s", csv_path);
    log_info("result directory: %s", root);
    log_close();
    return (!g_interrupted && executed > 0 && failed == 0) ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *config_path = NULL;
    const char *psk_path = NULL;
    const char *matrix_path = NULL;
    const char *selected_case = NULL;
    bool check_only = false;
    bool cleanup = false;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--config") && i + 1 < argc) config_path = argv[++i];
        else if (!strcmp(argv[i], "--matrix") && i + 1 < argc) matrix_path = argv[++i];
        else if (!strcmp(argv[i], "--case") && i + 1 < argc) selected_case = argv[++i];
        else if (!strcmp(argv[i], "--check")) check_only = true;
        else if (!strcmp(argv[i], "--cleanup")) cleanup = true;
        else if (!strcmp(argv[i], "--generate-psk") && i + 1 < argc) psk_path = argv[++i];
        else if (!strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (psk_path) return generate_psk(psk_path) == 0 ? 0 : 1;
    if (!config_path) {
        usage(argv[0]);
        return 1;
    }
    if (selected_case && !matrix_path) {
        fprintf(stderr, "--case requires --matrix\n");
        return 1;
    }

    app_config_t cfg;
    char error[512];
    if (app_config_load(config_path, &cfg, error, sizeof(error)) != 0) {
        fprintf(stderr, "configuration error: %s\n", error);
        return 1;
    }
    if (geteuid() != 0) {
        fprintf(stderr, "run with sudo/root\n");
        return 1;
    }
    if (verify_commands(&cfg) != 0) return 1;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    reset_capture_session();

    if (cleanup) return do_cleanup(&cfg) == 0 ? 0 : 1;
    if (matrix_path) {
        if (check_only) {
            crypto_test_matrix_t matrix;
            if (test_matrix_load(matrix_path, &matrix, error, sizeof(error)) != 0) {
                fprintf(stderr, "matrix configuration error: %s\n", error);
                return 1;
            }
            printf("configuration OK; matrix contains %zu cases\n", matrix.count);
            return 0;
        }
        return run_matrix(&cfg, matrix_path, selected_case);
    }

    char result_dir[1024];
    if (create_result_dir(&cfg, "ipsec", result_dir, sizeof(result_dir)) != 0) {
        perror("create result directory");
        return 1;
    }
    char log_path[1024];
    join_path(log_path, sizeof(log_path), result_dir, "application.log");
    if (log_open(log_path) != 0) {
        perror("log_open");
        return 1;
    }

    if (network_prepare(&cfg, result_dir) != 0 || strongswan_ensure_ready(&cfg, result_dir) != 0) {
        log_close();
        return 1;
    }

    bool firewall_installed = false;
    if (cfg.manage_firewall) {
        if (firewall_apply(&cfg, result_dir) != 0) {
            log_close();
            return 1;
        }
        firewall_installed = true;
    }

    int rc = 0;
    if (check_only) {
        if (strongswan_load_configuration(&cfg, result_dir) != 0) rc = 1;
        else log_pass("configuration check completed; SA lifecycle was not modified");
    } else {
        case_result_t result;
        rc = run_test_case(&cfg, result_dir, "single", "pass", false, false, NULL, &result) == 0 ? 0 : 1;
    }

    if (firewall_installed) (void)firewall_remove(&cfg, result_dir);
    log_info("result directory: %s", result_dir);
    log_close();
    return rc;
}
