#define _POSIX_C_SOURCE 200809L
#include "capture.h"
#include "logger.h"
#include "process.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CAPTURE_READY_TIMEOUT_MS 5000
#define READY_TEXT_MAX 8192

static int write_all(int fd, const char *data, size_t size)
{
    while (size > 0) {
        ssize_t n = write(fd, data, size);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        data += n;
        size -= (size_t)n;
    }
    return 0;
}

static void close_capture_fds(capture_session_t *session)
{
    if (session->stderr_fd >= 0) {
        close(session->stderr_fd);
        session->stderr_fd = -1;
    }
    if (session->stderr_log_fd >= 0) {
        close(session->stderr_log_fd);
        session->stderr_log_fd = -1;
    }
}

static void drain_stderr(capture_session_t *session)
{
    if (session->stderr_fd < 0) return;
    char buffer[4096];
    for (;;) {
        ssize_t n = read(session->stderr_fd, buffer, sizeof(buffer));
        if (n > 0) {
            if (session->stderr_log_fd >= 0) (void)write_all(session->stderr_log_fd, buffer, (size_t)n);
            continue;
        }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        return;
    }
}

static int wait_for_ready(capture_session_t *session, const char *interface_name)
{
    char observed[READY_TEXT_MAX];
    size_t used = 0;
    observed[0] = '\0';
    int waited_ms = 0;

    while (waited_ms < CAPTURE_READY_TIMEOUT_MS) {
        int status = 0;
        pid_t child = waitpid(session->pid, &status, WNOHANG);
        if (child == session->pid) {
            session->active = false;
            drain_stderr(session);
            return -1;
        }

        struct pollfd pfd = {.fd = session->stderr_fd, .events = POLLIN | POLLHUP};
        int slice = 100;
        int prc = poll(&pfd, 1, slice);
        waited_ms += slice;
        if (prc < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (prc == 0) continue;

        if (pfd.revents & (POLLIN | POLLHUP)) {
            char buffer[2048];
            ssize_t n = read(session->stderr_fd, buffer, sizeof(buffer));
            if (n > 0) {
                if (session->stderr_log_fd >= 0 && write_all(session->stderr_log_fd, buffer, (size_t)n) != 0) return -1;
                size_t copy = (size_t)n;
                if (copy > sizeof(observed) - used - 1U) copy = sizeof(observed) - used - 1U;
                if (copy > 0) {
                    memcpy(observed + used, buffer, copy);
                    used += copy;
                    observed[used] = '\0';
                }
                if (strstr(observed, "listening on") && strstr(observed, interface_name)) {
                    session->ready = true;
                    return 0;
                }
            } else if (n == 0) {
                return -1;
            } else if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
        }
    }
    return -1;
}


static long long realtime_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    return (long long)ts.tv_sec * 1000000LL + (long long)(ts.tv_nsec / 1000L);
}

void capture_mark_measurement_start(capture_session_t *session)
{
    if (!session || !session->active || !session->ready) return;
    session->measurement_start_us = realtime_us();
    session->measurement_end_us = 0;
    session->measurement_window_valid = session->measurement_start_us > 0;
}

void capture_mark_measurement_end(capture_session_t *session)
{
    if (!session || !session->measurement_window_valid) return;
    session->measurement_end_us = realtime_us();
    if (session->measurement_end_us <= session->measurement_start_us) {
        session->measurement_window_valid = false;
    }
}

int capture_start(const app_config_t *cfg, const char *result_dir, capture_session_t *session)
{
    memset(session, 0, sizeof(*session));
    session->pid = -1;
    session->stderr_fd = -1;
    session->stderr_log_fd = -1;
    join_path(session->pcap_path, sizeof(session->pcap_path), result_dir, "wire_capture.pcap");
    join_path(session->stderr_path, sizeof(session->stderr_path), result_dir, "tcpdump_stderr.txt");
    char stdout_path[1024];
    join_path(stdout_path, sizeof(stdout_path), result_dir, "tcpdump_stdout.txt");

    char filter[512];
    snprintf(filter, sizeof(filter), "host %s and (esp or udp port 4500 or udp port %d)",
             cfg->remote_ip, cfg->udp_port);
    char buffer_kib[32];
    snprintf(buffer_kib, sizeof(buffer_kib), "%d", cfg->capture_buffer_kib);
    char *argv[] = {"tcpdump", "--immediate-mode", "-B", buffer_kib, "-U", "-ni",
                    (char *)cfg->interface_name, "-s", "0", "-w", session->pcap_path,
                    filter, NULL};

    int stderr_pipe[2];
    if (pipe(stderr_pipe) != 0) {
        log_warn("cannot create tcpdump readiness pipe: %s", strerror(errno));
        return -1;
    }

    int stdout_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    int stderr_log_fd = open(session->stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (stdout_fd < 0 || stderr_log_fd < 0) {
        if (stdout_fd >= 0) close(stdout_fd);
        if (stderr_log_fd >= 0) close(stderr_log_fd);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        log_warn("cannot create tcpdump log files: %s", strerror(errno));
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(stdout_fd);
        close(stderr_log_fd);
        close(stderr_pipe[0]);
        close(stderr_pipe[1]);
        log_warn("cannot fork tcpdump: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        close(stderr_pipe[0]);
        if (dup2(stdout_fd, STDOUT_FILENO) < 0 || dup2(stderr_pipe[1], STDERR_FILENO) < 0) _exit(127);
        close(stdout_fd);
        close(stderr_pipe[1]);
        close(stderr_log_fd);
        execvp(argv[0], argv);
        dprintf(STDERR_FILENO, "execvp(tcpdump) failed: %s\n", strerror(errno));
        _exit(127);
    }

    close(stdout_fd);
    close(stderr_pipe[1]);
    int flags = fcntl(stderr_pipe[0], F_GETFL, 0);
    if (flags >= 0) (void)fcntl(stderr_pipe[0], F_SETFL, flags | O_NONBLOCK);
    session->pid = pid;
    session->stderr_fd = stderr_pipe[0];
    session->stderr_log_fd = stderr_log_fd;
    session->active = true;

    if (wait_for_ready(session, cfg->interface_name) != 0) {
        log_warn("tcpdump did not report 'listening on %s' within %d ms; capture disabled for this run",
                 cfg->interface_name, CAPTURE_READY_TIMEOUT_MS);
        if (session->active) (void)process_stop(session->pid, SIGINT, 3000);
        drain_stderr(session);
        close_capture_fds(session);
        session->active = false;
        session->pid = -1;
        return -1;
    }

    log_pass("packet capture ready on %s (IN/OUT, immediate mode, buffer=%d KiB, no -Q direction restriction)",
             cfg->interface_name, cfg->capture_buffer_kib);
    return 0;
}

int capture_stop(capture_session_t *session)
{
    if (!session->active) {
        close_capture_fds(session);
        return 0;
    }
    int rc = process_stop(session->pid, SIGINT, 3000);
    drain_stderr(session);
    close_capture_fds(session);
    session->active = false;
    session->pid = -1;
    return rc;
}

static int count_esp_packet_lines(const char *text)
{
    int count = 0;
    if (!text) return 0;
    char *copy = strdup(text);
    if (!copy) return 0;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strstr(line, "ESP(spi=") || strstr(line, "UDP-encap: ESP")) ++count;
    }
    free(copy);
    return count;
}

static int count_packet_lines(const char *text)
{
    int count = 0;
    if (!text) return 0;
    char *copy = strdup(text);
    if (!copy) return 0;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (strstr(line, " > ")) ++count;
    }
    free(copy);
    return count;
}


static void parse_capture_stats(const char *path, capture_result_t *result)
{
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[512];
    bool got_captured = false;
    bool got_received = false;
    bool got_dropped = false;
    while (fgets(line, sizeof(line), fp)) {
        int value = 0;
        if (strstr(line, " packets captured") && sscanf(line, "%d", &value) == 1) {
            result->packets_captured = value;
            got_captured = true;
        } else if (strstr(line, " packets received by filter") && sscanf(line, "%d", &value) == 1) {
            result->packets_received_by_filter = value;
            got_received = true;
        } else if (strstr(line, " packets dropped by kernel") && sscanf(line, "%d", &value) == 1) {
            result->packets_dropped_by_kernel = value;
            got_dropped = true;
        }
    }
    fclose(fp);
    result->stats_known = got_captured && got_received && got_dropped;
    result->lossless = result->stats_known && result->packets_dropped_by_kernel == 0;
}


static int count_esp_in_measurement_window(const char *text, const capture_session_t *session)
{
    if (!text || !session || !session->measurement_window_valid ||
        session->measurement_start_us <= 0 || session->measurement_end_us <= 0) return 0;

    int count = 0;
    char *copy = strdup(text);
    if (!copy) return 0;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        if (!(strstr(line, "ESP(spi=") || strstr(line, "UDP-encap: ESP"))) continue;
        char *end = NULL;
        double seconds = strtod(line, &end);
        if (end == line || seconds <= 0.0) continue;
        long long packet_us = (long long)(seconds * 1000000.0 + 0.5);
        if (packet_us >= session->measurement_start_us &&
            packet_us <= session->measurement_end_us) {
            ++count;
        }
    }
    free(copy);
    return count;
}

int capture_analyze(const app_config_t *cfg, const char *result_dir,
                    const capture_session_t *session, capture_result_t *result)
{
    result->enabled = true;
    result->ready = session->ready;
    result->analysis_ok = false;
    result->outbound_esp_seen = false;
    result->plaintext_udp_seen = false;
    result->outbound_esp_packets = 0;
    result->plaintext_udp_packets = 0;
    result->stats_known = false;
    result->lossless = false;
    result->packets_captured = 0;
    result->packets_received_by_filter = 0;
    result->packets_dropped_by_kernel = 0;
    result->measurement_window_known = false;
    result->measurement_total_esp_packets = 0;
    result->xfrm_capture_count_comparable = false;
    result->xfrm_capture_count_match = false;

    parse_capture_stats(session->stderr_path, result);

    char outbound_filter[512];
    snprintf(outbound_filter, sizeof(outbound_filter),
             "src host %s and dst host %s and (esp or udp port 4500)",
             cfg->local_ip, cfg->remote_ip);
    char *outbound_argv[] = {"tcpdump", "-nn", "-tt", "-r", (char *)session->pcap_path,
                             outbound_filter, NULL};
    char *outbound = NULL;
    int outbound_rc = process_run(outbound_argv, &outbound);
    char path[1024];
    join_path(path, sizeof(path), result_dir, "outbound_esp_check.txt");
    write_text_file(path, outbound ? outbound : "", 0640);
    if (outbound_rc == 0) {
        result->outbound_esp_packets = count_esp_packet_lines(outbound);
        result->outbound_esp_seen = result->outbound_esp_packets > 0;
    }
    free(outbound);

    char plain_filter[512];
    snprintf(plain_filter, sizeof(plain_filter),
             "host %s and host %s and udp port %d", cfg->local_ip, cfg->remote_ip, cfg->udp_port);
    char *plain_argv[] = {"tcpdump", "-nn", "-tt", "-r", (char *)session->pcap_path,
                          plain_filter, NULL};
    char *plain = NULL;
    int plain_rc = process_run(plain_argv, &plain);
    join_path(path, sizeof(path), result_dir, "plaintext_udp_check.txt");
    write_text_file(path, plain ? plain : "", 0640);
    if (plain_rc == 0) {
        result->plaintext_udp_packets = count_packet_lines(plain);
        result->plaintext_udp_seen = result->plaintext_udp_packets > 0;
    }
    free(plain);

    char *summary_argv[] = {"tcpdump", "-nn", "-tt", "-r", (char *)session->pcap_path, NULL};
    char *summary = NULL;
    int summary_rc = process_run(summary_argv, &summary);
    join_path(path, sizeof(path), result_dir, "tcpdump_summary.txt");
    write_text_file(path, summary ? summary : "", 0640);
    if (summary_rc == 0 && session->measurement_window_valid) {
        result->measurement_window_known = true;
        result->measurement_total_esp_packets =
            count_esp_in_measurement_window(summary ? summary : "", session);
    }
    free(summary);

    result->analysis_ok = outbound_rc == 0 && plain_rc == 0 && summary_rc == 0;
    log_info("capture analysis: ready=%s outbound_esp=%s (%d packets) plaintext_udp=%s (%d packets) stats=%s captured=%d filter=%d kernel_drop=%d measurement_esp=%d window=%s",
             result->ready ? "yes" : "no",
             result->outbound_esp_seen ? "yes" : "no", result->outbound_esp_packets,
             result->plaintext_udp_seen ? "yes" : "no", result->plaintext_udp_packets,
             result->stats_known ? "known" : "unknown", result->packets_captured,
             result->packets_received_by_filter, result->packets_dropped_by_kernel,
             result->measurement_total_esp_packets,
             result->measurement_window_known ? "known" : "unknown");
    if (result->stats_known && result->packets_dropped_by_kernel > 0) {
        log_warn("tcpdump/libpcap dropped %d packets in kernel capture buffer; IPsec data-path result is unaffected but packet-capture result is incomplete",
                 result->packets_dropped_by_kernel);
    }
    return result->analysis_ok ? 0 : -1;
}
