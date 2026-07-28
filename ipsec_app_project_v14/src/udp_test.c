#define _POSIX_C_SOURCE 200809L
#include "udp_test.h"
#include "logger.h"
#include "process.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int set_timeout(int fd, int seconds)
{
    struct timeval tv = {.tv_sec = seconds, .tv_usec = 0};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static FILE *open_udp_log(const char *result_dir)
{
    char path[1024]; join_path(path, sizeof(path), result_dir, "udp_test.txt");
    return fopen(path, "w");
}

int udp_run_responder(const app_config_t *cfg, const char *result_dir, udp_result_t *result)
{
    memset(result, 0, sizeof(*result));
    FILE *log = open_udp_log(result_dir);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { if (log) fclose(log); return -1; }
    set_timeout(fd, cfg->timeout_sec);
    struct sockaddr_in local = {0}; local.sin_family = AF_INET; local.sin_port = htons((uint16_t)cfg->udp_port);
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("UDP bind %s:%d failed: %s", cfg->local_ip, cfg->udp_port, strerror(errno));
        close(fd); if (log) fclose(log); return -1;
    }
    log_pass("UDP responder listening on %s:%d", cfg->local_ip, cfg->udp_port);
    unsigned char *buffer = malloc((size_t)cfg->payload_size + 1U);
    if (!buffer) { close(fd); if (log) fclose(log); return -1; }

    int sequence = 1;
    while (sequence <= cfg->packet_count) {
        struct sockaddr_in peer; socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(fd, buffer, (size_t)cfg->payload_size, 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) { log_error("UDP receive timeout/error at packet %d: %s", sequence, strerror(errno)); free(buffer); close(fd); if (log) fclose(log); return -1; }
        buffer[n] = '\0';
        if (strcmp((char *)buffer, "IPSEC-READY?") == 0) {
            static const char ready[] = "IPSEC-READY!";
            sendto(fd, ready, sizeof(ready) - 1U, 0, (struct sockaddr *)&peer, peer_len);
            if (log) fprintf(log, "readiness probe acknowledged\n");
            continue;
        }
        result->received++; result->bytes_received += n;
        char ack[128]; int ack_len = snprintf(ack, sizeof(ack), "IPSEC-ACK %d/%d", sequence, cfg->packet_count);
        ssize_t sent = sendto(fd, ack, (size_t)ack_len, 0, (struct sockaddr *)&peer, peer_len);
        if (sent != ack_len) { log_error("UDP ACK send failed at packet %d", sequence); free(buffer); close(fd); if (log) fclose(log); return -1; }
        result->sent++; result->acknowledgements++; result->bytes_sent += sent;
        if (log) fprintf(log, "RX %d bytes; TX ACK %d/%d\n", (int)n, sequence, cfg->packet_count);
        ++sequence;
    }
    free(buffer); close(fd); if (log) fclose(log);
    log_pass("UDP responder received %d and acknowledged %d datagrams", result->received, result->acknowledgements);
    return 0;
}

static int wait_for_responder(int fd, const app_config_t *cfg,
                              const struct sockaddr_in *remote, FILE *log)
{
    static const char probe[] = "IPSEC-READY?";
    time_t deadline = time(NULL) + cfg->timeout_sec;
    set_timeout(fd, 1);
    while (time(NULL) <= deadline) {
        (void)sendto(fd, probe, sizeof(probe) - 1U, 0,
                     (const struct sockaddr *)remote, sizeof(*remote));
        char reply[64];
        ssize_t n = recvfrom(fd, reply, sizeof(reply) - 1U, 0, NULL, NULL);
        if (n > 0) {
            reply[n] = '\0';
            if (strcmp(reply, "IPSEC-READY!") == 0) {
                if (log) fprintf(log, "responder readiness confirmed\n");
                log_pass("UDP responder readiness confirmed through IPsec path");
                set_timeout(fd, cfg->timeout_sec);
                return 0;
            }
        }
    }
    log_error("UDP responder did not become ready within %d seconds", cfg->timeout_sec);
    return -1;
}

int udp_run_initiator(const app_config_t *cfg, const char *result_dir, udp_result_t *result)
{
    memset(result, 0, sizeof(*result));
    FILE *log = open_udp_log(result_dir);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { if (log) fclose(log); return -1; }
    set_timeout(fd, cfg->timeout_sec);
    struct sockaddr_in local = {0}; local.sin_family = AF_INET; local.sin_port = 0;
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("UDP source bind %s failed: %s", cfg->local_ip, strerror(errno)); close(fd); if (log) fclose(log); return -1;
    }
    struct sockaddr_in remote = {0}; remote.sin_family = AF_INET; remote.sin_port = htons((uint16_t)cfg->udp_port);
    inet_pton(AF_INET, cfg->remote_ip, &remote.sin_addr);
    if (wait_for_responder(fd, cfg, &remote, log) != 0) {
        close(fd); if (log) fclose(log); return -1;
    }

    unsigned char *payload = malloc((size_t)cfg->payload_size);
    if (!payload) { close(fd); if (log) fclose(log); return -1; }
    for (int i = 1; i <= cfg->packet_count; ++i) {
        memset(payload, 'A' + (i % 26), (size_t)cfg->payload_size);
        int header = snprintf((char *)payload, (size_t)cfg->payload_size,
                              "IPSEC-UDP-TEST sequence=%d/%d ", i, cfg->packet_count);
        if (header < 0) { free(payload); close(fd); if (log) fclose(log); return -1; }
        ssize_t sent = sendto(fd, payload, (size_t)cfg->payload_size, 0,
                              (struct sockaddr *)&remote, sizeof(remote));
        if (sent != cfg->payload_size) { log_error("UDP send failed at packet %d: %s", i, strerror(errno)); free(payload); close(fd); if (log) fclose(log); return -1; }
        result->sent++; result->bytes_sent += sent;
        char ack[128]; ssize_t n = recvfrom(fd, ack, sizeof(ack) - 1, 0, NULL, NULL);
        if (n < 0) { log_error("UDP ACK timeout at packet %d: %s", i, strerror(errno)); free(payload); close(fd); if (log) fclose(log); return -1; }
        ack[n] = '\0';
        char expected[128]; snprintf(expected, sizeof(expected), "IPSEC-ACK %d/%d", i, cfg->packet_count);
        if (strcmp(ack, expected) != 0) { log_error("unexpected UDP ACK: expected '%s', got '%s'", expected, ack); free(payload); close(fd); if (log) fclose(log); return -1; }
        result->received++; result->acknowledgements++; result->bytes_received += n;
        if (log) fprintf(log, "TX %d bytes; RX %s\n", cfg->payload_size, ack);
    }
    free(payload); close(fd); if (log) fclose(log);
    log_pass("UDP initiator sent %d and received %d acknowledgements", result->sent, result->acknowledgements);
    return 0;
}

static FILE *open_lifecycle_log(const char *result_dir)
{
    char path[1024];
    join_path(path, sizeof(path), result_dir, "udp_lifecycle_barrier.txt");
    return fopen(path, "w");
}

static int lifecycle_barrier_responder(const app_config_t *cfg, const char *result_dir)
{
    FILE *log = open_lifecycle_log(result_dir);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (log) fclose(log);
        return -1;
    }
    set_timeout(fd, cfg->timeout_sec);

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons((uint16_t)cfg->udp_port);
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("lifecycle barrier UDP bind %s:%d failed: %s",
                  cfg->local_ip, cfg->udp_port, strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }

    static const char request[] = "IPSEC-LIFECYCLE-READY?";
    static const char response[] = "IPSEC-LIFECYCLE-READY!";
    char buffer[128];
    struct sockaddr_in peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t n = recvfrom(fd, buffer, sizeof(buffer) - 1U, 0,
                         (struct sockaddr *)&peer, &peer_len);
    if (n < 0) {
        log_error("lifecycle barrier receive failed: %s", strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }
    buffer[n] = '\0';
    if (strcmp(buffer, request) != 0) {
        log_error("unexpected lifecycle barrier request: '%s'", buffer);
        close(fd);
        if (log) fclose(log);
        return -1;
    }
    ssize_t sent = sendto(fd, response, sizeof(response) - 1U, 0,
                          (struct sockaddr *)&peer, peer_len);
    if (sent != (ssize_t)(sizeof(response) - 1U)) {
        log_error("lifecycle barrier response send failed: %s", strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }
    if (log) fprintf(log, "responder barrier acknowledged after post-test snapshots\n");
    close(fd);
    if (log) fclose(log);
    log_pass("peer lifecycle barrier completed after post-test snapshots");
    return 0;
}

static int lifecycle_barrier_initiator(const app_config_t *cfg, const char *result_dir)
{
    FILE *log = open_lifecycle_log(result_dir);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (log) fclose(log);
        return -1;
    }
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("lifecycle barrier source bind %s failed: %s", cfg->local_ip, strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons((uint16_t)cfg->udp_port);
    inet_pton(AF_INET, cfg->remote_ip, &remote.sin_addr);
    static const char request[] = "IPSEC-LIFECYCLE-READY?";
    static const char response[] = "IPSEC-LIFECYCLE-READY!";
    time_t deadline = time(NULL) + cfg->timeout_sec;
    set_timeout(fd, 1);

    while (time(NULL) <= deadline) {
        (void)sendto(fd, request, sizeof(request) - 1U, 0,
                     (struct sockaddr *)&remote, sizeof(remote));
        char buffer[128];
        ssize_t n = recvfrom(fd, buffer, sizeof(buffer) - 1U, 0, NULL, NULL);
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, response) == 0) {
                if (log) fprintf(log, "initiator barrier acknowledged after post-test snapshots\n");
                close(fd);
                if (log) fclose(log);
                log_pass("peer lifecycle barrier completed after post-test snapshots");
                return 0;
            }
        }
    }

    log_error("lifecycle barrier did not complete within %d seconds", cfg->timeout_sec);
    close(fd);
    if (log) fclose(log);
    return -1;
}

int udp_lifecycle_barrier(const app_config_t *cfg, const char *result_dir)
{
    return cfg->role == ROLE_INITIATOR ?
        lifecycle_barrier_initiator(cfg, result_dir) :
        lifecycle_barrier_responder(cfg, result_dir);
}

static FILE *open_matrix_barrier_log(const char *result_dir, const char *phase)
{
    char file[256];
    snprintf(file, sizeof(file), "matrix_barrier_%s.txt", phase);
    char path[1024];
    join_path(path, sizeof(path), result_dir, file);
    return fopen(path, "w");
}

static int matrix_barrier_responder(const app_config_t *cfg, const char *result_dir,
                                    const char *case_id, const char *phase)
{
    FILE *log = open_matrix_barrier_log(result_dir, phase);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (log) fclose(log);
        return -1;
    }
    set_timeout(fd, cfg->timeout_sec);

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = htons((uint16_t)cfg->matrix_control_port);
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("matrix barrier UDP bind %s:%d failed: %s",
                  cfg->local_ip, cfg->matrix_control_port, strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }

    char expected[320];
    char response[320];
    snprintf(expected, sizeof(expected), "IPSEC-MATRIX-%s? %s", phase, case_id);
    snprintf(response, sizeof(response), "IPSEC-MATRIX-%s! %s", phase, case_id);

    time_t deadline = time(NULL) + cfg->timeout_sec;
    while (time(NULL) <= deadline) {
        char buffer[320];
        struct sockaddr_in peer;
        socklen_t peer_len = sizeof(peer);
        ssize_t n = recvfrom(fd, buffer, sizeof(buffer) - 1U, 0,
                             (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            if (errno == EINTR) continue;
            log_error("matrix barrier receive failed for %s/%s: %s", case_id, phase, strerror(errno));
            close(fd);
            if (log) fclose(log);
            return -1;
        }
        buffer[n] = '\0';
        if (strcmp(buffer, expected) != 0) {
            if (log) fprintf(log, "ignored unexpected request: %s\n", buffer);
            continue;
        }
        ssize_t sent = sendto(fd, response, strlen(response), 0,
                              (struct sockaddr *)&peer, peer_len);
        if (sent != (ssize_t)strlen(response)) {
            log_error("matrix barrier response send failed for %s/%s: %s", case_id, phase, strerror(errno));
            close(fd);
            if (log) fclose(log);
            return -1;
        }
        if (log) fprintf(log, "responder barrier acknowledged for %s/%s\n", case_id, phase);
        close(fd);
        if (log) fclose(log);
        log_pass("matrix testcase %s: peer synchronization phase %s completed", case_id, phase);
        return 0;
    }

    log_error("matrix barrier timed out for %s/%s", case_id, phase);
    close(fd);
    if (log) fclose(log);
    return -1;
}

static int matrix_barrier_initiator(const app_config_t *cfg, const char *result_dir,
                                    const char *case_id, const char *phase)
{
    FILE *log = open_matrix_barrier_log(result_dir, phase);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        if (log) fclose(log);
        return -1;
    }

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    inet_pton(AF_INET, cfg->local_ip, &local.sin_addr);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) {
        log_error("matrix barrier source bind %s failed: %s", cfg->local_ip, strerror(errno));
        close(fd);
        if (log) fclose(log);
        return -1;
    }

    struct sockaddr_in remote = {0};
    remote.sin_family = AF_INET;
    remote.sin_port = htons((uint16_t)cfg->matrix_control_port);
    inet_pton(AF_INET, cfg->remote_ip, &remote.sin_addr);

    char request[320];
    char expected[320];
    snprintf(request, sizeof(request), "IPSEC-MATRIX-%s? %s", phase, case_id);
    snprintf(expected, sizeof(expected), "IPSEC-MATRIX-%s! %s", phase, case_id);

    time_t deadline = time(NULL) + cfg->timeout_sec;
    set_timeout(fd, 1);
    while (time(NULL) <= deadline) {
        (void)sendto(fd, request, strlen(request), 0,
                     (struct sockaddr *)&remote, sizeof(remote));
        char buffer[320];
        ssize_t n = recvfrom(fd, buffer, sizeof(buffer) - 1U, 0, NULL, NULL);
        if (n > 0) {
            buffer[n] = '\0';
            if (strcmp(buffer, expected) == 0) {
                if (log) fprintf(log, "initiator barrier acknowledged for %s/%s\n", case_id, phase);
                close(fd);
                if (log) fclose(log);
                log_pass("matrix testcase %s: peer synchronization phase %s completed", case_id, phase);
                return 0;
            }
        }
    }

    log_error("matrix barrier did not complete for %s/%s within %d seconds",
              case_id, phase, cfg->timeout_sec);
    close(fd);
    if (log) fclose(log);
    return -1;
}

int udp_matrix_phase_barrier(const app_config_t *cfg, const char *result_dir,
                             const char *case_id, const char *phase)
{
    return cfg->role == ROLE_INITIATOR ?
        matrix_barrier_initiator(cfg, result_dir, case_id, phase) :
        matrix_barrier_responder(cfg, result_dir, case_id, phase);
}

int udp_matrix_ready_barrier(const app_config_t *cfg, const char *result_dir,
                             const char *case_id)
{
    return udp_matrix_phase_barrier(cfg, result_dir, case_id, "CONFIG_READY");
}
