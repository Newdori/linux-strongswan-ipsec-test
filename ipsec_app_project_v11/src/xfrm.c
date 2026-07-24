#define _POSIX_C_SOURCE 200809L
#include "xfrm.h"
#include "logger.h"
#include "process.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static long long sum_before_marker(const char *text, const char *marker)
{
    long long total = 0;
    const char *cursor = text;
    while (cursor && *cursor) {
        const char *hit = strstr(cursor, marker);
        if (!hit) break;
        const char *end = hit;
        while (end > text && isspace((unsigned char)end[-1])) --end;
        const char *start = end;
        while (start > text && isdigit((unsigned char)start[-1])) --start;
        if (start < end) {
            char number[64];
            size_t n = (size_t)(end - start);
            if (n < sizeof(number)) {
                memcpy(number, start, n);
                number[n] = '\0';
                total += strtoll(number, NULL, 10);
            }
        }
        cursor = hit + strlen(marker);
    }
    return total;
}

static long long sum_xfrm_errors(const char *text)
{
    long long total = 0;
    char *copy = strdup(text ? text : "");
    if (!copy) return 0;
    char *save = NULL;
    for (char *line = strtok_r(copy, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char name[128];
        long long value;
        if (sscanf(line, "%127s %lld", name, &value) == 2) total += value;
    }
    free(copy);
    return total;
}

static bool text_has_reqid(const char *text, unsigned int reqid)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "reqid %u", reqid);
    size_t len = strlen(needle);
    const char *p = text ? text : "";
    while ((p = strstr(p, needle)) != NULL) {
        char next = p[len];
        if (next < '0' || next > '9') return true;
        p += len;
    }
    return false;
}

static void sum_state_block_for_reqid(const char *block, unsigned int reqid,
                                      long long *packets, long long *bytes)
{
    if (!block || !text_has_reqid(block, reqid)) return;
    *packets += sum_before_marker(block, "(packets)");
    *bytes += sum_before_marker(block, "(bytes)");
}

static void sum_reqid_counters(const char *text, unsigned int reqid,
                               long long *packets, long long *bytes)
{
    *packets = 0;
    *bytes = 0;
    if (!text || !*text) return;

    const char *block_start = text;
    const char *cursor = text;
    while (*cursor) {
        const char *next = strstr(cursor + 1, "\nsrc ");
        if (!next) {
            sum_state_block_for_reqid(block_start, reqid, packets, bytes);
            break;
        }

        size_t len = (size_t)(next - block_start + 1);
        char *block = malloc(len + 1U);
        if (!block) return;
        memcpy(block, block_start, len);
        block[len] = '\0';
        sum_state_block_for_reqid(block, reqid, packets, bytes);
        free(block);

        block_start = next + 1;
        cursor = block_start;
    }
}

static int save_snapshot_files(const char *result_dir, const char *phase,
                               const char *state)
{
    char file[128];
    char path[1024];
    snprintf(file, sizeof(file), "xfrm_state_%s.txt", phase);
    join_path(path, sizeof(path), result_dir, file);
    return write_text_file(path, state ? state : "", 0640);
}

static int take_snapshot_common(const app_config_t *cfg, const char *result_dir,
                                const char *phase, bool scoped_to_reqid,
                                unsigned int reqid, xfrm_snapshot_t *snapshot)
{
    (void)cfg;
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->scoped_to_reqid = scoped_to_reqid;
    snapshot->reqid = scoped_to_reqid ? reqid : 0U;

    char *state_argv[] = {"ip", "-d", "-s", "xfrm", "state", NULL};
    char *state = NULL;
    int rc = process_run(state_argv, &state);
    (void)save_snapshot_files(result_dir, phase, state);

    if (scoped_to_reqid) {
        sum_reqid_counters(state ? state : "", reqid, &snapshot->packets, &snapshot->bytes);
    } else {
        snapshot->packets = sum_before_marker(state ? state : "", "(packets)");
        snapshot->bytes = sum_before_marker(state ? state : "", "(bytes)");
    }
    free(state);

    char file[128];
    char path[1024];
    char *policy_argv[] = {"ip", "-d", "-s", "xfrm", "policy", NULL};
    snprintf(file, sizeof(file), "xfrm_policy_%s.txt", phase);
    join_path(path, sizeof(path), result_dir, file);
    (void)process_run_to_file(policy_argv, path);

    char *stat_argv[] = {"cat", "/proc/net/xfrm_stat", NULL};
    char *stats = NULL;
    (void)process_run(stat_argv, &stats);
    snprintf(file, sizeof(file), "xfrm_stat_%s.txt", phase);
    join_path(path, sizeof(path), result_dir, file);
    (void)write_text_file(path, stats ? stats : "", 0640);
    snapshot->error_total = sum_xfrm_errors(stats ? stats : "");
    free(stats);

    if (scoped_to_reqid) {
        log_info("XFRM %s: reqid=%u packets=%lld bytes=%lld error_total=%lld",
                 phase, reqid, snapshot->packets, snapshot->bytes, snapshot->error_total);
    } else {
        log_info("XFRM %s: all-states packets=%lld bytes=%lld error_total=%lld",
                 phase, snapshot->packets, snapshot->bytes, snapshot->error_total);
    }
    return rc;
}

int xfrm_take_snapshot(const app_config_t *cfg, const char *result_dir,
                       const char *phase, xfrm_snapshot_t *snapshot)
{
    return take_snapshot_common(cfg, result_dir, phase, false, 0U, snapshot);
}

int xfrm_take_snapshot_for_reqid(const app_config_t *cfg, const char *result_dir,
                                 const char *phase, unsigned int reqid,
                                 xfrm_snapshot_t *snapshot)
{
    return take_snapshot_common(cfg, result_dir, phase, true, reqid, snapshot);
}

bool xfrm_counters_increased(const xfrm_snapshot_t *before, const xfrm_snapshot_t *after)
{
    return after->packets > before->packets && after->bytes > before->bytes;
}

static int save_cleanup_xfrm(const char *result_dir, const char *phase,
                             const char *kind, const char *text)
{
    char file[192], path[1024];
    snprintf(file, sizeof(file), "xfrm_cleanup_%s_%s.txt", phase, kind);
    join_path(path, sizeof(path), result_dir, file);
    return write_text_file(path, text ? text : "", 0640);
}

int xfrm_wait_for_reqid_absent(const app_config_t *cfg, const char *result_dir,
                               const char *phase, unsigned int reqid, int timeout_sec)
{
    (void)cfg;
    time_t deadline = time(NULL) + timeout_sec;
    char *last_state = NULL;
    char *last_policy = NULL;

    while (time(NULL) <= deadline) {
        free(last_state);
        free(last_policy);
        last_state = NULL;
        last_policy = NULL;

        char *state_argv[] = {"ip", "-d", "xfrm", "state", NULL};
        char *policy_argv[] = {"ip", "-d", "xfrm", "policy", NULL};
        int state_rc = process_run(state_argv, &last_state);
        int policy_rc = process_run(policy_argv, &last_policy);
        if (state_rc != 0 || policy_rc != 0) {
            save_cleanup_xfrm(result_dir, phase, "state_error", last_state);
            save_cleanup_xfrm(result_dir, phase, "policy_error", last_policy);
            free(last_state);
            free(last_policy);
            log_error("failed to query XFRM while verifying reqid %u removal", reqid);
            return -1;
        }

        if (!text_has_reqid(last_state, reqid) && !text_has_reqid(last_policy, reqid)) {
            save_cleanup_xfrm(result_dir, phase, "state_absent", last_state);
            save_cleanup_xfrm(result_dir, phase, "policy_absent", last_policy);
            free(last_state);
            free(last_policy);
            log_pass("XFRM state/policy removal confirmed for reqid %u (%s cleanup)",
                     reqid, phase);
            return 0;
        }

        struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000L};
        nanosleep(&delay, NULL);
    }

    save_cleanup_xfrm(result_dir, phase, "state_timeout", last_state);
    save_cleanup_xfrm(result_dir, phase, "policy_timeout", last_policy);
    free(last_state);
    free(last_policy);
    log_error("XFRM entries for reqid %u still present after %d seconds (%s cleanup)",
              reqid, timeout_sec, phase);
    return -1;
}
