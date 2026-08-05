#define _POSIX_C_SOURCE 200809L
#include "strongswan.h"
#include "logger.h"
#include "process.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define PSK_MAX 1024
#define SWANCTL_ARGV_MAX 24
#define SWANCTL_RUNTIME_DIR "/etc/swanctl"

static int save_output(const char *result_dir, const char *file, const char *text);

static int run_swanctl(const app_config_t *cfg,
                       const char *const args[], size_t arg_count,
                       char **out)
{
    char *argv[SWANCTL_ARGV_MAX];
    size_t n = 0;

    argv[n++] = "swanctl";
    for (size_t i = 0; i < arg_count; ++i) {
        if (n + 3 >= SWANCTL_ARGV_MAX) {
            if (out) *out = strdup("too many swanctl arguments\n");
            return -1;
        }
        argv[n++] = (char *)args[i];
    }
    if (cfg->vici_uri[0]) {
        argv[n++] = "--uri";
        argv[n++] = (char *)cfg->vici_uri;
    }
    argv[n] = NULL;
    return process_run(argv, out);
}


static void save_runtime_diagnostics(const app_config_t *cfg, const char *result_dir)
{
    char *out = NULL;

    const char *version_args[] = {"--version"};
    if (run_swanctl(cfg, version_args, 1, &out) == 0) {
        save_output(result_dir, "swanctl_version.txt", out);
    } else {
        save_output(result_dir, "swanctl_version.txt", out ? out : "");
    }
    free(out);
    out = NULL;

    /* Supported by the target 5.x swanctl builds in normal distributions.
     * Failure is diagnostic-only because this is a cross-version test. */
    const char *daemon_args[] = {"--version", "--daemon"};
    int daemon_rc = run_swanctl(cfg, daemon_args, 2, &out);
    save_output(result_dir, "charon_daemon_version.txt", out ? out : "");
    if (daemon_rc != 0) {
        log_warn("unable to query charon daemon version; continuing: %s",
                 out ? out : "");
    }
    free(out);
    out = NULL;

    const char *algs_args[] = {"--list-algs"};
    int algs_rc = run_swanctl(cfg, algs_args, 1, &out);
    save_output(result_dir, "swanctl_list_algs.txt", out ? out : "");
    if (algs_rc != 0) {
        log_warn("unable to query loaded strongSwan algorithms; continuing: %s",
                 out ? out : "");
    }
    free(out);
    out = NULL;

    /* Record VICI sockets from both common runtime paths.  PetaLinux often
     * exposes /var/run while desktop distributions commonly use /run. */
    char sockets[8192];
    size_t used = 0;
    sockets[0] = '\0';
    const char *runtime_dirs[] = {"/run", "/var/run", NULL};
    for (size_t i = 0; runtime_dirs[i]; ++i) {
        DIR *dir = opendir(runtime_dirs[i]);
        if (!dir) continue;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strstr(ent->d_name, "charon") && strstr(ent->d_name, ".vici")) {
                int n = snprintf(sockets + used, sizeof(sockets) - used,
                                 "%s/%s\n", runtime_dirs[i], ent->d_name);
                if (n < 0 || (size_t)n >= sizeof(sockets) - used) {
                    used = sizeof(sockets) - 1U;
                    break;
                }
                used += (size_t)n;
            }
        }
        closedir(dir);
        if (used >= sizeof(sockets) - 1U) break;
    }
    if (used == 0) {
        snprintf(sockets, sizeof(sockets),
                 "<no charon*.vici entries found under /run or /var/run>\n");
    }
    save_output(result_dir, "vici_sockets.txt", sockets);

    char target[1024];
    snprintf(target, sizeof(target),
             "configured_vici_uri=%s\n"
             "service_control=ipsec start/stop/restart\n"
             "common_vici_paths=/run/charon.vici,/var/run/charon.vici\n",
             cfg->vici_uri[0] ? cfg->vici_uri : "<swanctl default>");
    save_output(result_dir, "vici_target.txt", target);
}

static int read_psk(const char *path, char psk[PSK_MAX])
{
    struct stat st;
    if (stat(path, &st) != 0) {
        log_error("cannot stat PSK file %s: %s", path, strerror(errno));
        return -1;
    }
    if ((st.st_mode & 0077) != 0) {
        log_error("PSK file must have mode 600: chmod 600 %s", path);
        return -1;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    if (!fgets(psk, PSK_MAX, fp)) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    psk[strcspn(psk, "\r\n")] = '\0';
    if (strlen(psk) < 32) {
        log_error("PSK must contain at least 32 characters");
        return -1;
    }
    for (const unsigned char *p = (const unsigned char *)psk; *p; ++p) {
        if (*p < 0x21 || *p > 0x7e || strchr("\\\"{}#", *p)) {
            log_error("PSK contains a character unsafe for generated swanctl configuration");
            return -1;
        }
    }
    return 0;
}

static int save_output(const char *result_dir, const char *file, const char *text)
{
    char path[1024];
    join_path(path, sizeof(path), result_dir, file);
    return write_text_file(path, text ? text : "", 0640);
}

/* swanctl --list-conns output has changed slightly between strongSwan
 * releases.  Do not rely on a particular indentation layout.  We only require
 * that a configuration label appears as a token followed by ':'. */
static int output_has_config_label(const char *text, const char *name)
{
    if (!text || !name || !*name) return 0;

    size_t name_len = strlen(name);
    const char *p = text;
    while ((p = strstr(p, name)) != NULL) {
        int left_ok = (p == text) || p[-1] == '\n' || p[-1] == '\r' ||
                      p[-1] == ' ' || p[-1] == '\t' || p[-1] == '{' ||
                      p[-1] == '[' || p[-1] == '\'' || p[-1] == '"';
        char right = p[name_len];
        int right_ok = right == ':' || right == '\'' || right == '"' ||
                       right == ' ' || right == '\t' || right == '=' ||
                       right == '{' || right == '[';
        if (left_ok && right_ok) return 1;
        p += name_len;
    }
    return 0;
}

static int verify_loaded_connection(const app_config_t *cfg, const char *result_dir)
{
    const char *args[] = {"--list-conns"};
    char *out = NULL;
    int rc = run_swanctl(cfg, args, 1, &out);
    save_output(result_dir, "list_connections.txt", out);

    if (rc != 0) {
        log_error("unable to list loaded strongSwan connections: %s",
                  out ? out : "");
        free(out);
        return -1;
    }

    if (!output_has_config_label(out, cfg->connection_name)) {
        log_error("IKE config '%s' is not present after swanctl --load-conns; "
                  "see load_connections.txt and list_connections.txt",
                  cfg->connection_name);
        free(out);
        return -1;
    }

    if (!output_has_config_label(out, cfg->child_name)) {
        /* Older/custom swanctl builds may format the VICI list-conns response
         * differently.  load-conns is authoritative for syntax acceptance and
         * --initiate is authoritative for CHILD lookup, so don't abort here. */
        log_warn("could not confirm CHILD_SA config '%s' in formatted "
                 "swanctl --list-conns output; continuing and letting charon "
                 "validate it during initiation. See list_connections.txt",
                 cfg->child_name);
        free(out);
        return 1;
    }

    log_pass("loaded IKE config '%s' and CHILD_SA config '%s' are visible",
             cfg->connection_name, cfg->child_name);
    free(out);
    return 0;
}

static int wait_for_vici(const app_config_t *cfg, int attempts,
                         long delay_ns, char **last_output)
{
    const char *stats_args[] = {"--stats"};
    char *out = NULL;
    int rc = -1;

    for (int attempt = 1; attempt <= attempts; ++attempt) {
        free(out);
        out = NULL;
        rc = run_swanctl(cfg, stats_args, 1, &out);
        if (rc == 0) {
            if (last_output) *last_output = out;
            else free(out);
            return 0;
        }
        if (attempt < attempts) {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = delay_ns};
            while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
                /* Continue sleeping for the remaining interval. */
            }
        }
    }

    if (last_output) *last_output = out;
    else free(out);
    return rc;
}

int strongswan_ensure_ready(const app_config_t *cfg, const char *result_dir)
{
    char *out = NULL;

    /* First try the already-running daemon.  This avoids restarting charon
     * during a two-peer test when PetaLinux boot scripts already started it. */
    int rc = wait_for_vici(cfg, 1, 0, &out);
    save_output(result_dir, "swanctl_stats_initial.txt", out ? out : "");
    free(out);
    out = NULL;

    if (rc != 0) {
        log_info("VICI/charon is not ready; starting strongSwan with 'ipsec start'");
        char *start[] = {"ipsec", "start", NULL};
        int start_rc = process_run(start, &out);
        save_output(result_dir, "service_start.txt", out ? out : "");
        if (start_rc != 0) {
            /* Some starter implementations return non-zero when charon is
             * already starting.  The VICI readiness check below is decisive. */
            log_warn("'ipsec start' returned rc=%d; waiting for VICI: %s",
                     start_rc, out ? out : "");
        }
        free(out);
        out = NULL;
    }

    /* PetaLinux/embedded storage can make daemon startup slower than a desktop
     * system.  Wait up to ten seconds for the VICI socket and plugin. */
    rc = wait_for_vici(cfg, 20, 500000000L, &out);
    save_output(result_dir, "swanctl_stats.txt", out ? out : "");
    if (rc != 0) {
        log_error("VICI/charon is not ready after 'ipsec start': %s",
                  out ? out : "");
        free(out);
        return -1;
    }
    free(out);

    save_runtime_diagnostics(cfg, result_dir);

    /* A successful swanctl --stats call using cfg->vici_uri proves that the
     * configured VICI endpoint is reachable; no systemd state is required. */
    log_pass("strongSwan charon/VICI are ready (service control: ipsec)");
    return 0;
}

int strongswan_load_configuration(const app_config_t *cfg, const char *result_dir)
{
    char psk[PSK_MAX];
    char conn_path[1024];
    char cred_path[1024];
    char saved_conn_path[1024];
    int rc = -1;
    char *out = NULL;

    if (read_psk(cfg->psk_file, psk) != 0) return -1;

    /*
     * Do not put custom swanctl input under /run.  Ubuntu packages ship an
     * AppArmor profile for /usr/sbin/swanctl and arbitrary /run paths may be
     * unreadable even when ipsec_app itself (running as root) created them.
     * Keep the transient input in swanctl's normal configuration directory,
     * which also works with strongSwan 5.8.x/5.9.x custom --file loading.
     */
    snprintf(conn_path, sizeof(conn_path),
             SWANCTL_RUNTIME_DIR "/ipsec-app-%ld-conns.conf", (long)getpid());
    snprintf(cred_path, sizeof(cred_path),
             SWANCTL_RUNTIME_DIR "/ipsec-app-%ld-creds.conf", (long)getpid());
    join_path(saved_conn_path, sizeof(saved_conn_path), result_dir, "generated_connections.conf");

    {
        struct stat swanctl_dir_st;
        if (stat(SWANCTL_RUNTIME_DIR, &swanctl_dir_st) != 0) {
            if (errno != ENOENT || mkdir_recursive(SWANCTL_RUNTIME_DIR, 0750) != 0) {
                log_error("cannot create %s: %s", SWANCTL_RUNTIME_DIR,
                          strerror(errno));
                goto cleanup;
            }
            if (stat(SWANCTL_RUNTIME_DIR, &swanctl_dir_st) != 0) {
                log_error("cannot stat %s after creation: %s",
                          SWANCTL_RUNTIME_DIR, strerror(errno));
                goto cleanup;
            }
        }
        if (!S_ISDIR(swanctl_dir_st.st_mode)) {
            log_error("%s exists but is not a directory", SWANCTL_RUNTIME_DIR);
            goto cleanup;
        }
    }

    /* Keep the connection file free of secrets.  This is intentionally split
     * from the credential file because older swanctl releases are most
     * predictable when --load-conns and --load-creds each receive only the
     * section they are supposed to load. */
    FILE *fp = fopen(conn_path, "w");
    if (!fp) {
        log_error("cannot create temporary connection config %s: %s", conn_path, strerror(errno));
        goto cleanup;
    }
    if (chmod(conn_path, 0600) != 0) {
        log_error("chmod(%s) failed: %s", conn_path, strerror(errno));
        fclose(fp);
        goto cleanup;
    }
    fprintf(fp,
        "connections {\n"
        "  %s {\n"
        "    version = 2\n"
        "    local_addrs = %s\n"
        "    remote_addrs = %s\n"
        "    proposals = %s\n"
        "    mobike = no\n"
        "    fragmentation = yes\n"
        "    childless = %s\n"
        "    local {\n"
        "      auth = psk\n"
        "      id = %s\n"
        "    }\n"
        "    remote {\n"
        "      auth = psk\n"
        "      id = %s\n"
        "    }\n"
        "    children {\n"
        "      %s {\n"
        "        local_ts = %s/32\n"
        "        remote_ts = %s/32\n"
        "        mode = %s\n"
        "        esp_proposals = %s\n"
        "        start_action = none\n"
        "        close_action = none\n"
        "        dpd_action = clear\n"
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
        cfg->connection_name, cfg->local_ip, cfg->remote_ip, cfg->ike_proposals,
        cfg->childless_ike ? "force" : "allow",
        cfg->local_id, cfg->remote_id, cfg->child_name,
        cfg->local_ip, cfg->remote_ip, cfg->ipsec_mode, cfg->esp_proposals);
    if (fclose(fp) != 0) {
        log_error("failed to finalize temporary connection config");
        goto cleanup;
    }

    /* Save an exact, non-secret copy for diagnostics. */
    {
        FILE *src = fopen(conn_path, "r");
        FILE *dst = fopen(saved_conn_path, "w");
        if (src && dst) {
            char buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                if (fwrite(buf, 1, n, dst) != n) break;
            }
            chmod(saved_conn_path, 0640);
        }
        if (src) fclose(src);
        if (dst) fclose(dst);
    }

    fp = fopen(cred_path, "w");
    if (!fp) {
        log_error("cannot create temporary credential config %s: %s", cred_path, strerror(errno));
        goto cleanup;
    }
    if (chmod(cred_path, 0600) != 0) {
        log_error("chmod(%s) failed: %s", cred_path, strerror(errno));
        fclose(fp);
        goto cleanup;
    }
    fprintf(fp,
        "secrets {\n"
        "  ike-ipsec-app {\n"
        "    id-local = %s\n"
        "    id-remote = %s\n"
        "    secret = \"%s\"\n"
        "  }\n"
        "}\n",
        cfg->local_id, cfg->remote_id, psk);
    if (fclose(fp) != 0) {
        log_error("failed to finalize temporary credential config");
        goto cleanup;
    }

    /* Record which daemon/socket this run targets. */
    {
        char context[4096];
        snprintf(context, sizeof(context),
                 "service_control=ipsec\nlegacy_service_name=%s\nVICI URI=%s\nconnection_file=%s\nruntime_config_dir=%s\n"
                 "ike_proposals=%s\nesp_proposals=%s\nipsec_mode=%s\nchildless_ike=%s\n"
                 "credential_file=<temporary secret file deleted after load>\n",
                 cfg->service_name,
                 cfg->vici_uri[0] ? cfg->vici_uri : "<swanctl default>",
                 saved_conn_path, SWANCTL_RUNTIME_DIR, cfg->ike_proposals,
                 cfg->esp_proposals, cfg->ipsec_mode,
                 cfg->childless_ike ? "force" : "allow");
        save_output(result_dir, "strongswan_context.txt", context);
    }

    /* Prove the file exists and is readable before exec'ing swanctl. */
    {
        struct stat st;
        char diag[2048];
        if (stat(conn_path, &st) != 0) {
            log_error("temporary connection config disappeared before swanctl: %s",
                      strerror(errno));
            goto cleanup;
        }
        snprintf(diag, sizeof(diag),
                 "path=%s\nuid=%ld\ngid=%ld\nmode=%04o\nsize=%lld\naccess_R_OK=%s\n",
                 conn_path, (long)st.st_uid, (long)st.st_gid,
                 (unsigned)(st.st_mode & 07777), (long long)st.st_size,
                 access(conn_path, R_OK) == 0 ? "yes" : "no");
        save_output(result_dir, "runtime_connection_file_stat.txt", diag);
    }

    const char *load_conns_args[] = {"--load-conns", "--file", conn_path};
    rc = run_swanctl(cfg, load_conns_args, 3, &out);
    save_output(result_dir, "load_connections.txt", out);
    if (rc != 0 || !out || strstr(out, "failed to open config file") ||
        strstr(out, "no connections found")) {
        log_error("swanctl --load-conns did not load the connection (rc=%d): %s",
                  rc, out ? out : "");

        if (command_exists("journalctl")) {
            char *aa_out = NULL;
            char *aa_argv[] = {"journalctl", "-k", "--since=-3min",
                               "--no-pager", NULL};
            (void)process_run(aa_argv, &aa_out);
            save_output(result_dir, "kernel_security_log.txt", aa_out ? aa_out : "");
            free(aa_out);
        }

        free(out);
        out = NULL;
        rc = -1;
        goto cleanup;
    }
    log_info("swanctl --load-conns output: %s", out && *out ? out : "<empty>");
    free(out);
    out = NULL;

    if (verify_loaded_connection(cfg, result_dir) < 0) {
        log_error("connection load verification failed. Run the exact non-secret file manually with:\n"
                  "  sudo swanctl --load-conns --file %s%s%s",
                  saved_conn_path,
                  cfg->vici_uri[0] ? " --uri " : "",
                  cfg->vici_uri[0] ? cfg->vici_uri : "");
        rc = -1;
        goto cleanup;
    }

    const char *load_creds_args[] = {"--load-creds", "--file", cred_path};
    rc = run_swanctl(cfg, load_creds_args, 3, &out);
    save_output(result_dir, "load_credentials.txt", out);
    if (rc != 0) {
        log_error("swanctl --load-creds failed (rc=%d): %s", rc, out ? out : "");
        free(out);
        out = NULL;
        rc = -1;
        goto cleanup;
    }
    free(out);
    out = NULL;

    log_pass("IPsec connection and PSK loaded by application");
    rc = 0;

cleanup:
    memset(psk, 0, sizeof(psk));
    if (out) free(out);
    unlink(conn_path);
    unlink(cred_path);
    return rc;
}

int strongswan_initiate_child(const app_config_t *cfg, const char *result_dir)
{
    char timeout[32];
    snprintf(timeout, sizeof(timeout), "%d", cfg->timeout_sec);
    const char *args[] = {
        "--initiate",
        "--child", cfg->child_name,
        "--timeout", timeout
    };
    char *out = NULL;
    int rc = run_swanctl(cfg, args, 5, &out);
    save_output(result_dir, cfg->childless_ike ? "initiate_child.txt" : "initiate.txt", out);
    if (rc != 0) {
        log_error("CHILD_SA initiation failed: %s", out ? out : "");
        log_error("requested parent IKE='%s', CHILD='%s'; see list_connections.txt",
                  cfg->connection_name, cfg->child_name);
        free(out);
        return -1;
    }
    log_pass("CHILD SA initiation completed");
    free(out);
    return 0;
}

int strongswan_initiate(const app_config_t *cfg, const char *result_dir)
{
    return strongswan_initiate_child(cfg, result_dir);
}

int strongswan_initiate_ike_only(const app_config_t *cfg, const char *result_dir)
{
    char timeout[32];
    snprintf(timeout, sizeof(timeout), "%d", cfg->timeout_sec);
    const char *args[] = {
        "--initiate",
        "--ike", cfg->connection_name,
        "--timeout", timeout
    };
    char *out = NULL;
    int rc = run_swanctl(cfg, args, 5, &out);
    save_output(result_dir, "initiate_ike_only.txt", out);
    if (rc != 0) {
        log_error("childless IKE_SA initiation failed: %s", out ? out : "");
        free(out);
        return -1;
    }
    log_pass("childless IKE SA initiation completed");
    free(out);
    return 0;
}

static int line_contains_token(const char *start, const char *end, const char *token)
{
    size_t token_len = strlen(token);
    if (!start || !end || !token || token_len == 0 || end < start) return 0;
    for (const char *p = start; p + token_len <= end; ++p) {
        if (memcmp(p, token, token_len) == 0) return 1;
    }
    return 0;
}

static void parse_reqid(const char *start, const char *end, strongswan_sa_info_t *info)
{
    const char needle[] = "reqid ";
    size_t needle_len = sizeof(needle) - 1U;
    for (const char *p = start; p + needle_len < end; ++p) {
        if (memcmp(p, needle, needle_len) != 0) continue;
        p += needle_len;
        if (p >= end || *p < '0' || *p > '9') return;
        unsigned long value = 0;
        while (p < end && *p >= '0' && *p <= '9') {
            value = value * 10UL + (unsigned long)(*p - '0');
            if (value > 0xffffffffUL) return;
            ++p;
        }
        info->reqid = (unsigned int)value;
        info->reqid_valid = true;
        return;
    }
}


static void parse_child_algorithms(const char *start, const char *end,
                                   strongswan_sa_info_t *info)
{
    const char *esp = NULL;
    for (const char *p = start; p + 4 <= end; ++p) {
        if (memcmp(p, "ESP:", 4) == 0) {
            esp = p + 4;
            break;
        }
    }
    if (!esp) return;
    const char *stop = esp;
    while (stop < end && *stop != ' ' && *stop != '\t' && *stop != '\r') ++stop;
    size_t len = (size_t)(stop - esp);
    if (len >= sizeof(info->child_algorithms)) len = sizeof(info->child_algorithms) - 1U;
    memcpy(info->child_algorithms, esp, len);
    info->child_algorithms[len] = '\0';
}

/* Parse unfiltered --list-sas output.  This is deliberately used instead of
 * --list-sas --child because CHILD filtering was added after strongSwan 5.8.4.
 * An IKE SA starts at column 0 and its CHILD SAs are indented below it. */
static void scan_target_sa(const char *text,
                           const char *connection_name,
                           const char *child_name,
                           strongswan_sa_info_t *info)
{
    memset(info, 0, sizeof(*info));
    if (!text || !connection_name || !*connection_name || !child_name || !*child_name) return;

    size_t conn_len = strlen(connection_name);
    size_t child_len = strlen(child_name);
    const char *line = text;
    int in_connection = 0;
    int ike_established = 0;

    while (*line) {
        const char *end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        const char *p = line;
        size_t indent = 0;
        while (p < end && (*p == ' ' || *p == '\t')) {
            ++indent;
            ++p;
        }

        if (indent == 0) {
            in_connection = ((size_t)(end - p) > conn_len &&
                             strncmp(p, connection_name, conn_len) == 0 &&
                             p[conn_len] == ':');
            ike_established = in_connection && line_contains_token(p, end, "ESTABLISHED");
            if (in_connection) {
                info->ike_present = true;
                info->ike_established = ike_established != 0;
            }
        } else if (in_connection && (size_t)(end - p) > child_len &&
                   strncmp(p, child_name, child_len) == 0 && p[child_len] == ':') {
            info->child_present = true;
            parse_reqid(p, end, info);
            parse_child_algorithms(p, end, info);
            if (ike_established && line_contains_token(p, end, "INSTALLED")) info->ready = true;
        }

        line = *end ? end + 1 : end;
    }
}

static int list_target_sa(const app_config_t *cfg, const char *result_dir,
                          const char *file, strongswan_sa_info_t *info, char **text_out)
{
    const char *args[] = {"--list-sas"};
    char *out = NULL;
    int rc = run_swanctl(cfg, args, 1, &out);
    if (file) save_output(result_dir, file, out ? out : "");
    if (rc == 0) scan_target_sa(out, cfg->connection_name, cfg->child_name, info);
    else memset(info, 0, sizeof(*info));

    if (text_out) *text_out = out;
    else free(out);
    return rc;
}

int strongswan_get_sa_info(const app_config_t *cfg, const char *result_dir,
                           const char *phase, strongswan_sa_info_t *info)
{
    char file[160];
    snprintf(file, sizeof(file), "sa_info_%s.txt", phase);
    int rc = list_target_sa(cfg, result_dir, file, info, NULL);
    if (rc != 0) {
        log_error("unable to inspect IKE/CHILD SA state for phase '%s'", phase);
        return -1;
    }
    log_info("SA %s: ike=%s established=%s child=%s ready=%s reqid=%s%u algorithms=%s", phase,
             info->ike_present ? "yes" : "no",
             info->ike_established ? "yes" : "no",
             info->child_present ? "yes" : "no",
             info->ready ? "yes" : "no",
             info->reqid_valid ? "" : "n/a ",
             info->reqid_valid ? info->reqid : 0U,
             info->child_algorithms[0] ? info->child_algorithms : "<none>");
    return 0;
}


int strongswan_wait_for_ike(const app_config_t *cfg, const char *result_dir)
{
    time_t deadline = time(NULL) + cfg->timeout_sec;
    char *last = NULL;
    strongswan_sa_info_t info;

    while (time(NULL) <= deadline) {
        free(last);
        last = NULL;
        int rc = list_target_sa(cfg, result_dir, NULL, &info, &last);
        if (rc == 0 && info.ike_established) {
            save_output(result_dir, "ike_ready_childless.txt", last ? last : "");
            if (info.child_present) {
                log_error("IKE SA is established but CHILD '%s' already exists; childless PFS precondition failed",
                          cfg->child_name);
                free(last);
                return -1;
            }
            log_pass("IKE SA ESTABLISHED without CHILD SA (childless precondition confirmed)");
            free(last);
            return 0;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000L};
        nanosleep(&delay, NULL);
    }

    save_output(result_dir, "ike_wait_timeout.txt", last ? last : "");
    log_error("childless IKE SA '%s' was not established within %d seconds",
              cfg->connection_name, cfg->timeout_sec);
    free(last);
    return -1;
}

bool strongswan_sa_has_child_ke(const strongswan_sa_info_t *info, const char *expected_ke)
{
    if (!info || !expected_ke || !*expected_ke || !info->child_algorithms[0]) return false;
    size_t expected_len = strlen(expected_ke);
    const char *p = info->child_algorithms;
    while (*p) {
        const char *end = strchr(p, '/');
        if (!end) end = p + strlen(p);
        if ((size_t)(end - p) == expected_len &&
            memcmp(p, expected_ke, expected_len) == 0) return true;
        p = *end ? end + 1 : end;
    }
    return false;
}

int strongswan_wait_for_sa(const app_config_t *cfg, const char *result_dir)
{
    time_t deadline = time(NULL) + cfg->timeout_sec;
    char *last = NULL;
    strongswan_sa_info_t info;

    while (time(NULL) <= deadline) {
        free(last);
        last = NULL;
        int rc = list_target_sa(cfg, result_dir, NULL, &info, &last);
        if (rc == 0 && info.ready) {
            save_output(result_dir, "sa_ready.txt", last ? last : "");
            log_pass("IKE SA ESTABLISHED and CHILD SA '%s' INSTALLED", cfg->child_name);
            free(last);
            return 0;
        }
        sleep(1);
    }

    save_output(result_dir, "sa_wait_timeout.txt", last ? last : "");
    log_error("SA '%s/%s' was not ready within %d seconds",
              cfg->connection_name, cfg->child_name, cfg->timeout_sec);
    free(last);
    return -1;
}

static int wait_for_target_sa_absent(const app_config_t *cfg, const char *result_dir,
                                     const char *phase)
{
    time_t deadline = time(NULL) + cfg->timeout_sec;
    char *last = NULL;
    strongswan_sa_info_t info;

    while (time(NULL) <= deadline) {
        free(last);
        last = NULL;
        int rc = list_target_sa(cfg, result_dir, NULL, &info, &last);
        if (rc == 0 && !info.ike_present && !info.child_present) {
            char file[160];
            snprintf(file, sizeof(file), "sa_absent_%s.txt", phase);
            save_output(result_dir, file, last ? last : "");
            free(last);
            return 0;
        }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 250000000L};
        nanosleep(&delay, NULL);
    }

    char file[160];
    snprintf(file, sizeof(file), "sa_absent_timeout_%s.txt", phase);
    save_output(result_dir, file, last ? last : "");
    free(last);
    return -1;
}

int strongswan_cleanup_target_sa(const app_config_t *cfg, const char *result_dir,
                                 const char *phase, strongswan_sa_info_t *previous_info)
{
    strongswan_sa_info_t info;
    char before_file[160];
    snprintf(before_file, sizeof(before_file), "sa_before_cleanup_%s.txt", phase);
    if (list_target_sa(cfg, result_dir, before_file, &info, NULL) != 0) {
        log_error("cannot inspect existing target SA before %s cleanup", phase);
        return -1;
    }
    if (previous_info) *previous_info = info;

    if (!info.ike_present && !info.child_present) {
        log_pass("no existing target SA '%s/%s' before %s cleanup",
                 cfg->connection_name, cfg->child_name, phase);
        return 0;
    }

    log_info("existing target SA detected before %s cleanup: IKE=%s CHILD=%s%s",
             phase,
             info.ike_present ? "yes" : "no",
             info.child_present ? "yes" : "no",
             info.reqid_valid ? " (reqid recorded)" : "");

    char timeout[32];
    snprintf(timeout, sizeof(timeout), "%d", cfg->timeout_sec);
    const char *args[] = {
        "--terminate", "--ike", cfg->connection_name,
        "--timeout", timeout
    };
    char *out = NULL;
    int terminate_rc = run_swanctl(cfg, args, 5, &out);
    char terminate_file[160];
    snprintf(terminate_file, sizeof(terminate_file), "terminate_%s.txt", phase);
    save_output(result_dir, terminate_file, out ? out : "");
    if (terminate_rc != 0) {
        strongswan_sa_info_t after_terminate;
        int inspect_rc = list_target_sa(cfg, result_dir, NULL, &after_terminate, NULL);
        if (inspect_rc == 0 && !after_terminate.ike_present && !after_terminate.child_present) {
            log_info("terminate returned rc=%d during %s cleanup because the target SA was already removed (likely by peer); absence will still be verified",
                     terminate_rc, phase);
        } else {
            log_warn("swanctl terminate returned rc=%d during %s cleanup; verifying actual SA removal: %s",
                     terminate_rc, phase, out ? out : "");
        }
    }
    free(out);

    if (wait_for_target_sa_absent(cfg, result_dir, phase) != 0) {
        log_error("target SA '%s/%s' still exists after %s cleanup timeout",
                  cfg->connection_name, cfg->child_name, phase);
        return -1;
    }

    log_pass("target IKE/CHILD SA removed and absence confirmed (%s cleanup)", phase);
    return 0;
}

int strongswan_snapshot(const app_config_t *cfg, const char *result_dir, const char *phase)
{
    const char *args[] = {"--list-sas"};
    char *out = NULL;
    int rc = run_swanctl(cfg, args, 1, &out);
    char file[128];
    snprintf(file, sizeof(file), "swanctl_sas_%s.txt", phase);
    save_output(result_dir, file, out ? out : "");
    free(out);
    return rc;
}
