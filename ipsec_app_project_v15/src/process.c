#define _GNU_SOURCE
#include "process.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_CAPTURE_SIZE (4U * 1024U * 1024U)

int command_exists(const char *name)
{
    const char *path = getenv("PATH");
    if (!path || !name || !*name) return 0;
    char *copy = strdup(path);
    if (!copy) return 0;
    int found = 0;
    char *save = NULL;
    for (char *dir = strtok_r(copy, ":", &save); dir; dir = strtok_r(NULL, ":", &save)) {
        char candidate[1024];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", dir, name) >= (int)sizeof(candidate)) continue;
        if (access(candidate, X_OK) == 0) { found = 1; break; }
    }
    free(copy);
    return found;
}

int process_run(char *const argv[], char **combined_output)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(argv[0], argv);
        dprintf(STDERR_FILENO, "execvp(%s) failed: %s\n", argv[0], strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    size_t capacity = 8192, length = 0;
    char *buffer = malloc(capacity);
    if (!buffer) { close(pipefd[0]); kill(pid, SIGTERM); waitpid(pid, NULL, 0); return -1; }
    while (length + 1 < MAX_CAPTURE_SIZE) {
        if (capacity - length < 4096) {
            size_t next = capacity * 2;
            if (next > MAX_CAPTURE_SIZE) next = MAX_CAPTURE_SIZE;
            char *new_buffer = realloc(buffer, next);
            if (!new_buffer) break;
            buffer = new_buffer;
            capacity = next;
        }
        ssize_t n = read(pipefd[0], buffer + length, capacity - length - 1);
        if (n < 0) { if (errno == EINTR) continue; break; }
        if (n == 0) break;
        length += (size_t)n;
    }
    close(pipefd[0]);
    buffer[length] = '\0';
    int status = 0;
    waitpid(pid, &status, 0);
    if (combined_output) *combined_output = buffer; else free(buffer);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return -1;
}

int process_run_to_file(char *const argv[], const char *output_path)
{
    char *output = NULL;
    int rc = process_run(argv, &output);
    int save_rc = write_text_file(output_path, output ? output : "", 0640);
    free(output);
    return save_rc == 0 ? rc : -1;
}

pid_t process_spawn(char *const argv[], const char *stdout_path, const char *stderr_path)
{
    pid_t pid = fork();
    if (pid != 0) return pid;
    int out_fd = open(stdout_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    int err_fd = open(stderr_path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (out_fd >= 0) { dup2(out_fd, STDOUT_FILENO); close(out_fd); }
    if (err_fd >= 0) { dup2(err_fd, STDERR_FILENO); close(err_fd); }
    execvp(argv[0], argv);
    _exit(127);
}

int process_stop(pid_t pid, int signal_number, int timeout_ms)
{
    if (pid <= 0) return 0;
    kill(pid, signal_number);
    int waited = 0;
    while (waited < timeout_ms) {
        int status = 0;
        pid_t rc = waitpid(pid, &status, WNOHANG);
        if (rc == pid) return 0;
        if (rc < 0 && errno == ECHILD) return 0;
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000L};
        nanosleep(&delay, NULL);
        waited += 100;
    }
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    return -1;
}

int write_text_file(const char *path, const char *text, unsigned int mode)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)mode);
    if (fd < 0) return -1;
    size_t len = text ? strlen(text) : 0;
    const char *p = text;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        p += n; len -= (size_t)n;
    }
    close(fd);
    return 0;
}

int mkdir_recursive(const char *path, unsigned int mode)
{
    char copy[1024];
    if (!path || strlen(path) >= sizeof(copy)) return -1;
    strcpy(copy, path);
    for (char *p = copy + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, (mode_t)mode) != 0 && errno != EEXIST) return -1;
            *p = '/';
        }
    }
    return (mkdir(copy, (mode_t)mode) == 0 || errno == EEXIST) ? 0 : -1;
}

void join_path(char *out, size_t out_size, const char *dir, const char *name)
{
    snprintf(out, out_size, "%s/%s", dir, name);
}
