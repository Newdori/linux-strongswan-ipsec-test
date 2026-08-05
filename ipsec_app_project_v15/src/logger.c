#define _POSIX_C_SOURCE 200809L
#include "logger.h"
#include <stdio.h>
#include <time.h>

static FILE *g_log_file = NULL;

int log_open(const char *path)
{
    g_log_file = fopen(path, "a");
    return g_log_file ? 0 : -1;
}

void log_close(void)
{
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

void log_vmessage(const char *level, const char *fmt, va_list ap)
{
    char timestamp[64];
    time_t now = time(NULL);
    struct tm tm_value;
    localtime_r(&now, &tm_value);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_value);

    va_list copy;
    va_copy(copy, ap);
    fprintf(stdout, "[%s] [%s] ", timestamp, level);
    vfprintf(stdout, fmt, ap);
    fputc('\n', stdout);
    fflush(stdout);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] [%s] ", timestamp, level);
        vfprintf(g_log_file, fmt, copy);
        fputc('\n', g_log_file);
        fflush(g_log_file);
    }
    va_end(copy);
}

static void message(const char *level, const char *fmt, va_list ap)
{
    log_vmessage(level, fmt, ap);
}

void log_info(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); message("INFO", fmt, ap); va_end(ap);
}
void log_pass(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); message("PASS", fmt, ap); va_end(ap);
}
void log_warn(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); message("WARN", fmt, ap); va_end(ap);
}
void log_error(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt); message("ERROR", fmt, ap); va_end(ap);
}
