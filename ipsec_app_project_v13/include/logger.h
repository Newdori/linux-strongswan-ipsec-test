#ifndef LOGGER_H
#define LOGGER_H

#include <stdarg.h>

int log_open(const char *path);
void log_close(void);
void log_info(const char *fmt, ...);
void log_pass(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_vmessage(const char *level, const char *fmt, va_list ap);

#endif
