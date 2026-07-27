#ifndef PROCESS_H
#define PROCESS_H

#include <stddef.h>
#include <sys/types.h>

int command_exists(const char *name);
int process_run(char *const argv[], char **combined_output);
int process_run_to_file(char *const argv[], const char *output_path);
pid_t process_spawn(char *const argv[], const char *stdout_path, const char *stderr_path);
int process_stop(pid_t pid, int signal_number, int timeout_ms);
int write_text_file(const char *path, const char *text, unsigned int mode);
int mkdir_recursive(const char *path, unsigned int mode);
void join_path(char *out, size_t out_size, const char *dir, const char *name);

#endif
