#ifndef _H_CTF_PWN_SERVER_
#define _H_CTF_PWN_SERVER_

#define VERSION "2.2.8"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                                          \
    {                                                                         \
        if ((value) == 0)                                                     \
        {                                                                     \
            error_printf("%s  %s:%d\n", strerror(errno), __FILE__, __LINE__); \
            exit(EXIT_FAILURE);                                               \
        }                                                                     \
    }

int parsing_env();
int parsing_argv(int argc, char *argv[]);

extern char **arg_execve_argv;
extern char *arg_chroot_path;
extern int arg_port;
extern int arg_per_source;
extern int arg_timeout;
extern int arg_max_connection;
extern int arg_uid_start;
extern int arg_rlimit_cpu;
extern int arg_rlimit_process;
extern int arg_rlimit_memory;
extern int arg_time_offset;
extern int arg_verbose;

int debug_printf(const char *format, ...);
int info_printf(const char *format, ...);
int warning_printf(const char *format, ...);
int error_printf(const char *format, ...);

#include <signal.h>
extern int epoll_fd;
extern int signal_fd;
extern int server_socket;
extern sigset_t old_mask;

#include <arpa/inet.h>
struct connection
{
    struct in6_addr addr;
    in_port_t port;
    pid_t pid;
    time_t start;
};

extern int cons_len;
extern unsigned int cons_index;
extern struct connection *cons;

int service_handler();
int clean_timeout_process();
int end_all_process();

int handle_service_child(int option);
int signal_handler();

int initial_service();

#endif