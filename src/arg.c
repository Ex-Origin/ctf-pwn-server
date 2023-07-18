#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "ctf-pwn-server.h"

char **arg_execve_argv  = NULL;
char *arg_chroot_path   = NULL;
int arg_port            = 10000;
int arg_per_source      = 16;
int arg_timeout         = 10 * 60;
int arg_max_connection  = 100;
int arg_uid_start       = 23000;
int arg_rlimit_cpu      = 1 * 60;
int arg_rlimit_process  = 8;
int arg_rlimit_memory   = 0x40000000; // 1024M
int arg_time_offset     = 0;
int arg_verbose         = 0;

int help()
{
    fprintf(stderr, "Usage: ctf-pwn-server [ARGS ...]\n"
                    "\n"
                    "ctf-pwn-server " VERSION "\n"
                    "General:\n"
                    "  -h, --help\n"
                    "    print help message\n"
                    "\n"
                    "  -v, --verbose\n"
                    "    verbose mode\n"
                    "\n"
                    "  --port=PORT (default: 10000)\n"
                    "    Specify local port for remote connects\n"
                    "\n"
                    "  --execve_argv=CMD\n"
                    "    service argv\n"
                    "\n"
                    "  --chroot_path=PATH\n"
                    "    Set the chroot path for the service\n"
                    "\n"
                    "  --per_source=LIMIT (default: 16)\n"
                    "    the maximum instances of this service per source IP address\n"
                    "\n"
                    "  --timeout=LIMIT (default: 10m)\n"
                    "    Set a timeout for the service, for example, 1 ,1s, 1m, 1h, 1d\n"
                    "\n"
                    "  --max_connection=MAX_CON (default: 100)\n"
                    "    Limits the amount of incoming connections\n"
                    "\n"
                    "  --uid_start=UID (default: 23000)\n"
                    "    Specify the UID range for the service to be [UID, UID+MAX_CON)\n"
                    "    Every connection possesses an individual UID\n"
                    "\n"
                    "  --rlimit_cpu=LIMIT (default: 1m)\n"
                    "    Set the maximum number of CPU seconds that every connection may use\n"
                    "    For example, 1 ,1s, 1m, 1h, 1d\n"
                    "\n"
                    "  --rlimit_process=LIMIT (default: 8)\n"
                    "    Set the maximum number of user processes that every connection may use\n"
                    "\n"
                    "  --rlimit_memory=LIMIT (default: 1024m)\n"
                    "    Set the maximum number of user memory that every connection may use\n"
                    "    For example, 1 ,1b, 1k, 1m, 1g\n"
                    "\n"
                    "  --time_offset=OFFSET (default: +0h)\n"
                    "    Set the offset of time for log\n"
                    "    For example, 0, +0h, -8h, +8h\n"
                    "\n"
                    "Report bugs to \"<https://github.com/Ex-Origin/ctf-pwn-server/issues>\"\n"
    );
    exit(EXIT_FAILURE);
}

char **parsing_execve_str(char *cmd)
{
    char *ptr = NULL, **tmp, **argv = NULL;
    int argc = 0, max;
    
    max = 16;
    CHECK((argv = calloc(max, sizeof(char *))) != NULL);

    ptr = strtok(cmd, " ");
    while(1)
    {
        if(ptr == NULL || *ptr)
        {
            if(argc + 1 > max)
            {
                CHECK((tmp = realloc(argv, (max * 2) * sizeof(char *))) != NULL);
                argv = tmp;
                max = max * 2;
            }
            argv[argc++] = ptr;
        }
        if(ptr == NULL)
        {
            break;
        }
        ptr = strtok(NULL, " ");
    }

    return argv;
}

int parsing_time(char *time_str)
{
    int result = 0;
    int sign = 0;

    if(*time_str == '+' || *time_str == '-')
    {
        if(*time_str == '-')
        {
            sign = 1;
        }
        time_str ++;
    }
    while(*time_str)
    {
        if(*time_str >= '0' && *time_str <='9')
        {
            result = result * 10 + *time_str - '0';
        }
        else
        {
            break;
        }
        time_str ++;
    }
    switch (*time_str)
    {
    case 0:
        break;

    case 's':
    case 'S':
        result = result * 1;
        break;

    case 'm':
    case 'M':
        result = result * 60;
        break;

    case 'h':
    case 'H':
        result = result * 60 * 60;
        break;

    case 'd':
    case 'D':
        result = result * 60 * 60 * 24;
        break;
    
    default:
        fprintf(stderr, "ctf-pwn-server: unknown unit of time (\"%c\")\n", *time_str);
        help();
        break;
    }
    if(sign)
    {
        result = -result;
    }
    return result;
}

int parsing_memory(char *memory_str)
{
    int result = 0;
    while(*memory_str)
    {
        if(*memory_str >= '0' && *memory_str <='9')
        {
            result = result * 10 + *memory_str - '0';
        }
        else
        {
            break;
        }
        memory_str ++;
    }
    switch (*memory_str)
    {
    case 0:
        break;

    case 'b':
    case 'B':
        result = result * 1;
        break;

    case 'k':
    case 'K':
        result = result * 1024;
        break;

    case 'm':
    case 'M':
        result = result * 1024 * 1024;
        break;

    case 'g':
    case 'G':
        result = result * 1024 * 1024 * 1024;
        break;
    
    default:
        fprintf(stderr, "ctf-pwn-server: unknown unit of memory (\"%c\")\n", *memory_str);
        help();
        break;
    }
    return result;
}

int parsing_argv(int argc, char *argv[])
{
    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"help",            no_argument,       0,  0 },
        {"verbose",         no_argument,       0,  0 },
        {"port",            required_argument, 0,  0 },
        {"execve_argv",     required_argument, 0,  0 },
        {"chroot_path",     required_argument, 0,  0 },
        {"per_source",      required_argument, 0,  0 },
        {"timeout",         required_argument, 0,  0 },
        {"max_connection",  required_argument, 0,  0 },
        {"uid_start",       required_argument, 0,  0 },
        {"rlimit_cpu",      required_argument, 0,  0 },
        {"rlimit_process",  required_argument, 0,  0 },
        {"rlimit_memory",   required_argument, 0,  0 },
        {"time_offset",     required_argument, 0,  0 },
    };

    while (1) {
       opt = getopt_long(argc, argv, "hv",
                 long_options, &option_index);
        if (opt == -1)
            break;

        switch (opt) {
        case 0:
            if(strcmp(long_options[option_index].name, "help") == 0){
                help();
            }else if(strcmp(long_options[option_index].name, "port") == 0){
                arg_port = atoi(optarg);
            }else if(strcmp(long_options[option_index].name, "execve_argv") == 0){
                arg_execve_argv = parsing_execve_str(optarg);
            }else if(strcmp(long_options[option_index].name, "execve_argv") == 0){
                arg_execve_argv = parsing_execve_str(optarg);
            }else if(strcmp(long_options[option_index].name, "chroot_path") == 0){
                arg_chroot_path = optarg;
            }else if(strcmp(long_options[option_index].name, "timeout") == 0){
                arg_timeout = parsing_time(optarg);
            }else if(strcmp(long_options[option_index].name, "max_connection") == 0){
                arg_max_connection = atoi(optarg);
            }else if(strcmp(long_options[option_index].name, "uid_start") == 0){
                arg_uid_start = atoi(optarg);
            }else if(strcmp(long_options[option_index].name, "rlimit_cpu") == 0){
                arg_rlimit_cpu = parsing_time(optarg);
            }else if(strcmp(long_options[option_index].name, "rlimit_process") == 0){
                arg_rlimit_process = atoi(optarg);
            }else if(strcmp(long_options[option_index].name, "rlimit_memory") == 0){
                arg_rlimit_memory = parsing_memory(optarg);
            }else if(strcmp(long_options[option_index].name, "time_offset") == 0){
                arg_time_offset = parsing_time(optarg);
            }else if(strcmp(long_options[option_index].name, "verbose") == 0){
                arg_verbose = 1;
            }
            break;

       case 'h':
            help();
            break;
        
        case 'v':
            arg_verbose = 1;
            break;

       default:
            help();
            break;
        }
    }

    if(!arg_execve_argv)
    {
        fprintf(stderr, "ctf-pwn-server: must have --execve_argv=CMD\n");
        help();
    }
    return 0;
}