#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include "ctf-pwn-server.h"

int cons_len            = 0;
unsigned int cons_index = 0;
struct connection *cons = NULL;

int sandbox()
{
    int i, j, enable, existed;
    int enable_capabilities[] = {
        // CAP_CHOWN,
        // CAP_DAC_OVERRIDE,
        // CAP_FSETID,
        // CAP_FOWNER,
        // CAP_MKNOD,
        // CAP_NET_RAW,
        // CAP_SETGID,
        // CAP_SETUID,
        // CAP_SETFCAP,
        // CAP_SETPCAP,
        // CAP_NET_BIND_SERVICE,
        // CAP_SYS_CHROOT,
        // CAP_KILL,
        // CAP_AUDIT_WRITE,
    };

    i = 0;
    enable = 0;
    while(enable != -1)
    {
        enable = prctl(PR_CAPBSET_READ, i, 0, 0, 0);
        existed = 0;
        for(j = 0; j < (sizeof(enable_capabilities)/sizeof(enable_capabilities[0])); j++)
        {
            if(i == enable_capabilities[j])
            {
                existed = 1;
                break;
            }
        }

        if(existed == 0 && enable == 1)
        {
            CHECK(prctl(PR_CAPBSET_DROP, i, 0, 0, 0) != -1);
        }

        i++;
    }
    return 0;
}

int service_handler()
{
    socklen_t struct_len;
    struct sockaddr_in6 client_addr;
    struct timeval timeout; 
    int client_socket;
    int existed_num;
    int pid;
    struct rlimit limit;
    char clientIP[INET6_ADDRSTRLEN], ip_buf[0x100];
    int clientPort;
    time_t now;
    int i, index;

    struct_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &struct_len);
    now = time(NULL);
    // Get the client's IP address and port
    memset(clientIP, 0, sizeof(clientIP));
    inet_ntop(AF_INET6, &(client_addr.sin6_addr), clientIP, INET6_ADDRSTRLEN);
    memset(ip_buf, 0, sizeof(ip_buf));
    if (clientIP[0] == ':')
    {
        snprintf(ip_buf, sizeof(ip_buf)-1, "%s", clientIP + 7);
    }
    else
    {
        snprintf(ip_buf, sizeof(ip_buf)-1, "[%s]", clientIP);
    }
    clientPort = ntohs(client_addr.sin6_port);

    if(cons_len < arg_max_connection)
    {
        existed_num = 1;
        for(i = 0; i < arg_max_connection; i++)
        {
            if(memcmp(&cons[i].addr, &client_addr.sin6_addr, sizeof(cons[i].addr)) == 0)
            {
                existed_num++;
            }
        }

        index = -1;
        for(i = 0; i < arg_max_connection; i++)
        {
            // Find the free space
            if(cons[((cons_index + i) % arg_max_connection)].pid == 0)
            {
                cons_index = ((cons_index + i) % arg_max_connection);
                index = cons_index;
                break;
            }
        }
        CHECK(index != -1);

        if(existed_num <= arg_per_source)
        {
            timeout.tv_sec = arg_timeout;
            timeout.tv_usec = 0;
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != -1);
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != -1);

            pid = fork();
            if(pid == 0)
            {
                CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);
                CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

                if(arg_chroot_path)
                {
                    CHECK(chroot(arg_chroot_path) != -1);
                    CHECK(chdir("/") != -1);
                }

                sandbox();

                CHECK(setgid(arg_uid_start + index) != -1);
                CHECK(setuid(arg_uid_start + index) != -1);

                limit.rlim_cur = arg_rlimit_cpu;
                limit.rlim_max = arg_rlimit_cpu;
                CHECK(setrlimit(RLIMIT_CPU, &limit) != -1);

                limit.rlim_cur = arg_rlimit_process;
                limit.rlim_max = arg_rlimit_process;
                CHECK(setrlimit(RLIMIT_NPROC, &limit) != -1);

                limit.rlim_cur = arg_rlimit_memory;
                limit.rlim_max = arg_rlimit_memory;
                CHECK(setrlimit(RLIMIT_AS, &limit) != -1);

                CHECK(close(signal_fd)      != -1);
                CHECK(close(server_socket)  != -1);
                CHECK(close(epoll_fd)       != -1);

                CHECK(dup2(client_socket, STDIN_FILENO) != -1);
                CHECK(close(client_socket)  != -1);
                CHECK(setsid() != -1);
                dup2(STDIN_FILENO, STDOUT_FILENO);
                dup2(STDIN_FILENO, STDERR_FILENO);

                execvp(arg_execve_argv[0], arg_execve_argv);

                for(;;)
                    exit(EXIT_FAILURE);
            }

            if(pid != -1)
            {
                cons[index].addr  = client_addr.sin6_addr;
                cons[index].port  = clientPort;
                cons[index].pid   = pid;
                cons[index].start = now;
                cons_len ++;
                cons_index ++;

                info_printf("Receive %s:%d (pid=%d,cons_len=%d,existed_num=%d,uid=%d)\n", ip_buf, clientPort, pid, cons_len, existed_num, arg_uid_start + index);
            }
            else
            {
                warning_printf("Failed at %s:%d, fork error : Resource temporarily unavailable (cons_len=%d,existed_num=%d)\n", ip_buf, clientPort, cons_len, existed_num);
                if(write(client_socket, "Resource temporarily unavailable\n", 33) == -1)
                {
                    warning_printf("Write error  %s:%d  %m\n", __FILE__, __LINE__);
                }
            }
        }
        else
        {
            info_printf("Block %s:%d (cons_len=%d,existed_num=%d)\n", ip_buf, clientPort, cons_len, existed_num);
            if(write(client_socket, "There are excessive connections from your IP\n", 45) == -1)
            {
                warning_printf("Write error  %s:%d  %m\n", __FILE__, __LINE__);
            }
        }
    }
    else
    {
        warning_printf("Failed at %s:%d, run out of resources (cons_len=%d,existed_num=%d)\n", ip_buf, clientPort, cons_len, existed_num);
        if(write(client_socket, "There are no more resources to start a new child process, "
                                "please wait a while or connect to the administrator\n", 110) == -1)
        {
            warning_printf("Write error  %s:%d  %m\n", __FILE__, __LINE__);
        }
    }

    CHECK(close(client_socket) != -1);

    return 1;
}

int clean_timeout_process()
{
    time_t now;
    int i;

    now = time(NULL);
    for(i = 0; i < arg_max_connection; i++)
    {
        if(cons[i].pid != 0 && now - cons[i].start > arg_timeout)
        {
            info_printf("Killed timeout process (pid=%d)\n", cons[i].pid);
            kill(cons[i].pid, SIGKILL);
        }
    }
    return 0;
}

int end_all_process()
{
    int i;

    for(i = 0; i < arg_max_connection; i++)
    {
        if(cons[i].pid != 0)
        {
            kill(cons[i].pid, SIGKILL);
        }
    }
    
    handle_service_child(0);

    return 0;
}