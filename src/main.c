#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include "ctf-pwn-server.h"

int main(int argc, char *argv[])
{
    struct epoll_event ev, events[2];
    int run, event_num, i, wait_time;

    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    parsing_argv(argc, argv);

    if(getuid() != 0)
    {
        error_printf("Please execute the program with root privileges.\n");
        exit(EXIT_FAILURE);
    }

    initial_service();

    info_printf("Service start (pid=%d,version=%s)\n", getpid(), VERSION);

    run = 1;
    while(run)
    {
        if(cons_len == 0)
        {
            wait_time = -1;
        }
        else
        {
            wait_time = 1000;
        }
        event_num = epoll_wait(epoll_fd, events, sizeof(events)/sizeof(events[0]), wait_time);
        for(i = 0; i < event_num; i++)
        {
            if(events[i].data.fd == signal_fd)
            {
                run = signal_handler();
            }
            else if(events[i].data.fd == server_socket)
            {
                run = service_handler();
            }
        }
        clean_timeout_process();
    }

    end_all_process();
    info_printf("Service end\n");

    return 0;
}