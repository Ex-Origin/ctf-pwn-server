#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <arpa/inet.h>
#include "ctf-pwn-server.h"

int epoll_fd        = -1;
int signal_fd       = -1;
int server_socket   = -1;
sigset_t old_mask   = {0};

int init_socket()
{
    int value;
    struct sockaddr_in6 serverAddressV6;

    CHECK((server_socket = socket(AF_INET6, SOCK_STREAM, 0)) != -1);

    // Don't wait WAIT signal.
    value = 1;
    CHECK(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != -1);
    
    memset(&serverAddressV6, 0, sizeof(serverAddressV6));
    serverAddressV6.sin6_family = AF_INET6;
    serverAddressV6.sin6_port = htons(arg_port);
    inet_pton(AF_INET6, "::", &serverAddressV6.sin6_addr);

    CHECK(bind(server_socket, (struct sockaddr *)&serverAddressV6, sizeof(struct sockaddr_in6)) != -1);

    CHECK(listen(server_socket, 16) != -1);

    return 0;
}

int set_sig_handler()
{
    sigset_t new_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    sigaddset(&new_mask, SIGQUIT);
    sigaddset(&new_mask, SIGCHLD);

    CHECK(sigprocmask(SIG_BLOCK, &new_mask, &old_mask) != -1);
    CHECK((signal_fd = signalfd(-1, &new_mask, 0)) != -1);

    return 0;
}

int monitor_fd(int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
    event.data.fd = fd;

    CHECK(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) != -1);

    return 0;
}

int randomize_index()
{
    int fd;

    fd = open("/dev/urandom", O_RDONLY);
    if(fd != -1)
    {
        CHECK(read(fd, &cons_index, sizeof(cons_index)) == sizeof(cons_index));
        cons_index = (cons_index % arg_max_connection);
        close(fd);
    }
    else
    {
        srand(time(NULL));
        cons_index = (rand() % arg_max_connection);
    }

    info_printf("Randomize cons_index=%u\n", cons_index);

    return 0;
}

int initial_service()
{
    CHECK((cons = calloc(arg_max_connection, sizeof(*cons))) != NULL);
    CHECK((epoll_fd = epoll_create(2)) != -1);

    init_socket();
    set_sig_handler();
    monitor_fd(signal_fd);
    monitor_fd(server_socket);

    randomize_index();

    return 0;
}