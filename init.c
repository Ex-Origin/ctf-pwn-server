#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <sys/ptrace.h>
#include <wait.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/resource.h>
#include <linux/netlink.h>  
#include <sys/un.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>

#define INIT_LOG "/var/log/init.log"
// the maximum instances of this service per source IP address
#define PER_SOURCE 10
#define PORT 10000
#define TIMEOUT 600

#define CLEAN_DAEMON
#define LIMIT_IP

// Show more information
#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            fprintf(stderr, "%s:%d: %m\n", __FILE__, __LINE__); \
            abort();                                            \
        }                                                       \
    }

#define LOGV(variable)                           \
    {                                            \
        printf("" #variable ": 0x%llx (%llu)\n", \
               (unsigned long long)(variable),   \
               (unsigned long long)(variable));  \
    }

int log_printf( const char *format, ...)
{
    va_list args;
    // variables to store the date and time components
    int hours, minutes, seconds, day, month, year;
    // `time_t` is an arithmetic time type
    time_t now = 0;
    // localtime converts a `time_t` value to calendar time and
    // returns a pointer to a `tm` structure with its members
    // filled with the corresponding values
    struct tm *local;
    size_t result;

    CHECK(time(&now) != -1);
    local = localtime(&now);

    hours = local->tm_hour;         // get hours since midnight (0-23)
    minutes = local->tm_min;        // get minutes passed after the hour (0-59)
    seconds = local->tm_sec;        // get seconds passed after a minute (0-59)
 
    day = local->tm_mday;            // get day of month (1 to 31)
    month = local->tm_mon + 1;      // get month of year (0 to 11)
    year = local->tm_year + 1900;   // get year since 1900

    fprintf(stdout, "[%04d-%02d-%02d %02d:%02d:%02d] -- ", year, month, day, hours, minutes, seconds);

    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);

    return result;
}

/* Handle stop signal (Ctrl-C, etc). */
void handle_stop_sig(int sig) 
{
    log_printf("Received a STOP signal then exit\n");
    exit(EXIT_SUCCESS);
}

/* Handle timeout (SIGALRM). */

void handle_timeout(int sig) 
{
    log_printf("Received a timeout signal then exit\n");
    exit(EXIT_SUCCESS);
}

/* Handle skip request (SIGUSR1). */
void handle_skipreq(int sig) 
{
    log_printf("Received a SIGUSR1 signal\n");
}

void setup_signal_handlers(void) 
{
  /* Various ways of saying "stop". */
  signal(SIGHUP, handle_stop_sig);
  signal(SIGINT, handle_stop_sig);
  signal(SIGTERM, handle_stop_sig);

  /* Exec timeout notifications. */
  signal(SIGALRM, handle_timeout);

  /* SIGUSR1: skip entry */
  signal(SIGUSR1, handle_skipreq);

  /* Things we don't care about. */
  signal(SIGTSTP, SIG_IGN);
  signal(SIGPIPE, SIG_IGN);
}

char *sig_name[] = {
    NULL,
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    NULL,
    "SIGFPE",
    "SIGKILL",
    "SIGBUS",
    "SIGSEGV",
    "SIGSYS",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGURG",
    "SIGSTOP",
    "SIGTSTP",
    "SIGCONT",
    "SIGCHLD",
    "SIGTTIN",
    "SIGTTOU",
    "SIGPOLL",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    NULL,
    "SIGUSR1",
    "SIGUSR2",
    "__SIGRTMIN"
};

int init_handle()
{
    int pid, status;

    for(pid = wait(&status); pid != -1; pid = wait(&status))
    {
        if (WIFEXITED(status))
        {
            log_printf("INIT  : pid: %d    exited, status = %d\n", pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WTERMSIG(status)])
            {
                log_printf("INIT  : pid: %d    killed by signal %s\n", pid, sig_name[WTERMSIG(status)]);
            }
            else
            {
                log_printf("INIT  : pid: %d    killed by signal %d\n", pid, WTERMSIG(status));
            }
        }
        else if (WIFSTOPPED(status))
        {
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WSTOPSIG(status)])
            {
                log_printf("INIT  : pid: %d    stopped by signal %s\n", pid, sig_name[WSTOPSIG(status)]);
            }
            else
            {
                log_printf("INIT  : pid: %d    stopped by signal %d\n", pid, WSTOPSIG(status));
            }
        }
        else if (WIFCONTINUED(status))
        {
            log_printf("INIT  : pid: %d    continued\n", pid);
        }
    }

    return 0;
}

#ifdef CLEAN_DAEMON
int is_num(const char *s)
{
    int result = 1;
    int i;

    for(i = 0, result = 1; result && s[i]; i++)
    {
        if(!(s[i] >= '0' && s[i] <= '9'))
        {
            result = 0;
        }
    }

    return result;
}

/**
 * Return:
 *  1 zombie process
 *  0  check success
 *  -1 check failed
 */
int proc_check(char *pid_str, int *uid, int *pid)
{
    char path[0x100];
    char status_buf[0x1000];
    int result = 0;
    int fd = -1;
    int ppid = 0;
    char *tmp;
    struct stat sb;
    int is_zombie = 0;

    memset(path, 0, sizeof(path));
    strncpy(path, "/proc/", sizeof(path) - 1);
    strncat(path, pid_str, sizeof(path) - 1);
    strncat(path, "/status", sizeof(path) - 1);

    memset(status_buf, 0, sizeof(status_buf));
    memset(&sb, 0, sizeof(struct stat));
    if((fd  = open(path, O_RDONLY)) != -1 && 
        read(fd, status_buf, sizeof(status_buf)) != -1 &&
        fstat(fd, &sb) != -1)
    {
        if((tmp = strstr(status_buf, "Pid:")) != NULL)
        {
            *pid = atoi(tmp + 4);
        }
        else
        {
            log_printf("CLEAN : Not found 'Pid:' in '%s'\n", path);
        }

        if((tmp = strstr(status_buf, "PPid:")) != NULL)
        {
            ppid = atoi(tmp + 5);
        }
        else
        {
            log_printf("CLEAN : Not found 'PPid:' in '%s'\n", path);
        }

        if((tmp = strstr(status_buf, "Uid:")) != NULL)
        {
            *uid = atoi(tmp + 4);
        }
        else
        {
            log_printf("CLEAN : Not found 'Uid:' in '%s'\n", path);
        }

        if((tmp = strstr(status_buf, "State:	Z (zombie)")) != NULL)
        {
            is_zombie = 1;
            result = 1;
        }

        /* uid != 0 means the process is not root, and ppid == 1 means the process is daemon. */
        if(is_zombie == 0 && *uid != 0 && ppid == 1)
        {
            kill(*pid, SIGKILL);
            log_printf("CLEAN : Killed daemon process (uid=%d, pid=%d)\n", *uid, *pid);
            result = -1;
        }

        if(is_zombie == 0 && *uid != 0 && (time(NULL) - sb.st_ctime) > TIMEOUT)
        {
            kill(*pid, SIGKILL);
            log_printf("CLEAN : Killed timeout process (uid=%d, pid=%d)\n", *uid, *pid);
            result = -1;
        }
    }
    
    if(fd != -1)
    {
        close(fd);
    }

    return result;
}

int clean_handle(int pfd)
{
    struct dirent **namelist;
    int n, i;
    int uid, result;
    // Number of consecutive abnormal times
    size_t count;
    int pid;

    CHECK(getuid() == 0);
    CHECK(prctl(PR_SET_NAME, "clean-handle", NULL, NULL, NULL) != -1);
    signal(SIGCHLD, SIG_IGN);

    for(count = 0, uid = 0, result = 0;;)
    {
        if(result != -1) // normal
        {
            count = 0;
            // Wait
            sleep(1);
        }
        else // abnormal
        {
            count ++;
            usleep(100000);
        }

        // Clean all
        if(uid != 0 && count > 16)
        {
            log_printf("CLEAN : Clean all (count=%u, uid=%d)\n", count, uid);
            pid = fork();
            if(pid != -1)
            {
                CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL) != -1);

                if(pid == 0 && setuid(uid) == 0) // Child
                {
                    kill(-1, SIGKILL);
                    exit(EXIT_SUCCESS);
                }
            }
            else
            {
                log_printf("CLEAN : fork error : %m : when clean all\n");
            }

            // clear
            count = 0;
        }


        uid = 0;
        CHECK((n = scandir("/proc", &namelist, NULL, alphasort)) != -1);

        for(i = 0; i < n; i++)
        {
            if(namelist[i]->d_type == DT_DIR)
            {
                result = 0;
                if(is_num(namelist[i]->d_name))
                {
                    switch ((result = proc_check(namelist[i]->d_name, &uid, &pid)))
                    {
                    case 1:
                        CHECK(write(pfd, &pid, sizeof(pid)) == sizeof(pid));
                    case 0:
                        break;
                    case -1:
                        break;
                    default:
                        break;
                    }
                }
            }

            free(namelist[i]);
        }

        free(namelist);
    }

    return 0;
}
#endif

int start_service()
{
    char *child_args[] = {"/bin/bash", NULL};
    struct rlimit limit;

    CHECK(setgid(2301) != -1);
    CHECK(setuid(2301) != -1);

    limit.rlim_cur = TIMEOUT;
    limit.rlim_max = TIMEOUT;
    CHECK(setrlimit(RLIMIT_CPU, &limit) != -1);

    limit.rlim_cur = 256;
    limit.rlim_max = 256;
    CHECK(setrlimit(RLIMIT_NPROC, &limit) != -1);

    limit.rlim_cur = 0x40000000; // 1024M
    limit.rlim_max = 0x40000000;
    CHECK(setrlimit(RLIMIT_AS, &limit) != -1);

    return execv(child_args[0], child_args);
}

#ifdef LIMIT_IP
int send_query(int fd)
{
    struct sockaddr_nl nladdr = {
        .nl_family = AF_NETLINK
    };
    struct
    {
        struct nlmsghdr nlh;
        struct inet_diag_req_raw idr;
    } req = {
        .nlh = {
            .nlmsg_len = sizeof(req),
            .nlmsg_type = SOCK_DIAG_BY_FAMILY,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP
        },
        .idr = {
            .sdiag_family = AF_INET,
            .sdiag_protocol = IPPROTO_TCP,
            .idiag_states = 1<<TCP_ESTABLISHED|1<<TCP_SYN_SENT|1<<TCP_FIN_WAIT1|1<<TCP_FIN_WAIT2|1<<TCP_CLOSE_WAIT|1<<TCP_LAST_ACK|1<<TCP_CLOSING|0x1,
        }
    };
    struct iovec iov = {
        .iov_base = &req,
        .iov_len = sizeof(req)
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1
    };

    for (;;) {
        if (sendmsg(fd, &msg, 0) < 0) {
            if (errno == EINTR)
                continue;

            log_printf("PWN   : sendmsg error : %m\n");
            return -1;
        }

        return 0;
    }
}

int compare_diag(const struct inet_diag_msg *diag, unsigned int len, in_addr_t target)
{
    in_addr_t dst_addr;
    int result;
    int port;

    if (len < NLMSG_LENGTH(sizeof(*diag))) {
        log_printf("PWN   : short response\n");
        return 0;
    }
    if (diag->idiag_family != AF_INET) {
        log_printf("PWN   : unexpected family %u\n", diag->idiag_family);
        return 0;
    }

    dst_addr = diag->id.idiag_dst[0];
    port = diag->id.idiag_sport;

    if(target == dst_addr && port == htons(PORT))
    {
        result = 1;
    }
    else
    {
        result = 0;
    }

    return result;
}

int receive_and_count(int fd, in_addr_t target)
{
    long buf[8192 / sizeof(long)];
    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = sizeof(buf)
    };
    int flags = 0;
    const struct nlmsghdr *h;
    const struct nlmsgerr *err;
    int result = 0;

    for (;;) {
        struct msghdr msg = {
            .msg_name = &nladdr,
            .msg_namelen = sizeof(nladdr),
            .msg_iov = &iov,
            .msg_iovlen = 1
        };

        ssize_t ret = recvmsg(fd, &msg, flags);

        if (ret < 0) {
            if (errno == EINTR)
                continue;

            log_printf("PWN   : sendmsg error : %m\n");
            return -1;
        }
        if (ret == 0)
            return result;

        if (nladdr.nl_family != AF_NETLINK) {
            log_printf("PWN   : !AF_NETLINK\n");
            return -1;
        }

        h = (struct nlmsghdr *) buf;

        if (!NLMSG_OK(h, ret)) {
            log_printf("PWN   : !NLMSG_OK\n");
            return -1;
        }

        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return result;

            if (h->nlmsg_type == NLMSG_ERROR) {
                err = NLMSG_DATA(h);

                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
                    log_printf("PWN   : NLMSG_ERROR\n");
                } else {
                    errno = -err->error;
                    log_printf("PWN   : NLMSG_ERROR\n");
                }

                return -1;
            }

            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                log_printf("PWN   : unexpected nlmsg_type %u\n", (unsigned) h->nlmsg_type);
                return -1;
            }

            result += compare_diag(NLMSG_DATA(h), h->nlmsg_len, target);
        }
    }

    return result;
}
#endif

int handle_service_child(int pid)
{
    int recv_pid = 0, status = 0;
    int result = 0;
    
    recv_pid = waitpid(pid, &status, WNOHANG);
    if(recv_pid > 0)
    {
        if (WIFEXITED(status))
        {
            log_printf("PWN   : pid: %d    exited, status = %d\n", recv_pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status))
        {
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WTERMSIG(status)])
            {
                log_printf("PWN   : pid: %d    killed by signal %s\n", recv_pid, sig_name[WTERMSIG(status)]);
            }
            else
            {
                log_printf("PWN   : pid: %d    killed by signal %d\n", recv_pid, WTERMSIG(status));
            }
        }
        else if (WIFSTOPPED(status))
        {
            if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WSTOPSIG(status)])
            {
                log_printf("PWN   : pid: %d    stopped by signal %s\n", recv_pid, sig_name[WSTOPSIG(status)]);
            }
            else
            {
                log_printf("PWN   : pid: %d    stopped by signal %d\n", recv_pid, WSTOPSIG(status));
            }
        }
        else if (WIFCONTINUED(status))
        {
            log_printf("PWN   : pid: %d    continued\n", recv_pid);
        }
    }
    else if(recv_pid == 0)
    {
        log_printf("PWN   : pid: %d    recv_pid == 0 : waitpid : %m\n", pid);
    }
    else
    {
        log_printf("PWN   : pid: %d    Error: waitpid : %m\n", pid);
    }
    
    return result;
}

/**
 * The fd1 & fd2 are unnecessary for the child process.
 */
int handle_accept(int server_socket, int sock_fd, int fd1, int fd2)
{
    int struct_len;
    struct sockaddr_in client_addr;
    struct timeval timeout; 
    int client_socket;
    int existed_num;
    int pid;
    int result = 0;

    struct_len = sizeof(struct sockaddr_in);
    memset(&client_addr, 0, sizeof(client_addr));
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &struct_len);

#ifdef LIMIT_IP
    send_query(sock_fd);
    existed_num = receive_and_count(sock_fd, client_addr.sin_addr.s_addr);

    if(existed_num <= PER_SOURCE)
#endif
    {
        timeout.tv_sec = TIMEOUT;
        timeout.tv_usec = 0;
        CHECK(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != -1);
        CHECK(setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != -1);

        pid = fork();
        if(pid == 0)
        {
            CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL) != -1);

            CHECK(dup2(client_socket, STDIN_FILENO) != -1);
            CHECK(dup2(client_socket, STDOUT_FILENO) != -1);
            CHECK(dup2(client_socket, STDERR_FILENO) != -1);

            CHECK(close(server_socket) != -1);
            CHECK(close(client_socket) != -1);
            CHECK(close(sock_fd) != -1);
            CHECK(close(fd1) != -1);
            CHECK(close(fd2) != -1);

            CHECK(setsid() != -1);

            start_service();

            for(;;)
                exit(EXIT_SUCCESS);
        }

        if(pid != -1)
        {
            log_printf("PWN   : receive %s:%d with pid %d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, pid);
            result = 0;
        }
        else
        {
            log_printf("PWN   : receive %s:%d, fork error : Resource temporarily unavailable\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            CHECK(write(client_socket, "Resource temporarily unavailable\n", 33) != -1);
            result = -1;
        }
    }
#ifdef LIMIT_IP
    else
    {
        log_printf("PWN   : ban %s:%d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        CHECK(write(client_socket, "Blocked by pwn-service\n", 23) != -1);
        result = -1;
    }
#endif   

    close(client_socket);

    return result;
}

int pwn_service(int cfd)
{
    struct sockaddr_in server_addr, target_addr;
    int value;
    int server_socket;
    int sock_fd;
    struct sockaddr_nl src_addr;
    int epollfd;
    struct epoll_event ev, events[2];
    int child[0x100];
    int nfds;
    int i, j;
    // return value
    int ret_val;
    size_t zombie;

    CHECK(prctl(PR_SET_NAME, "pwn-service", NULL, NULL, NULL) != -1);
    CHECK((epollfd = epoll_create(2)) != -1);

#ifdef LIMIT_IP
    // https://man7.org/linux/man-pages/man7/sock_diag.7.html
    CHECK((sock_fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)) != -1);
    value = 32768;
    CHECK(setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != -1);
    value = 1048576;
    CHECK(setsockopt(sock_fd, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != -1);
    value = 1;
    CHECK(setsockopt(sock_fd, SOL_NETLINK, NETLINK_EXT_ACK, &value, sizeof(value)) != -1);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0;  /* all */  
    src_addr.nl_groups = 0;

    CHECK(bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr)) != -1);
#endif

    CHECK((server_socket = socket(AF_INET, SOCK_STREAM, 0)) != -1);

    // Don't wait WAIT signal.
    value = 1;
    CHECK(setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) != -1);
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    CHECK(bind(server_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) != -1);

    listen(server_socket, 10);

    ev.events = EPOLLIN;
    ev.data.fd = server_socket;
    CHECK(epoll_ctl(epollfd, EPOLL_CTL_ADD, server_socket, &ev) != -1);

    // Handle SIGCHLD
    ev.events = EPOLLIN;
    ev.data.fd = cfd;
    CHECK(epoll_ctl(epollfd, EPOLL_CTL_ADD, cfd, &ev) != -1);

    for(;;)
    {
        CHECK((nfds = epoll_wait(epollfd, events, 2, -1)) != -1);
        for(i = 0; i < nfds; i++)
        {
            if(events[i].data.fd == server_socket)
            {
                handle_accept(server_socket, sock_fd, epollfd, cfd);
            }
            else if(events[i].data.fd == cfd)
            {
                CHECK((ret_val = read(cfd, &child, sizeof(child))) >= 0);            
                CHECK(ret_val % sizeof(*child) == 0);
                CHECK(ret_val <= sizeof(child));
                for(j = 0; j < (ret_val / sizeof(*child)); j++)
                {
                    handle_service_child(child[j]);
                }
            }
            else
            {
                fprintf(stderr, "PWN   : Error : Unknown fd %s:%d: %m\n", __FILE__, __LINE__);
            }
        }
    }

    return 0;
} 

int log_to_file()
{
    int fd;
    fd = open(INIT_LOG, O_WRONLY|O_CREAT|O_TRUNC, 0600);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    int pid;
    int pipe_fd[2];

#ifndef DEBUG
    log_to_file();
#endif
    setlinebuf(stdout);
    setlinebuf(stderr);
    CHECK(pipe(pipe_fd) != -1);

#ifndef DEBUG
#ifdef CLEAN_DAEMON
    sleep(4);

    CHECK((pid = fork()) != -1);
    if(pid == 0)
    {
        CHECK(close(pipe_fd[0]) != -1);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL) != -1);
        log_printf("CLEAN : clean_handle start with pid %d\n", getpid());
        clean_handle(pipe_fd[1]);
        log_printf("CLEAN : clean_handle end\n");
        exit(EXIT_SUCCESS);
    }
#endif
#endif

#ifndef DEBUG
    sleep(4);

    CHECK((pid = fork()) != -1);
    if(pid == 0)
#endif 
    {
        CHECK(close(pipe_fd[1]) != -1);
        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL) != -1);
        log_printf("PWN   : pwn_service start with pid %d\n", getpid());
        pwn_service(pipe_fd[0]);
        log_printf("PWN   : pwn_service end\n");
        exit(EXIT_SUCCESS);
    }

    /* Init process */
    setup_signal_handlers();

    log_printf("INIT  : init_handle start with pid %d\n", getpid());
    init_handle();
    log_printf("INIT  : init_handle end\n");
    
    return 0;
}
