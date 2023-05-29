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
// #define CHROOT_PATH "/home/ctf"
// the maximum instances of this service per source IP address
#define PER_SOURCE 10
#define PORT 10000
#define TIMEOUT 600
#define UID 2301

// The limitation of resource
#define MAX_CPU_TIMEOUT 600
#define MAX_PROCESS 256
#define MAX_MEMORY 0x40000000; // 1024M

#define LIMIT_IP

int start_service()
{
    char *child_args[] = {"/bin/bash", NULL};
    return execv(child_args[0], child_args);
}

// Show more information
#ifdef DEBUG
#define DPRINTF printf
#else
#define DPRINTF(...)
#endif

int signal_fd = -1;
int epoll_fd = -1;
int network_socket = -1;
int server_socket = -1;
sigset_t old_mask;
int amount = 0;

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

int proc_check(int pid)
{
    char path[0x100];
    struct stat sb;

    memset(path, 0, sizeof(path));
    snprintf(path, sizeof(path)-1, "/proc/%d/status", pid);

    memset(&sb, 0, sizeof(struct stat));
    if(stat(path, &sb) != -1)
    {
        if(sb.st_uid == UID && (time(NULL) - sb.st_ctime) > TIMEOUT)
        {
            kill(pid, SIGKILL);
            log_printf("Killed timeout process (pid=%d)\n", pid);
        }
    }

    return 0;
}

int clean_process()
{
    struct dirent **namelist;
    int n, i;

    CHECK((n = scandir("/proc", &namelist, NULL, alphasort)) != -1);

    for(i = 0; i < n; i++)
    {
        if(namelist[i]->d_type == DT_DIR)
        {
            proc_check(atoi(namelist[i]->d_name));
        }

        free(namelist[i]);
    }

    free(namelist);

    return 0;
}

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
            if(prctl(PR_CAPBSET_DROP, i, 0, 0, 0) == -1)
            {
                fprintf(stderr, "ERROR : prctl:PR_CAPBSET_DROP %s:%d: %m\n", __FILE__, __LINE__);
            }
        }

        i++;
    }
    return 0;
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

            log_printf("Sendmsg error : %m\n");
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
        log_printf("Short response\n");
        return 0;
    }
    if (diag->idiag_family != AF_INET) {
        log_printf("Unexpected family %u\n", diag->idiag_family);
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

            log_printf("Sendmsg error : %m\n");
            return -1;
        }
        if (ret == 0)
            return result;

        if (nladdr.nl_family != AF_NETLINK) {
            log_printf("!AF_NETLINK\n");
            return -1;
        }

        h = (struct nlmsghdr *) buf;

        if (!NLMSG_OK(h, ret)) {
            log_printf("!NLMSG_OK\n");
            return -1;
        }

        for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
            if (h->nlmsg_type == NLMSG_DONE)
                return result;

            if (h->nlmsg_type == NLMSG_ERROR) {
                err = NLMSG_DATA(h);

                if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*err))) {
                    log_printf("NLMSG_ERROR\n");
                } else {
                    errno = -err->error;
                    log_printf("NLMSG_ERROR\n");
                }

                return -1;
            }

            if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
                log_printf("Unexpected nlmsg_type %u\n", (unsigned) h->nlmsg_type);
                return -1;
            }

            result += compare_diag(NLMSG_DATA(h), h->nlmsg_len, target);
        }
    }

    return result;
}
#endif

int handle_service_child()
{
    int r = 0, status = 0;

    for(r = 1; r != 0 && r!= -1; )
    {
        r = waitpid(-1, &status, WNOHANG);
        if(r > 0)
        {
            if (WIFEXITED(status))
            {
                log_printf("Pid: %d    exited, status = %d\n", r, WEXITSTATUS(status));
                amount--;
            }
            else if (WIFSIGNALED(status))
            {
                if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WTERMSIG(status)])
                {
                    log_printf("Pid: %d    killed by signal %s\n", r, sig_name[WTERMSIG(status)]);
                }
                else
                {
                    log_printf("Pid: %d    killed by signal %d\n", r, WTERMSIG(status));
                }
                amount--;
            }
            else if (WIFSTOPPED(status))
            {
                if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*) && sig_name[WSTOPSIG(status)])
                {
                    log_printf("Pid: %d    stopped by signal %s\n", r, sig_name[WSTOPSIG(status)]);
                }
                else
                {
                    log_printf("Pid: %d    stopped by signal %d\n", r, WSTOPSIG(status));
                }
            }
            else if (WIFCONTINUED(status))
            {
                log_printf("Pid: %d    continued\n", r);
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

int init_socket()
{
    int value;
    struct sockaddr_nl src_addr;
    struct sockaddr_in server_addr;

    #ifdef LIMIT_IP
    // https://man7.org/linux/man-pages/man7/sock_diag.7.html
    CHECK((network_socket = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_SOCK_DIAG)) != -1);
    value = 32768;
    CHECK(setsockopt(network_socket, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) != -1);
    value = 1048576;
    CHECK(setsockopt(network_socket, SOL_SOCKET, SO_RCVBUF, &value, sizeof(value)) != -1);
    value = 1;
    CHECK(setsockopt(network_socket, SOL_NETLINK, NETLINK_EXT_ACK, &value, sizeof(value)) != -1);

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = 0;  /* all */  
    src_addr.nl_groups = 0;

    CHECK(bind(network_socket, (struct sockaddr*)&src_addr, sizeof(src_addr)) != -1);
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

    CHECK(listen(server_socket, 16) != -1);

    return 0;
}

int set_sig_hander()
{
    sigset_t new_mask;

    sigemptyset(&new_mask);
    sigaddset(&new_mask, SIGINT);
    sigaddset(&new_mask, SIGTERM);
    sigaddset(&new_mask, SIGQUIT);
    sigaddset(&new_mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &new_mask, &old_mask) == -1 || (signal_fd = signalfd(-1, &new_mask, 0)) == -1)
    {
        fprintf(stderr, "Error : sigprocmask or signalfd %s:%d: %m\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int monitor_fd(int fd)
{
    struct epoll_event event;

    event.events = EPOLLIN;
	event.data.fd = fd;

    if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) == -1)
    {
        fprintf(stderr, "Error : epoll_ctl %s:%d: %m\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return 0;
}

int service_handler()
{

    socklen_t struct_len;
    struct sockaddr_in client_addr;
    struct timeval timeout; 
    int client_socket;
    int existed_num;
    int pid;
    struct rlimit limit;

    struct_len = sizeof(struct sockaddr_in);
    memset(&client_addr, 0, sizeof(client_addr));
    client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &struct_len);

#ifdef LIMIT_IP
    send_query(network_socket);
    existed_num = receive_and_count(network_socket, client_addr.sin_addr.s_addr);

    if(existed_num <= PER_SOURCE)
#endif
    {   
        if(amount < MAX_PROCESS)
        {
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != -1);
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != -1);

            pid = fork();
            if(pid == 0)
            {
                amount ++;
                CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);
                CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

#ifdef CHROOT_PATH
                CHECK(chroot(CHROOT_PATH) != -1);
                CHECK(chdir("/") != -1);
#endif

                sandbox();

                CHECK(setgid(UID) != -1);
                CHECK(setuid(UID) != -1);

                limit.rlim_cur = MAX_CPU_TIMEOUT;
                limit.rlim_max = MAX_CPU_TIMEOUT;
                CHECK(setrlimit(RLIMIT_CPU, &limit) != -1);

                limit.rlim_cur = MAX_PROCESS;
                limit.rlim_max = MAX_PROCESS;
                CHECK(setrlimit(RLIMIT_NPROC, &limit) != -1);

                limit.rlim_cur = MAX_MEMORY; // 1024M
                limit.rlim_max = MAX_MEMORY;
                CHECK(setrlimit(RLIMIT_AS, &limit) != -1);

                CHECK(close(signal_fd)      != -1);
                CHECK(close(server_socket)  != -1);
                CHECK(close(network_socket) != -1);
                CHECK(close(epoll_fd)       != -1);

                CHECK(dup2(client_socket, STDIN_FILENO)     != -1);
                CHECK(dup2(client_socket, STDOUT_FILENO)    != -1);
                CHECK(dup2(client_socket, STDERR_FILENO)    != -1);

                CHECK(close(client_socket)  != -1);
                
                CHECK(setsid() != -1);

                start_service();

                for(;;)
                    exit(EXIT_FAILURE);
            }

            if(pid != -1)
            {
                log_printf("Receive %s:%d with pid %d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, pid);
            }
            else
            {
                log_printf("Receive %s:%d, fork error : Resource temporarily unavailable\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
                if(write(client_socket, "Resource temporarily unavailable\n", 33) == -1)
                {
                    log_printf("Write error : %m\n");
                }
            }
        }
        else
        {
            log_printf("ban %s:%d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
            if(write(client_socket, "There are no more resources to start a new child process, "
                                    "please wait a while or connect to the administrator\n", 110) == -1)
            {
                log_printf("Write error : %m\n");
            }
        }
        
    }
#ifdef LIMIT_IP
    else
    {
        log_printf("Ban %s:%d\n", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
        if(write(client_socket, "There are excessive connections from your IP\n", 45) == -1)
        {
            log_printf("Write error : %m\n");
        }
    }
#endif   

    CHECK(close(client_socket) != -1);

    return 1;
}

int signal_hander()
{
    pid_t pid;
    struct signalfd_siginfo fdsi;
    int result;
    int ret_val = 1;
    int wstatus;

    result = read(signal_fd, &fdsi, sizeof(struct signalfd_siginfo));
    if(result == sizeof(struct signalfd_siginfo))
    {
        switch (fdsi.ssi_signo)
        {
        case SIGINT:
            ret_val = 0;
            log_printf("Receive signal SIGINT\n");
            break;
        
        case SIGQUIT:
            ret_val = 0;
            log_printf("Receive signal SIGQUIT\n");
            break;

        case SIGTERM:
            ret_val = 0;
            log_printf("Receive signal SIGTERM\n");
            break;

        case SIGCHLD:
            ret_val = 1;
            handle_service_child();
            break;
        
        default:
            fprintf(stderr, "WARNNING : Read unexpected signal %d  %s:%d: %m\n", fdsi.ssi_signo, __FILE__, __LINE__);
            break;
        }
    }
    else
    {
        fprintf(stderr, "ERROR : read %s:%d: %m\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return ret_val;
}

int main(int argc, char **argv, char **envp)
{
    struct epoll_event ev, events[2];
    int run, event_num, i;

    CHECK((epoll_fd = epoll_create(2)) != -1);

    init_socket();
    set_sig_hander();
    monitor_fd(signal_fd);
    monitor_fd(server_socket);

#ifndef DEBUG
    log_to_file();
#endif
    setlinebuf(stdout);
    setlinebuf(stderr);

    log_printf("Service start (pid=%d)\n", getpid());
    run = 1;
    while(run)
    {
        event_num = epoll_wait(epoll_fd, events, sizeof(events)/sizeof(events[0]), 1000);
        for(i = 0; i < event_num; i++)
        {
            if(events[i].data.fd == signal_fd)
            {
                run = signal_hander();
            }
            else if(events[i].data.fd == server_socket)
            {
                run = service_handler();
            }
        }
        clean_process();
    }
    log_printf("Service end\n");
    
    return 0;
}
