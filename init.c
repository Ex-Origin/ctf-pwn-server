/**
 * Compile:     gcc -s -O3 init.c -o init
 * Repository:  https://github.com/Ex-Origin/docker-pwn-init
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/signalfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>

// #define CHROOT_PATH     "/home/ctf"
// the maximum instances of this service per source IP address
#define PER_SOURCE      16
#define PORT            10000
#define TIMEOUT         600
#define MAX_CONNECTION  256
// The end of uid is (UID_START + MAX_CONNECTION - 1)
#define UID_START       23000
// #define TIME_OFFSET     (8*60*60) // +8 hours

// The limitation of resource
#define MAX_CPU_TIMEOUT 60
#define MAX_PROCESS     8
#define MAX_MEMORY      0x40000000; // 1024M

int start_service()
{
    char *child_args[] = {"/bin/bash", NULL};
    return execv(child_args[0], child_args);
}

#define VERSION "2.1.1"

/**
 * The value must be TRUE, or the program will break down.
 * e.g., the value is thing what the program need to do.
 **/
#define CHECK(value)                                            \
    {                                                           \
        if ((value) == 0)                                       \
        {                                                       \
            error_printf("%m  %s:%d\n", __FILE__, __LINE__);    \
            abort();                                            \
        }                                                       \
    }

int epoll_fd = -1;
int server_socket = -1;
int signal_fd = -1;
sigset_t old_mask;

struct connection
{
    struct in6_addr addr;
    in_port_t port;
    pid_t pid;
    time_t start;
};

int cons_len = 0;
unsigned int cons_index = 0;
#ifdef MAX_CONNECTION
struct connection cons[MAX_CONNECTION] = {0};
#else
struct connection cons[1024] = {0};
#endif

char *sig_name[] = {
    "0",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "7",
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
    "29",
    "SIGUSR1",
    "SIGUSR2",
    "__SIGRTMIN"
};

int prefix_printf(FILE* fp, char *level)
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

    now = time(NULL);
#ifdef TIME_OFFSET
    now = now + (TIME_OFFSET);
#endif
    local = localtime(&now);

    hours = local->tm_hour;         // get hours since midnight (0-23)
    minutes = local->tm_min;        // get minutes passed after the hour (0-59)
    seconds = local->tm_sec;        // get seconds passed after a minute (0-59)
 
    day = local->tm_mday;            // get day of month (1 to 31)
    month = local->tm_mon + 1;      // get month of year (0 to 11)
    year = local->tm_year + 1900;   // get year since 1900

    result = fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d | %-7s | ", year, month, day, hours, minutes, seconds, level);

    return result;
}

#ifdef DEBUG
int debug_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    prefix_printf(stdout, "DEBUG");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}
#else
#define debug_printf(...)
#endif

int info_printf(const char *format, ...)
{
    va_list args;
    size_t result;

    prefix_printf(stdout, "INFO");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}

int warning_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    prefix_printf(stdout, "WARNING");
    va_start(args, format);
    result = vfprintf (stdout, format, args);
    va_end (args);
    return result;
}

int error_printf(const char *format, ...)
{
    va_list args;
    size_t result;
    
    prefix_printf(stderr, "ERROR");
    va_start(args, format);
    result = vfprintf (stderr, format, args);
    va_end (args);
    return result;
}

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
    serverAddressV6.sin6_port = htons(PORT);
    inet_pton(AF_INET6, "::", &serverAddressV6.sin6_addr);

    CHECK(bind(server_socket, (struct sockaddr *)&serverAddressV6, sizeof(struct sockaddr_in6)) != -1);

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

    if(cons_len < (sizeof(cons)/sizeof(*cons)))
    {
        existed_num = 1;
        for(i = 0; i < (sizeof(cons)/sizeof(*cons)); i++)
        {
            if(memcmp(&cons[i].addr, &client_addr.sin6_addr, sizeof(cons[i].addr)) == 0)
            {
                existed_num++;
            }
        }

        index = -1;
        for(i = 0; i < (sizeof(cons)/sizeof(*cons)); i++)
        {
            // Find the free space
            if(cons[((cons_index + i) % (sizeof(cons)/sizeof(*cons)))].pid == 0)
            {
                cons_index = ((cons_index + i) % (sizeof(cons)/sizeof(*cons)));
                index = cons_index;
                break;
            }
        }
        CHECK(index != -1);

        if(existed_num <= PER_SOURCE)
        {
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != -1);
            CHECK(setsockopt(client_socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != -1);

            pid = fork();
            if(pid == 0)
            {
                CHECK(sigprocmask(SIG_SETMASK, &old_mask, NULL) != -1);
                CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != -1);

#ifdef CHROOT_PATH
                CHECK(chroot(CHROOT_PATH) != -1);
                CHECK(chdir("/") != -1);
#endif

                sandbox();

                CHECK(setgid(UID_START + index) != -1);
                CHECK(setuid(UID_START + index) != -1);

#ifdef MAX_CPU_TIMEOUT
                limit.rlim_cur = MAX_CPU_TIMEOUT;
                limit.rlim_max = MAX_CPU_TIMEOUT;
                CHECK(setrlimit(RLIMIT_CPU, &limit) != -1);
#endif

#ifdef MAX_PROCESS
                limit.rlim_cur = MAX_PROCESS;
                limit.rlim_max = MAX_PROCESS;
                CHECK(setrlimit(RLIMIT_NPROC, &limit) != -1);
#endif

#ifdef MAX_MEMORY
                limit.rlim_cur = MAX_MEMORY;
                limit.rlim_max = MAX_MEMORY;
                CHECK(setrlimit(RLIMIT_AS, &limit) != -1);
#endif

                CHECK(close(signal_fd)      != -1);
                CHECK(close(server_socket)  != -1);
                CHECK(close(epoll_fd)       != -1);

                CHECK(dup2(client_socket, STDIN_FILENO) != -1);
                CHECK(close(client_socket)  != -1);
                CHECK(setsid() != -1);
                dup2(STDIN_FILENO, STDOUT_FILENO);
                dup2(STDIN_FILENO, STDERR_FILENO);

                start_service();

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

                info_printf("Receive %s:%d (pid=%d,cons_len=%d,existed_num=%d,uid=%d)\n", ip_buf, clientPort, pid, cons_len, existed_num, UID_START + index);
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

int handle_service_child(int option)
{
    int status = 0;
    pid_t pid, pid2;
    int i, is_con = 0, index;
    time_t spend;

    for(pid = 1; pid != 0 && pid!= -1; )
    {
        pid = waitpid(-1, &status, option);
        if(pid > 0)
        {
            is_con = 0;
            for(i = 0; i < (sizeof(cons)/sizeof(*cons)); i++)
            {
                if(cons[i].pid == pid)
                {
                    spend = time(NULL) - cons[i].start;
                    is_con = 1;
                    index = i;
                    break;
                }
            }

            if (WIFEXITED(status))
            {
                if(is_con)
                {
                    if (cons_len > 0) cons_len --;
                    info_printf("Pid: %d    exited,status=%d,time=%ds  (cons_len=%d)\n", pid, WEXITSTATUS(status), spend, cons_len);
                }
                else
                {
                    warning_printf("Pid: %d    exited,status=%d, not in cons  (cons_len=%d)\n", pid, WEXITSTATUS(status), cons_len);
                }
            }
            else if (WIFSIGNALED(status))
            {
                if(is_con)
                {
                    if (cons_len > 0) cons_len --;
                    if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*))
                    {
                        info_printf("Pid: %d    killed by signal %s,time=%ds  (cons_len=%d)\n", pid, sig_name[WTERMSIG(status)], spend, cons_len);
                    }
                    else
                    {
                        info_printf("Pid: %d    killed by signal %d,time=%ds  (cons_len=%d)\n", pid, WTERMSIG(status), spend, cons_len);
                    }
                }
                else
                {
                    if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*))
                    {
                        warning_printf("Pid: %d    killed by signal %s  (cons_len=%d)\n", pid, sig_name[WTERMSIG(status)], cons_len);
                    }
                    else
                    {
                        warning_printf("Pid: %d    killed by signal %d  (cons_len=%d)\n", pid, WTERMSIG(status), cons_len);
                    }
                }
            }
            else if (WIFSTOPPED(status))
            {
                if(WTERMSIG(status) < sizeof(sig_name)/sizeof(char*))
                {
                    warning_printf("Pid: %d    stopped by signal %s  (cons_len=%d)\n", pid, sig_name[WSTOPSIG(status)], cons_len);
                }
                else
                {
                    warning_printf("Pid: %d    stopped by signal %d  (cons_len=%d)\n", pid, WSTOPSIG(status), cons_len);
                }
            }
            else if (WIFCONTINUED(status))
            {
                warning_printf("Pid: %d    continued  (cons_len=%d)\n", pid, cons_len);
            }

            if(is_con)
            {
                debug_printf("Terminate all processes with the UID of %d\n", UID_START + index);
                CHECK((pid2 = fork()) != -1);
                if(pid2 == 0)
                {

                    CHECK(setgid(UID_START + index) != -1);
                    CHECK(setuid(UID_START + index) != -1);
                    kill(-1, SIGKILL);
                    while(1)
                        exit(EXIT_FAILURE);
                }
                CHECK(waitpid(pid2, NULL, 0) == pid2);
                memset(&cons[index], 0, sizeof(*cons));
            }
        }
    }

    return 0;
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
            info_printf("Receive signal SIGINT\n");
            break;
        
        case SIGQUIT:
            ret_val = 0;
            info_printf("Receive signal SIGQUIT\n");
            break;

        case SIGTERM:
            ret_val = 0;
            info_printf("Receive signal SIGTERM\n");
            break;

        case SIGCHLD:
            ret_val = 1;
            handle_service_child(WNOHANG);
            break;
        
        default:
            warning_printf("Read unexpected signal %d  %s:%d  %m\n", fdsi.ssi_signo, __FILE__, __LINE__);
            break;
        }
    }
    else
    {
        error_printf("read error  %s:%d  %m\n", __FILE__, __LINE__);
        exit(EXIT_FAILURE);
    }

    return ret_val;
}

int clean_process()
{
    time_t now;
    int i;

    now = time(NULL);
    for(i = 0; i < (sizeof(cons)/sizeof(*cons)); i++)
    {
        if(now - cons[i].start > TIMEOUT)
        {
            kill(UID_START + i, SIGKILL);
        }
    }
    return 0;
}

int end_all_process()
{
    int i;

    for(i = 0; i < (sizeof(cons)/sizeof(*cons)); i++)
    {
        if(cons[i].pid != 0)
        {
            kill(cons[i].pid, SIGKILL);
        }
    }
    
    handle_service_child(0);

    return 0;
}

int main()
{
    struct epoll_event ev, events[2];
    int run, event_num, i;

    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    if(getuid() != 0)
    {
        error_printf("Please execute the program with root privileges.\n");
        exit(EXIT_FAILURE);
    }

    CHECK((epoll_fd = epoll_create(2)) != -1);

    init_socket();
    set_sig_hander();
    monitor_fd(signal_fd);
    monitor_fd(server_socket);

    info_printf("Service start (pid=%d,version=%s)\n", getpid(), VERSION);
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

    end_all_process();
    info_printf("Service end\n");

    return 0;
}
