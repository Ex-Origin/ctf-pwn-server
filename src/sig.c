#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/signalfd.h>
#include <sys/wait.h>
#include "ctf-pwn-server.h"

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
            for(i = 0; i < arg_max_connection; i++)
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
                debug_printf("Terminate all processes with the UID of %d\n", arg_uid_start + index);
                CHECK((pid2 = fork()) != -1);
                if(pid2 == 0)
                {

                    CHECK(setgid(arg_uid_start + index) != -1);
                    CHECK(setuid(arg_uid_start + index) != -1);
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

int signal_handler()
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