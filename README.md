
## Docker-Pwn-Init

**An init process specialized in CTF-Pwn service for competitions**

* It has no dependency on other package.
* Be similar to xinetd
* It could be used cross-platform.
* More low overhead than conventional methods

### Examples

```shell
gcc -g init.c -o init
docker build -t examples .
docker run --name examples --rm -d -p 10000:10000 examples
nc localhost 10000
ps -aux
# USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
# root           1  0.1  0.0   2508   644 ?        Ss   12:24   0:00 /init
# root           8  0.0  0.0   2508    76 ?        S    12:24   0:00 /init
# root           9  0.0  0.0   2508    76 ?        S    12:24   0:00 /init
# 2301          10  0.0  0.0   3984  2888 ?        S    12:24   0:00 /bin/bash
# 2301          11  0.0  0.0   5900  2724 ?        R    12:24   0:00 ps -aux
```

### start_service

We can deploy the Pwn service at function `start_service()`.

```c++
int start_service()
{
    char *child_args[] = {"/bin/bash", NULL};
    struct rlimit limit;

    limit.rlim_cur = 10 * 60;
    limit.rlim_max = 10 * 60;
    CHECK(setrlimit(RLIMIT_CPU, &limit) != -1);

    limit.rlim_cur = 256;
    limit.rlim_max = 256;
    CHECK(setrlimit(RLIMIT_NPROC, &limit) != -1);

    limit.rlim_cur = 0x40000000; // 1024M
    limit.rlim_max = 0x40000000;
    CHECK(setrlimit(RLIMIT_AS, &limit) != -1);

    alarm(10 * 60);

    setgid(2301);
    setuid(2301);

    return execv(child_args[0], child_args);
}
```


