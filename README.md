
## Docker-Pwn-Init

**An init process specialized in CTF-Pwn service for competitions**

* It has no dependency on other package.
* Be similar to xinetd
* It could be used cross-platform.
* More low overhead than conventional methods

### Examples

```shell
gcc -s -O3 init.c -o init
docker build -t examples .
docker run --name examples --rm -d -p 10000:10000 examples
nc localhost 10000
ps -aux
# USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
# root           1  0.1  0.0   2508   644 ?        Ss   12:24   0:00 /init
# 2301          10  0.0  0.0   3984  2888 ?        S    12:24   0:00 /bin/bash
# 2301          11  0.0  0.0   5900  2724 ?        R    12:24   0:00 ps -aux
```

### start_service

We can deploy the Pwn service at function `start_service()`.

```c++
int start_service()
{
    char *child_args[] = {"/bin/bash", NULL};
    return execv(child_args[0], child_args);
}
```


