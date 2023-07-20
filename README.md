
# CTF-Pwn-Server

**A service process specialized in CTF-Pwn service for competitions**

## Features

* It has no dependency on other package.
* Be similar to [xinetd](https://linux.die.net/man/5/xinetd.conf).
* It could be used cross-platform.
* More low overhead than conventional methods.
* Every connection is allocated a distinct UID to safeguard against interference from other users.
* Builtin timeout function, when activated, will kill all processes belonging to the specified UID to prevent the presence of Trojan horses.
* Remove most of [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html) to mitigate potential attacks by users.
* Builtin chroot function.
* More precise log information.

## Usage

```
Usage: ctf-pwn-server [ARGS ...]

General:
  -h, --help
    print help message

  -v, --verbose
    verbose mode

  --port=PORT (default: 10000)
    Specify local port for remote connects
    Environment variable: CTF_PWN_SERVER_PORT

  --execve_argv=CMD
    service argv
    Environment variable: CTF_PWN_SERVER_EXECVE_ARGV

  --chroot_path=PATH
    Set the chroot path for the service
    Environment variable: CTF_PWN_SERVER_CHROOT_PATH

  --per_source=LIMIT (default: 16)
    the maximum instances of this service per source IP address
    Environment variable: CTF_PWN_SERVER_PER_SOURCE

  --timeout=LIMIT (default: 10m)
    Set a timeout for the service, for example, 1 ,1s, 1m, 1h, 1d
    Environment variable: CTF_PWN_SERVER_TIMEOUT

  --max_connection=MAX_CON (default: 100)
    Limits the amount of incoming connections
    Environment variable: CTF_PWN_SERVER_MAX_CONNECTION

  --uid_start=UID (default: 23000)
    Specify the UID range for the service to be [UID, UID+MAX_CON)
    Every connection possesses an individual UID
    Environment variable: CTF_PWN_SERVER_UID_START

  --rlimit_cpu=LIMIT (default: 1m)
    Set the maximum number of CPU seconds that every connection may use
    For example, 1 ,1s, 1m, 1h, 1d
    Environment variable: CTF_PWN_SERVER_RLIMIT_CPU

  --rlimit_process=LIMIT (default: 8)
    Set the maximum number of user processes that every connection may use
    Environment variable: CTF_PWN_SERVER_RLIMIT_PROCESS

  --rlimit_memory=LIMIT (default: 1024m)
    Set the maximum number of user memory that every connection may use
    For example, 1 ,1b, 1k, 1m, 1g
    Environment variable: CTF_PWN_SERVER_RLIMIT_MEMORY

  --time_offset=OFFSET (default: +0h)
    Set the offset of time for log
    For example, 0, +0h, -8h, +8h
    Environment variable: CTF_PWN_SERVER_TIME_OFFSET

Report bugs to "<https://github.com/Ex-Origin/ctf-pwn-server/issues>"
```

## Examples

1. Download the `ctf-pwn-server` from [Releases](https://github.com/Ex-Origin/ctf-pwn-server/releases) or compile the source code by yourself.
2. Run the server

    1. Executing manually

        ```shell
        sudo ./ctf-pwn-server --execve_argv=/bin/sh
        ```
    
    2. Running within a Docker container

        ```shell
        cp ./ctf-pwn-server docker/
        cd docker/
        docker-compose build
        docker-compose up -d
        ```

3. Connect to the service

    ```shell
    $ nc localhost 10000
    pwd
    /
    ls -l /
    total 12
    drwxr-xr-x 1 0 0 4096 Jun 21 13:30 bin
    drwxr-xr-x 1 0 0 4096 Jun 21 13:30 dev
    lrwxrwxrwx 1 0 0    7 Jun 21 13:29 lib -> usr/lib
    lrwxrwxrwx 1 0 0    9 Jun 21 13:29 lib32 -> usr/lib32
    lrwxrwxrwx 1 0 0    9 Jun 21 13:29 lib64 -> usr/lib64
    lrwxrwxrwx 1 0 0   10 Jun 21 13:29 libx32 -> usr/libx32
    drwxr-xr-x 1 0 0 4096 Jun 21 13:29 usr
    ls -l /bin
    total 296
    -rwxr-xr-x 1 0 0  35280 Jun 21 13:30 cat
    -rwxr-xr-x 1 0 0 138208 Jun 21 13:30 ls
    -rwxr-xr-x 1 0 0 125688 Jun 21 13:29 sh
    ```
