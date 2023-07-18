FROM ubuntu:22.04

RUN mkdir -m 755 -p /home/ctf

WORKDIR /home/ctf

RUN cp -r /lib* /home/ctf
RUN mkdir /home/ctf/usr
RUN cp -r /usr/lib* /home/ctf/usr

RUN mkdir /home/ctf/bin
RUN cp /bin/sh /home/ctf/bin
RUN cp /bin/ls /home/ctf/bin
RUN cp /bin/cat /home/ctf/bin

RUN mkdir /home/ctf/dev
RUN mknod /home/ctf/dev/null c 1 3
RUN mknod /home/ctf/dev/zero c 1 5
RUN mknod /home/ctf/dev/random c 1 8
RUN mknod /home/ctf/dev/urandom c 1 9
RUN chmod 666 /home/ctf/dev/*

COPY ./ctf-pwn-server /
RUN chown root:root /ctf-pwn-server && chmod 700 /ctf-pwn-server

CMD [ \
    "/ctf-pwn-server", \
    "--port=10000", \
    "--execve_argv=/bin/sh", \
    "--chroot_path=/home/ctf", \
    "--per_source=16", \
    "--timeout=10m", \
    "--max_connection=100", \
    "--uid_start=23000", \
    "--rlimit_cpu=1m", \
    "--rlimit_process=8", \
    "--rlimit_memory=1024m", \
    "--time_offset=+8h" \
]

EXPOSE 10000
