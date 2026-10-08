/* Disposable App Sandbox behavior fixture; never a runtime execution backend. */
#define _DARWIN_C_SOURCE 1
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

static void result(int allowed, int error) {
    printf("{\"allowed\":%s,\"errno\":%d}\n", allowed ? "true" : "false", error);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (!strcmp(argv[1], "identity")) {
        printf("{\"uid\":%u,\"pid\":%d,\"pgid\":%d}\n", getuid(), getpid(), getpgrp());
        return 0;
    }
    if ((!strcmp(argv[1], "read") || !strcmp(argv[1], "write")) && argc == 3) {
        int writing = !strcmp(argv[1], "write");
        int fd = open(argv[2], writing ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY, 0600);
        int error = fd < 0 ? errno : 0;
        int allowed = fd >= 0;
        if (allowed) {
            char byte = 'x';
            ssize_t count = writing ? write(fd, &byte, 1) : read(fd, &byte, 1);
            allowed = count == 1;
            error = allowed ? 0 : errno;
            close(fd);
        }
        result(allowed, error);
        return 0;
    }
    if (!strcmp(argv[1], "network") && argc == 3) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        int opened = fd >= 0;
        int error = opened ? 0 : errno;
        int connected = 0;
        if (opened) {
            struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
            struct sockaddr_in target = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
            target.sin_port = htons((uint16_t)atoi(argv[2]));
            connected = connect(fd, (struct sockaddr *)&target, sizeof(target)) == 0;
            error = connected ? 0 : errno;
            close(fd);
        }
        printf("{\"socket_opened\":%s,\"connected\":%s,\"errno\":%d}\n", opened ? "true" : "false", connected ? "true" : "false", error);
        return 0;
    }
    if (!strcmp(argv[1], "detach")) {
        pid_t child = fork();
        if (child < 0) { result(0, errno); return 0; }
        if (child == 0) _exit(setsid() >= 0 ? 0 : 1);
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 3;
        result(WIFEXITED(status) && WEXITSTATUS(status) == 0, 0);
        return 0;
    }
    if (!strcmp(argv[1], "exec")) {
        pid_t child = fork();
        if (child < 0) { result(0, errno); return 0; }
        if (child == 0) {
            char *const args[] = { "true", NULL };
            char *const environment[] = { NULL };
            execve("/usr/bin/true", args, environment);
            _exit(111);
        }
        int status = 0;
        if (waitpid(child, &status, 0) != child) return 3;
        result(WIFEXITED(status) && WEXITSTATUS(status) == 0, 0);
        return 0;
    }
    if (!strcmp(argv[1], "files")) {
        struct rlimit limit = { .rlim_cur = 16, .rlim_max = 16 };
        int applied = setrlimit(RLIMIT_NOFILE, &limit) == 0;
        int descriptors[32], count = 0, error = applied ? 0 : errno;
        if (applied) {
            while (count < 32) {
                int fd = open("/dev/null", O_RDONLY);
                if (fd < 0) { error = errno; break; }
                descriptors[count++] = fd;
            }
            for (int i = 0; i < count; i++) close(descriptors[i]);
        }
        printf("{\"limit_applied\":%s,\"opened\":%d,\"errno\":%d}\n", applied ? "true" : "false", count, error);
        return 0;
    }
    if (!strcmp(argv[1], "memory")) {
        struct rlimit limit = { .rlim_cur = 64 * 1024 * 1024, .rlim_max = 64 * 1024 * 1024 };
        int applied = setrlimit(RLIMIT_AS, &limit) == 0;
        int apply_error = applied ? 0 : errno;
        size_t size = 128 * 1024 * 1024;
        void *memory = applied ? mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0) : MAP_FAILED;
        int allocated = memory != MAP_FAILED;
        int allocation_error = allocated ? 0 : errno;
        if (allocated) {
            volatile unsigned char *bytes = memory;
            for (size_t i = 0; i < size; i += 4096) bytes[i] = 1;
            munmap(memory, size);
        }
        printf("{\"limit_applied\":%s,\"apply_errno\":%d,\"allocated_above_limit\":%s,\"allocation_errno\":%d}\n", applied ? "true" : "false", apply_error, allocated ? "true" : "false", allocation_error);
        return 0;
    }
    if (!strcmp(argv[1], "processes")) {
        struct rlimit limit = { .rlim_cur = 0, .rlim_max = 0 };
        int applied = setrlimit(RLIMIT_NPROC, &limit) == 0;
        pid_t child = applied ? fork() : -1;
        int error = child < 0 ? errno : 0;
        if (child == 0) _exit(0);
        if (child > 0) {
            int status;
            if (waitpid(child, &status, 0) != child) return 3;
        }
        printf("{\"limit_applied\":%s,\"forked\":%s,\"errno\":%d}\n", applied ? "true" : "false", child >= 0 ? "true" : "false", error);
        return 0;
    }
    return 2;
}
