#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Observe the relay's real receive without changing its result or payload. */
ssize_t recvfrom(int fd, void *buffer, size_t size, int flags,
                 struct sockaddr *address, socklen_t *length) {
    ssize_t n = syscall(SYS_recvfrom, fd, buffer, size, flags, address, length);
    const char *pipe_fd = getenv("NEXUS_TEST_UDP_OBSERVE_FD");
    if (pipe_fd && n == 65500 && size >= 65500 && (flags & MSG_TRUNC)) {
        const unsigned char *bytes = buffer;
        size_t i = 0;
        while (i < 65500 && bytes[i] == 'x') ++i;
        if (i == 65500) (void)syscall(SYS_write, atoi(pipe_fd), "1", 1);
    }
    return n;
}
