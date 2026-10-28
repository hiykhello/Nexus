#define _GNU_SOURCE
#include <sys/syscall.h>
#include <sys/socket.h>
#include <unistd.h>

int listen(int fd, int backlog) {
    static const char marker[] = "nexus listen called\n";
    (void)syscall(SYS_write, STDERR_FILENO, marker, sizeof(marker)-1);
    return (int)syscall(SYS_listen, fd, backlog);
}
