#include "owner_lock.hpp"
#include <cstdio>
#include <cstdlib>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    auto [owner, error] = OwnerLock::acquire(argv[1]);
    if (error) { std::printf("error %d\n", error); return 1; }
    std::puts("acquired");
    std::fflush(stdout);
    char byte;
    ssize_t n;
    do { n = ::read(STDIN_FILENO, &byte, 1); } while (n < 0 && errno == EINTR);
    if (n == 1 && byte == 'w') {
        int fd = ::openat(owner.directory_fd(), "marker", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) return 3;
        if (::close(fd) != 0) return 4;
    }
}
