#define _GNU_SOURCE
#include <liburing.h>
#include <liburing/io_uring_version.h>
#if IO_URING_VERSION_MAJOR < 2 || (IO_URING_VERSION_MAJOR == 2 && IO_URING_VERSION_MINOR < 5)
#error "Nexus requires system liburing >= 2.5"
#endif
int nexus_uring_system_link_check(void) {
    struct io_uring_probe *probe = io_uring_get_probe();
    io_uring_free_probe(probe);
    return probe != 0;
}
