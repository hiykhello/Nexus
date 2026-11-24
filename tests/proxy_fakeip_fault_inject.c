#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test-only syscall interposition, scoped to one selected snapshot save. */
#ifndef NEXUS_FAULT_TEMP_NAME
#define NEXUS_FAULT_TEMP_NAME "next.beve"
#endif
static int saves, selected_fd = -1, selected_dir = -1, partial;
static char selected_name[64];
static int tracked(const char *path) {
    return strcmp(path, NEXUS_FAULT_TEMP_NAME) == 0 || strcmp(path, "history.next") == 0 || strcmp(path, "highwater.next") == 0;
}

int openat(int dir, const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    int fd = (int)syscall(SYS_openat, dir, path, flags, mode);
    const char *index = getenv("NEXUS_FAULT_SAVE");
    if (fd >= 0 && (flags & O_CREAT) && tracked(path) &&
        ++saves == (index ? atoi(index) : 0)) {
        selected_fd = fd;
        selected_dir = dir;
        strncpy(selected_name, path, sizeof(selected_name)-1);
        selected_name[sizeof(selected_name)-1] = 0;
    }
    return fd;
}

static int fails(const char *stage) {
    const char *requested = getenv("NEXUS_FAULT_STAGE");
    return requested && strcmp(requested, stage) == 0;
}

static int fail(void) {
    static const char marker[] = "nexus injected EIO\n";
    (void)syscall(SYS_write, STDERR_FILENO, marker, sizeof(marker) - 1);
    errno = EIO;
    return -1;
}

ssize_t write(int fd, const void *buf, size_t count) {
    if (fd == selected_fd && fails("write")) {
        if (!partial && count > 1) {
            partial = 1;
            return syscall(SYS_write, fd, buf, count / 2);
        }
        return fail();
    }
    return syscall(SYS_write, fd, buf, count);
}

int fsync(int fd) {
    if ((fd == selected_fd && fails("file-sync")) ||
        (fd == selected_dir && fails("dir-sync"))) return fail();
    return (int)syscall(SYS_fsync, fd);
}

int renameat(int olddir, const char *old, int newdir, const char *newname) {
    if (olddir == selected_dir && selected_name[0] && strcmp(old, selected_name) == 0 && fails("rename")) return fail();
    return (int)syscall(SYS_renameat, olddir, old, newdir, newname);
}
