#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool write_failed;
static bool paused;

static bool mode(const char *name) {
    const char *configured = getenv("NEXUS_STATE_FAULT");
    return configured && strcmp(configured, name) == 0;
}

static bool ends_with(const char *text, const char *suffix) {
    size_t text_size = strlen(text), suffix_size = strlen(suffix);
    return text_size >= suffix_size && strcmp(text + text_size - suffix_size, suffix) == 0;
}

static bool fd_path(int fd, const char *suffix) {
    char link[64], path[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t count = readlink(link, path, sizeof(path) - 1);
    if (count < 0) return false;
    path[count] = '\0';
    return ends_with(path, suffix);
}

static void stop_at_fault(void) {
    static const char ready[] = "READY\n";
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    real_write(STDOUT_FILENO, ready, sizeof(ready) - 1);
    raise(SIGSTOP);
}

ssize_t write(int fd, const void *buffer, size_t size) {
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if ((mode("before-write") || mode("write-cleanup-error")) && fd_path(fd, "/.value.next")) {
        if (mode("before-write")) stop_at_fault();
        else {
            write_failed = true;
            errno = EIO;
            return -1;
        }
    }
    if (!paused && mode("fakeip-partial-wal") && fd_path(fd, "/fakeip.wal")) {
        paused = true;
        ssize_t written = real_write(fd, buffer, size / 2);
        if (written > 0) stop_at_fault();
        return written;
    }
    return real_write(fd, buffer, size);
}

int unlinkat(int directory, const char *path, int flags) {
    int (*real_unlink)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    if (mode("write-cleanup-error") && write_failed && strcmp(path, ".value.next") == 0) {
        errno = EACCES;
        return -1;
    }
    return real_unlink(directory, path, flags);
}

int fsync(int fd) {
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    const char *directory = getenv("NEXUS_STATE_DIRECTORY");
    const char *ready_fd = getenv("NEXUS_STATE_READY_FD");
    if (!paused && ready_fd && ((mode("hold-stage-sync") && fd_path(fd, "/.value.next")) ||
        (mode("hold-dir-sync") && directory && fd_path(fd, directory)))) {
        paused = true;
        ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
        int ready = atoi(ready_fd);
        int resume = atoi(getenv("NEXUS_STATE_RELEASE_FD"));
        char byte;
        if (real_write(ready, "x", 1) != 1 || read(resume, &byte, 1) != 1) _exit(81);
    }

    if (directory && (mode("before-dir-sync") || mode("dir-sync-error")) && fd_path(fd, directory)) {
        if (mode("before-dir-sync")) stop_at_fault();
        else {
            errno = EIO;
            return -1;
        }
    }
    return real_fsync(fd);
}

int renameat(int from, const char *source, int to, const char *destination) {
    int (*real_rename)(int, const char *, int, const char *) = dlsym(RTLD_NEXT, "renameat");
    if (mode("before-rename") && strcmp(destination, "value.state") == 0) stop_at_fault();
    return real_rename(from, source, to, destination);
}

int renameat2(int from, const char *source, int to, const char *destination, unsigned flags) {
    int (*real_rename)(int, const char *, int, const char *, unsigned) = dlsym(RTLD_NEXT, "renameat2");
    if (mode("isolate-error") && strcmp(source, "value.state") == 0) {
        errno = EROFS;
        return -1;
    }
    return real_rename(from, source, to, destination, flags);
}
