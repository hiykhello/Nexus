#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <dlfcn.h>

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    if (node && strcmp(node, "nexus-slow-resolver.invalid") == 0) {
        const char *marker = getenv("NEXUS_TEST_RESOLVER_MARKER");
        if (marker) { FILE *file = fopen(marker, "w"); if (file) { fputs("started\n", file); fclose(file); } }
        struct timespec delay = {3, 0};
        while (nanosleep(&delay, &delay) != 0) {}
        *result = NULL;
        return EAI_AGAIN;
    }
    int (*next)(const char *, const char *, const struct addrinfo *, struct addrinfo **) = dlsym(RTLD_NEXT, "getaddrinfo");
    return next(node, service, hints, result);
}
