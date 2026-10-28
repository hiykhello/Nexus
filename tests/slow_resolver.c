#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static int (*next_resolver)(char const*, char const*, struct addrinfo const*, struct addrinfo**);
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_resolver(void) {
    *(void**)(&next_resolver) = dlsym(RTLD_NEXT, "getaddrinfo");
}

int getaddrinfo(char const* node, char const* service,
                struct addrinfo const* hints, struct addrinfo** result) {
    if (node && strcmp(node, "nexus-missing.test") == 0) return EAI_NONAME;
    if (node && strcmp(node, "nexus-delay.test") == 0) {
        char const* ready = getenv("NEXUS_TEST_RESOLVER_READY_FD");
        char const* gate = getenv("NEXUS_TEST_RESOLVER_GATE_FD");
        if (ready && gate) {
            char byte = 'x';
            ssize_t result;
            do { result = write(atoi(ready), &byte, 1); } while (result < 0 && errno == EINTR);
            if (result == 1) do { result = read(atoi(gate), &byte, 1); } while (result < 0 && errno == EINTR);
        }
        return EAI_NONAME;
    }
    pthread_once(&init_once, init_resolver);
    if (!next_resolver) return EAI_SYSTEM;
    if (node && (strcmp(node, "nexus-64.test") == 0 || strcmp(node, "nexus-65.test") == 0)) {
        struct addrinfo numeric_hints = {0};
        numeric_hints.ai_family = AF_INET;
        numeric_hints.ai_socktype = SOCK_STREAM;
        numeric_hints.ai_flags = AI_NUMERICHOST;
        struct addrinfo *head = NULL, **tail = &head;
        int count = strcmp(node, "nexus-64.test") == 0 ? 64 : 65;
        for (int i = 0; i < count; ++i) {
            struct addrinfo* entry = NULL;
            int error = next_resolver("127.0.0.1", service, &numeric_hints, &entry);
            if (error) { if (head) freeaddrinfo(head); return error; }
            *tail = entry;
            while (*tail) tail = &(*tail)->ai_next;
        }
        *result = head;
        return 0;
    }
    if (node && (strcmp(node, "nexus-fallback.test") == 0 ||
                 strcmp(node, "nexus-fallback-reversed.test") == 0)) {
        struct addrinfo numeric_hints = {0};
        numeric_hints.ai_family = AF_INET;
        numeric_hints.ai_socktype = SOCK_STREAM;
        numeric_hints.ai_flags = AI_NUMERICHOST;
        struct addrinfo *first = NULL, *second = NULL;
        int reversed = strcmp(node, "nexus-fallback-reversed.test") == 0;
        int error = next_resolver(reversed ? "127.0.0.1" : "127.0.0.2", service, &numeric_hints, &first);
        if (error) return error;
        error = next_resolver(reversed ? "127.0.0.2" : "127.0.0.1", service, &numeric_hints, &second);
        if (error) { freeaddrinfo(first); return error; }
        struct addrinfo *tail = first;
        while (tail->ai_next) tail = tail->ai_next;
        tail->ai_next = second;
        *result = first;
        return 0;
    }
    if (node && strcmp(node, "nexus-mapped.test") == 0) {
        struct addrinfo mapped_hints = {0};
        mapped_hints.ai_family = AF_INET6;
        mapped_hints.ai_socktype = SOCK_STREAM;
        mapped_hints.ai_flags = AI_NUMERICHOST;
        return next_resolver("::ffff:127.0.0.1", service, &mapped_hints, result);
    }
    return next_resolver(node, service, hints, result);
}
