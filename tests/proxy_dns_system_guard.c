#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#include <netdb.h>
#include <unistd.h>

int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** result) {
    (void)node; (void)service; (void)hints; (void)result;
    static const char marker[] = "unexpected-system-resolver\n";
    (void)write(STDERR_FILENO, marker, sizeof(marker)-1);
    return EAI_FAIL;
}
