#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Test-only: require DF on the selected Hy2 listener, so a per-destination
   route MTU produces a real kernel EMSGSIZE instead of IPv4 fragmentation. */
int bind(int fd, const struct sockaddr *address, socklen_t length) {
    int result = (int)syscall(SYS_bind, fd, address, length);
    if (result || !address || address->sa_family != AF_INET || length < sizeof(struct sockaddr_in)) return result;
    const char *configured = getenv("NEXUS_TEST_HY2_LISTENER_PORT");
    if (!configured || ntohs(((const struct sockaddr_in *)address)->sin_port) != strtoul(configured, 0, 10)) return result;
    int kind = 0; socklen_t size = sizeof(kind);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) || kind != SOCK_DGRAM) return result;
    int mode = IP_PMTUDISC_DO;
    if (setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &mode, sizeof(mode))) return -1;
    return 0;
}
