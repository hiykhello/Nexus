// Diagnostic only: timestamp synthetic IPv4 UDP packets on an isolated lo.
// No payload is stored except the final eight bytes (the test's token at the
// SOCKS and echo endpoints). Encrypted packets have an unrelated final value.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static void stop_capture(int signal_number) { (void)signal_number; stopping = 1; }

static int64_t clock_ns(clockid_t clock) {
    struct timespec value;
    if (clock_gettime(clock, &value)) { perror("clock_gettime"); exit(2); }
    return (int64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static int64_t realtime_offset(void) {
    int64_t before = clock_ns(CLOCK_MONOTONIC);
    int64_t realtime = clock_ns(CLOCK_REALTIME);
    int64_t after = clock_ns(CLOCK_MONOTONIC);
    return realtime - (before + (after - before) / 2);
}

static uint16_t read16(unsigned char const* p) { return (uint16_t)((p[0] << 8) | p[1]); }

int main(int argc, char** argv) {
    if (argc != 2) { fprintf(stderr, "usage: packet_trace OUTPUT\n"); return 2; }
    FILE* out = fopen(argv[1], "w");
    if (!out) { perror("fopen"); return 2; }
    if (setvbuf(out, NULL, _IOFBF, 1 << 20)) { perror("setvbuf"); return 2; }
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_IP));
    if (fd < 0) { perror("packet socket"); return 2; }
    int enabled = 1, receive_buffer = 4 * 1024 * 1024;
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 200000};
    if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &enabled, sizeof(enabled)) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof(receive_buffer)) ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
        perror("setsockopt"); return 2;
    }
    unsigned interface = if_nametoindex("lo");
    if (!interface) { perror("if_nametoindex"); return 2; }
    struct sockaddr_ll address = {.sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_IP), .sll_ifindex = (int)interface};
    if (bind(fd, (struct sockaddr*)&address, sizeof(address))) { perror("bind"); return 2; }
    struct sigaction action = {.sa_handler = stop_capture};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) { perror("sigaction"); return 2; }
    fprintf(out, "offset_start %" PRId64 "\n", realtime_offset());
    puts("ready"); fflush(stdout);
    uint64_t recorded = 0;
    int result = 0;
    while (!stopping) {
        unsigned char buffer[65536];
        char control[CMSG_SPACE(sizeof(struct timespec))];
        struct sockaddr_ll peer = {0};
        struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};
        struct msghdr message = {.msg_name = &peer, .msg_namelen = sizeof(peer), .msg_iov = &iov, .msg_iovlen = 1,
                                 .msg_control = control, .msg_controllen = sizeof(control)};
        ssize_t length = recvmsg(fd, &message, 0);
        if (length < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            perror("recvmsg"); result = 2; break;
        }
        if (peer.sll_pkttype == PACKET_OUTGOING || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || length < 42) continue;
        unsigned char const* ip = buffer + 14;
        size_t available = (size_t)length - 14, ihl = (ip[0] & 15u) * 4u;
        if (read16(buffer + 12) != ETH_P_IP || (ip[0] >> 4) != 4 || ihl < 20 || ihl + 8 > available ||
            ip[9] != 17 || (read16(ip + 6) & 0x3fff) || read16(ip + 2) > available ||
            read16(ip + 2) < ihl + 8) continue;
        unsigned char const* udp = ip + ihl;
        size_t udp_length = read16(udp + 4);
        if (udp_length < 8 || udp_length > read16(ip + 2) - ihl) continue;
        struct timespec timestamp = {0};
        for (struct cmsghdr* c = CMSG_FIRSTHDR(&message); c; c = CMSG_NXTHDR(&message, c)) {
            if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SO_TIMESTAMPNS && c->cmsg_len >= CMSG_LEN(sizeof(timestamp))) {
                memcpy(&timestamp, CMSG_DATA(c), sizeof(timestamp)); break;
            }
        }
        if (!timestamp.tv_sec) { fprintf(stderr, "missing packet timestamp\n"); result = 2; break; }
        uint64_t suffix = 0;
        if (udp_length >= 16)
            for (size_t i = udp_length - 8; i < udp_length; ++i) suffix = (suffix << 8) | udp[i];
        fprintf(out, "packet %" PRId64 " %u %u %zu %" PRIu64 "\n",
                (int64_t)timestamp.tv_sec * 1000000000 + timestamp.tv_nsec,
                read16(udp), read16(udp + 2), udp_length - 8, suffix);
        ++recorded;
    }
    struct tpacket_stats stats = {0}; socklen_t stats_size = sizeof(stats);
    if (getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &stats_size)) { perror("packet statistics"); result = 2; }
    fprintf(out, "offset_end %" PRId64 "\nstats %u %u %" PRIu64 "\n", realtime_offset(), stats.tp_packets, stats.tp_drops, recorded);
    if (fclose(out)) { perror("fclose"); result = 2; }
    close(fd);
    return result;
}
