#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

/* Test-only fault: retain the real monotonic clock and invalidate wall time
   only after the test creates its marker. Avoid libc clock interposition loops. */
int clock_gettime(clockid_t clock, struct timespec* result) {
    const char* marker = getenv("NEXUS_TEST_BAD_WALL_CLOCK");
    if (clock == CLOCK_REALTIME && marker && access(marker, F_OK) == 0) {
        result->tv_sec = -1;
        result->tv_nsec = 0;
        return 0;
    }
    return (int)syscall(SYS_clock_gettime, clock, result);
}
