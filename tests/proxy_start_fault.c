#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

static atomic_uint listens;
static atomic_uint reuse_options;
static atomic_uint threads;
static atomic_uint accepts;
static atomic_long first_accept_fault_ns;
long nexus_test_accept_fault_time_ns(void) { return atomic_load(&first_accept_fault_ns); }
static atomic_uint uring_setups;
static atomic_uint uring_wakeup;
static atomic_uint uring_submits;
static void mark(void) {
    static const char message[] = "proxy-start-fault-injected\n";
    (void)write(STDERR_FILENO, message, sizeof(message)-1);
}
struct io_uring;
struct io_uring_params;
int io_uring_queue_init_params(unsigned entries, struct io_uring* ring, struct io_uring_params* params) {
    int (*next)(unsigned,struct io_uring*,struct io_uring_params*) = dlsym(RTLD_NEXT,"io_uring_queue_init_params");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && (strcmp(mode,"uring-setup")==0 || strcmp(mode,"uring-fallback")==0) && atomic_fetch_add(&uring_setups,1)==0) {
        mark(); return strcmp(mode,"uring-fallback")==0 ? -EINVAL : -EPERM;
    }
    return next(entries,ring,params);
}
int eventfd(unsigned int initval, int flags) {
    int (*next)(unsigned int,int) = dlsym(RTLD_NEXT,"eventfd");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"uring-eventfd")==0 && atomic_fetch_add(&uring_wakeup,1)==0) {
        mark(); errno=EPERM; return -1;
    }
    return next(initval,flags);
}
int io_uring_submit(struct io_uring* ring) {
    int (*next)(struct io_uring*) = dlsym(RTLD_NEXT,"io_uring_submit");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"uring-submit")==0 && atomic_fetch_add(&uring_submits,1)==0) {
        mark(); return -EPERM;
    }
    return next(ring);
}
int listen(int fd, int backlog) {
    int (*next)(int,int) = dlsym(RTLD_NEXT,"listen");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"listen")==0 && atomic_fetch_add(&listens,1)==1) {
        mark(); errno=EADDRINUSE; return -1;
    }
    return next(fd,backlog);
}
int setsockopt(int fd, int level, int name, const void* value, socklen_t length) {
    int (*next)(int,int,int,const void*,socklen_t) = dlsym(RTLD_NEXT,"setsockopt");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"reuse")==0 && level==SOL_SOCKET && name==SO_REUSEPORT &&
        atomic_fetch_add(&reuse_options,1)==1) {
        mark(); errno=EACCES; return -1;
    }
    return next(fd,level,name,value,length);
}
int pthread_create(pthread_t* thread, const pthread_attr_t* attr, void* (*start)(void*), void* arg) {
    int (*next)(pthread_t*,const pthread_attr_t*,void* (*)(void*),void*) = dlsym(RTLD_NEXT,"pthread_create");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"thread")==0 && atomic_fetch_add(&threads,1)==1) {
        mark(); return EAGAIN;
    }
    return next(thread,attr,start,arg);
}

int accept4(int fd, struct sockaddr* address, socklen_t* length, int flags) {
    int (*next)(int,struct sockaddr*,socklen_t*,int) = dlsym(RTLD_NEXT,"accept4");
    const char* mode=getenv("NEXUS_START_FAULT");
    if (mode && strcmp(mode,"accept-target")==0) {
        const char* port_text=getenv("NEXUS_FAULT_PORT");
        struct sockaddr_storage local;
        socklen_t size=sizeof(local);
        if (port_text && getsockname(fd,(struct sockaddr*)&local,&size)==0 && local.ss_family==AF_INET &&
            ntohs(((struct sockaddr_in*)&local)->sin_port)==strtoul(port_text,NULL,10)) {
            static atomic_bool fired;
            if (!atomic_exchange(&fired,1)) { mark(); errno=EIO; return -1; }
        }
    }
    if (mode && strcmp(mode,"accept-race")==0) {
        unsigned index=atomic_fetch_add(&accepts,1);
        if (index<2) {
            struct timespec start, now;
            clock_gettime(CLOCK_MONOTONIC,&start);
            do {
                if (atomic_load(&accepts)>=2) break;
                sched_yield();
                clock_gettime(CLOCK_MONOTONIC,&now);
            } while (now.tv_sec-start.tv_sec<3);
            if (atomic_load(&accepts)<2) {
                static const char timeout[] = "proxy-fault-barrier-timeout\n";
                (void)write(STDERR_FILENO,timeout,sizeof(timeout)-1);
            }
            mark(); errno=index==0 ? EIO : ENOSPC; return -1;
        }
    }
    if (mode && strcmp(mode,"accept-burst")==0 && atomic_fetch_add(&accepts,1)<5) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long zero=0;
        atomic_compare_exchange_strong(&first_accept_fault_ns, &zero, now.tv_sec*1000000000L+now.tv_nsec);
        mark(); errno=EPROTO; return -1;
    }
    if (mode && (strcmp(mode,"accept")==0 || strcmp(mode,"accept-aborted")==0 ||
                 strcmp(mode,"accept-protocol")==0 || strcmp(mode,"accept-netdown")==0 ||
                 strcmp(mode,"accept-interrupted")==0) && atomic_fetch_add(&accepts,1)==0) {
        mark();
        errno=strcmp(mode,"accept-aborted")==0 ? ECONNABORTED :
              strcmp(mode,"accept-protocol")==0 ? EPROTO :
              strcmp(mode,"accept-netdown")==0 ? ENETDOWN :
              strcmp(mode,"accept-interrupted")==0 ? EINTR : EIO;
        return -1;
    }
    return next(fd,address,length,flags);
}
