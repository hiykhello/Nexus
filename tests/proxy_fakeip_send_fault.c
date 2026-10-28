#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

ssize_t sendmsg(int fd,const struct msghdr *msg,int flags) {
    const char *mode=getenv("NEXUS_FAKEIP_SEND_FAULT");
    if (mode && msg->msg_name && msg->msg_iovlen && msg->msg_iov[0].iov_len>=12) {
        const unsigned char *wire=msg->msg_iov[0].iov_base;
        if (wire[0]==0x12 && wire[1]==0x34 && (wire[2]&0x80) && wire[7]==1) {
            static const char marker[]="nexus injected DNS send EIO\n";
            if (!strcmp(mode,"delivered")) {
                ssize_t sent=syscall(SYS_sendmsg,fd,msg,flags);
                if (sent<0) return sent;
            }
            (void)syscall(SYS_write,STDERR_FILENO,marker,sizeof(marker)-1);
            errno=EIO;
            return -1;
        }
    }
    return syscall(SYS_sendmsg,fd,msg,flags);
}
