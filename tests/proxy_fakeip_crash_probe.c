#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int saves, selected_fd=-1, selected_dir=-1;
static char selected_name[32];

int openat(int dir, const char *path, int flags, ...) {
    mode_t mode=0;
    if (flags & O_CREAT) {
        va_list args; va_start(args,flags); mode=va_arg(args,int); va_end(args);
    }
    int fd=(int)syscall(SYS_openat,dir,path,flags,mode);
    const char *index=getenv("NEXUS_CRASH_SAVE");
    if (fd>=0 && (flags & O_CREAT) &&
        (!strcmp(path,"history.next") || !strcmp(path,"highwater.next")) &&
        ++saves==(index ? atoi(index) : 0)) {
        selected_fd=fd; selected_dir=dir;
        strncpy(selected_name,path,sizeof(selected_name)-1);
    }
    return fd;
}

static void checkpoint(const char *stage) {
    const char *requested=getenv("NEXUS_CRASH_STAGE");
    if (requested && !strcmp(requested,stage)) {
        static const char marker[]="nexus crash checkpoint\n";
        (void)syscall(SYS_write,STDERR_FILENO,marker,sizeof(marker)-1);
        (void)syscall(SYS_kill,syscall(SYS_getpid),SIGSTOP);
    }
}

int fsync(int fd) {
    int result=(int)syscall(SYS_fsync,fd);
    if (!result && fd==selected_fd) checkpoint("file-sync");
    if (!result && fd==selected_dir) checkpoint("dir-sync");
    return result;
}

int renameat(int olddir,const char *old,int newdir,const char *newname) {
    int result=(int)syscall(SYS_renameat,olddir,old,newdir,newname);
    if (!result && olddir==selected_dir && selected_name[0] && !strcmp(old,selected_name))
        checkpoint("rename");
    return result;
}
