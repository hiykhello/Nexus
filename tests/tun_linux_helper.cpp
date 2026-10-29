#include <sys/socket.h>
#include <unistd.h>
import std;
import nexus.packet.tun_linux;
int main(int argc,char** argv) {
    if (argc!=2) return 1;
    int control=std::atoi(argv[1]);
    auto tun=nexus::packet::LinuxTun::create("nx-test");
    if (!tun) return 2;
    char byte='T'; iovec data{&byte,1};
    alignas(cmsghdr) std::array<std::byte,CMSG_SPACE(sizeof(int))> buffer{};
    msghdr message{}; message.msg_iov=&data; message.msg_iovlen=1;
    message.msg_control=buffer.data(); message.msg_controllen=buffer.size();
    auto header=CMSG_FIRSTHDR(&message); header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    int fd=tun->native_handle(); std::memcpy(CMSG_DATA(header),&fd,sizeof(fd));
    if (::sendmsg(control,&message,0)!=1 || ::read(control,&byte,1)!=1 || byte!='X') return 3;
    return 0;
}
