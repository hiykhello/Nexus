module;
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

export module platform.unix_socket;
import std;
export import platform.unique_fd;

export namespace platform::unix_stream {
    struct Address { ::sockaddr_un value{}; ::socklen_t size=0; };
    inline auto address(std::string_view path) noexcept -> std::optional<Address> {
        Address result;
        if (path.size()<2 || path.size()>=sizeof(result.value.sun_path) ||
            (path.front()!='/' && path.front()!='@') || path.find('\0')!=path.npos) return {};
        result.value.sun_family=AF_UNIX;
        std::ranges::copy(path,result.value.sun_path);
        if (path.front()=='@') result.value.sun_path[0]='\0';
        result.size=static_cast<::socklen_t>(offsetof(::sockaddr_un,sun_path)+path.size()+(path.front()=='/'));
        return result;
    }

    using Fd = platform::UniqueFd;

    inline auto error() noexcept -> std::error_code {return {errno,std::generic_category()};}

    struct ListenerPath {
        Fd directory;
        std::string name;
        struct stat bound{};
        bool owned=false;

        inline auto close() noexcept -> void {
            if (!std::exchange(owned,false)) return;
            struct stat current{};
            if (::fstatat(directory.get(),name.c_str(),&current,AT_SYMLINK_NOFOLLOW)==0 &&
                current.st_dev==bound.st_dev && current.st_ino==bound.st_ino)
                (void)::unlinkat(directory.get(),name.c_str(),0);
        }
        inline ~ListenerPath() { close(); }

        inline auto bind(int descriptor,std::string_view path) -> std::error_code {
            auto endpoint=address(path);
            if (!endpoint) return std::make_error_code(std::errc::invalid_argument);
            if (path.front()=='@') {
#if defined(__linux__)
                if (::bind(descriptor,reinterpret_cast<::sockaddr*>(&endpoint->value),endpoint->size)<0) return error();
                return {};
#else
                return std::make_error_code(std::errc::operation_not_supported);
#endif
            }
            auto delimiter=path.rfind('/');
            name=path.substr(delimiter+1);
            auto parent=std::string(path.substr(0,std::max(delimiter,std::size_t{1})));
            if (name.empty() || name=="." || name=="..") return std::make_error_code(std::errc::invalid_argument);
            directory.reset(::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
            if (!directory) return error();
            struct stat info{};
            if (::fstat(directory.get(),&info)<0) return error();
            if (info.st_uid!=::geteuid() || (info.st_mode&(S_IWGRP|S_IWOTH)))
                return std::make_error_code(std::errc::permission_denied);
            if (::flock(directory.get(),LOCK_EX|LOCK_NB)<0) return error();
#if defined(__linux__)
            auto anchored=address(std::format("/proc/self/fd/{}/{}",directory.get(),name));
#else
            auto anchored=endpoint;
#endif
            if (!anchored) return std::make_error_code(std::errc::filename_too_long);
            struct stat existing{};
            if (::fstatat(directory.get(),name.c_str(),&existing,AT_SYMLINK_NOFOLLOW)==0) {
                if (!S_ISSOCK(existing.st_mode) || existing.st_uid!=::geteuid())
                    return std::make_error_code(std::errc::address_in_use);
#if defined(__linux__)
                Fd probe(::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0));
#else
                Fd probe(::socket(AF_UNIX,SOCK_STREAM,0));
                if (probe) {
                    (void)::fcntl(probe.get(),F_SETFL,O_NONBLOCK);
                    (void)::fcntl(probe.get(),F_SETFD,FD_CLOEXEC);
                }
#endif
                if (!probe) return error();
                if (::connect(probe.get(),reinterpret_cast<::sockaddr*>(&anchored->value),anchored->size)==0 || errno!=ECONNREFUSED)
                    return std::make_error_code(std::errc::address_in_use);
                struct stat current{};
                if (::fstatat(directory.get(),name.c_str(),&current,AT_SYMLINK_NOFOLLOW)<0) return error();
                if (current.st_ino!=existing.st_ino || current.st_dev!=existing.st_dev)
                    return std::make_error_code(std::errc::address_in_use);
                if (::unlinkat(directory.get(),name.c_str(),0)<0) return error();
            } else if (errno!=ENOENT) return error();
            if ((info.st_mode&(S_IRWXG|S_IRWXO))==0) {
                if (::bind(descriptor,reinterpret_cast<::sockaddr*>(&anchored->value),anchored->size)<0) return error();
                if (::fstatat(directory.get(),name.c_str(),&bound,AT_SYMLINK_NOFOLLOW)<0) return error();
                owned=true;
                if (::fchmodat(directory.get(),name.c_str(),0600,0)<0) return error();
                return {};
            }
            static std::atomic<std::uint64_t> stage_seq{0};
            auto stage_name=std::format(".nxs.{}.{}",::getpid(),stage_seq.fetch_add(1,std::memory_order_relaxed));
            if (::mkdirat(directory.get(),stage_name.c_str(),0700)<0) return error();
            struct StageGuard {
                int dir;
                std::string const& sub;
                int sub_fd=-1;
                bool unlink_sock=false;
                ~StageGuard() {
                    if (unlink_sock && sub_fd>=0) (void)::unlinkat(sub_fd,"s",0);
                    if (sub_fd>=0) ::close(sub_fd);
                    (void)::unlinkat(dir,sub.c_str(),AT_REMOVEDIR);
                }
            } stage{directory.get(),stage_name};
            stage.sub_fd=::openat(directory.get(),stage_name.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            if (stage.sub_fd<0) return error();
            if (::fchmod(stage.sub_fd,0700)<0) return error();
#if defined(__linux__)
            auto staged=address(std::format("/proc/self/fd/{}/s",stage.sub_fd));
#else
            auto staged=address(std::format("{}/{}/s",parent,stage_name));
#endif
            if (!staged) return std::make_error_code(std::errc::filename_too_long);
            if (::bind(descriptor,reinterpret_cast<::sockaddr*>(&staged->value),staged->size)<0) return error();
            stage.unlink_sock=true;
            if (::fchmodat(stage.sub_fd,"s",0600,0)<0) return error();
            if (::fstatat(stage.sub_fd,"s",&bound,AT_SYMLINK_NOFOLLOW)<0) return error();
            if (::renameat(stage.sub_fd,"s",directory.get(),name.c_str())<0) return error();
            stage.unlink_sock=false;
            owned=true;
            return {};
        }
    };
}
