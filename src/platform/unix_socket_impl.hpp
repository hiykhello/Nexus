#pragma once
namespace platform::unix_stream {
    struct Address { sockaddr_un value{}; socklen_t size=0; };
    inline auto address(std::string_view path) noexcept -> std::optional<Address> {
        Address result;
        if (path.size()<2 || path.size()>=sizeof(result.value.sun_path) ||
            (path.front()!='/' && path.front()!='@') || path.find('\0')!=path.npos) return {};
        result.value.sun_family=AF_UNIX;
        std::ranges::copy(path,result.value.sun_path);
        if (path.front()=='@') result.value.sun_path[0]='\0';
        result.size=static_cast<socklen_t>(offsetof(sockaddr_un,sun_path)+path.size()+(path.front()=='/'));
        return result;
    }

    struct Fd {
        int value=-1;
        inline auto release() noexcept -> int {return std::exchange(value,-1);}
        inline ~Fd() {if (value>=0) ::close(value);}
        explicit inline Fd(int descriptor=-1) noexcept : value(descriptor) {}
        Fd(Fd const&)=delete;
        auto operator=(Fd const&) -> Fd& =delete;
    };

    inline auto error() noexcept -> std::error_code {return {errno,std::generic_category()};}

    struct ListenerPath {
        Fd directory;
        std::string name;
        struct stat bound{};
        bool owned=false;

        inline auto close() noexcept -> void {
            if (!std::exchange(owned,false)) return;
            struct stat current{};
            if (::fstatat(directory.value,name.c_str(),&current,AT_SYMLINK_NOFOLLOW)==0 &&
                current.st_dev==bound.st_dev && current.st_ino==bound.st_ino)
                (void)::unlinkat(directory.value,name.c_str(),0);
        }
        inline ~ListenerPath() { close(); }

        inline auto bind(int descriptor,std::string_view path) -> std::error_code {
            auto endpoint=address(path);
            if (!endpoint) return std::make_error_code(std::errc::invalid_argument);
            if (path.front()=='@') {
#if defined(__linux__)
                if (::bind(descriptor,reinterpret_cast<sockaddr*>(&endpoint->value),endpoint->size)<0) return error();
                return {};
#else
                return std::make_error_code(std::errc::operation_not_supported);
#endif
            }
            auto delimiter=path.rfind('/');
            name=path.substr(delimiter+1);
            auto parent=std::string(path.substr(0,std::max(delimiter,std::size_t{1})));
            if (name.empty() || name=="." || name=="..") return std::make_error_code(std::errc::invalid_argument);
            directory.value=::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            if (directory.value<0) return error();
            struct stat info{};
            if (::fstat(directory.value,&info)<0) return error();
            if (info.st_uid!=::geteuid() || (info.st_mode&(S_IWGRP|S_IWOTH)))
                return std::make_error_code(std::errc::permission_denied);
            if (::flock(directory.value,LOCK_EX|LOCK_NB)<0) return error();
#if defined(__linux__)
            auto anchored=address(std::format("/proc/self/fd/{}/{}",directory.value,name));
#else
            auto anchored=endpoint;
#endif
            if (!anchored) return std::make_error_code(std::errc::filename_too_long);
            struct stat existing{};
            if (::fstatat(directory.value,name.c_str(),&existing,AT_SYMLINK_NOFOLLOW)==0) {
                if (!S_ISSOCK(existing.st_mode) || existing.st_uid!=::geteuid())
                    return std::make_error_code(std::errc::address_in_use);
#if defined(__linux__)
                Fd probe(::socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0));
#else
                Fd probe(::socket(AF_UNIX,SOCK_STREAM,0));
                if (probe.value>=0) {
                    (void)::fcntl(probe.value,F_SETFL,O_NONBLOCK);
                    (void)::fcntl(probe.value,F_SETFD,FD_CLOEXEC);
                }
#endif
                if (probe.value<0) return error();
                if (::connect(probe.value,reinterpret_cast<sockaddr*>(&anchored->value),anchored->size)==0 || errno!=ECONNREFUSED)
                    return std::make_error_code(std::errc::address_in_use);
                struct stat current{};
                if (::fstatat(directory.value,name.c_str(),&current,AT_SYMLINK_NOFOLLOW)<0) return error();
                if (current.st_ino!=existing.st_ino || current.st_dev!=existing.st_dev)
                    return std::make_error_code(std::errc::address_in_use);
                if (::unlinkat(directory.value,name.c_str(),0)<0) return error();
            } else if (errno!=ENOENT) return error();
            if (::bind(descriptor,reinterpret_cast<sockaddr*>(&anchored->value),anchored->size)<0) return error();
            if (::fstatat(directory.value,name.c_str(),&bound,AT_SYMLINK_NOFOLLOW)<0) return error();
            owned=true;
            if (::fchmodat(directory.value,name.c_str(),0600,0)<0) return error();
            return {};
        }
    };
}
