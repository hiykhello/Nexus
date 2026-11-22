module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

module proxy;
import std;
import platform.platform_defaults;

namespace proxy {
    namespace {
        struct Fd {
            int value=-1;
            explicit Fd(int fd) noexcept : value(fd) {}
            Fd(Fd const&)=delete;
            ~Fd() { if (value>=0) ::close(value); }
        };

        struct CloseDirectory {
            auto operator()(DIR* directory) const noexcept -> void { ::closedir(directory); }
        };
        using Directory=std::unique_ptr<DIR,CloseDirectory>;

        auto open_directory(int parent,char const* name) -> Directory {
            auto fd=::openat(parent,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
            if (fd<0) return {};
            Directory directory(::fdopendir(fd));
            if (!directory) {
                auto error=errno;
                ::close(fd);
                errno=error;
            }
            return directory;
        }

        auto decimal_name(std::string_view name) noexcept -> bool {
            return std::ranges::all_of(name,[](char byte) {return byte>='0' && byte<='9';});
        }

        template<std::size_t Size>
        auto read_link(int parent,char const* name,std::array<char,Size>& bytes) noexcept -> std::string_view {
            auto size=::readlinkat(parent,name,bytes.data(),bytes.size());
            if (size<=0 || static_cast<std::size_t>(size)==bytes.size()) return {};
            return {bytes.data(),static_cast<std::size_t>(size)};
        }

        auto effective_uid(int process) -> std::optional<std::uint32_t> {
            Fd file(::openat(process,"status",O_RDONLY|O_CLOEXEC|O_NOFOLLOW));
            if (file.value<0) return {};
            std::array<char,4096> bytes;
            auto size=::read(file.value,bytes.data(),bytes.size());
            if (size<=0) return {};
            auto status=std::string_view(bytes.data(),static_cast<std::size_t>(size));
            auto start=status.find("\nUid:\t");
            if (start==status.npos) return {};
            status.remove_prefix(start+6);
            auto separator=status.find('\t');
            if (separator==status.npos) return {};
            status.remove_prefix(separator+1);
            std::uint32_t uid;
            auto [end,error]=std::from_chars(status.data(),status.data()+status.size(),uid);
            if (error!=std::errc{} || end==status.data()+status.size() || *end!='\t') return {};
            return uid;
        }

        auto executable(int process,int descriptors,char const* slot,std::string_view socket,
            struct stat const& mount_namespace) -> std::string {
            // Opening the executable pins its identity while inspecting the
            // path and the descriptor that established the association.
            Fd exe(::openat(process,"exe",O_PATH|O_CLOEXEC));
            std::array<char,4096> path_bytes;
            std::array<char,64> socket_bytes;
            struct stat before{},after{},mount{};
            if (exe.value<0 || ::fstat(exe.value,&before)<0 ||
                ::fstatat(process,"ns/mnt",&mount,0)<0 || mount.st_dev!=mount_namespace.st_dev ||
                mount.st_ino!=mount_namespace.st_ino) return {};
            auto path=read_link(process,"exe",path_bytes);
            if (!path.starts_with('/') || path.ends_with(" (deleted)") ||
                platform::is_android_zygote_noise(path) ||
                read_link(descriptors,slot,socket_bytes)!=socket ||
                ::fstatat(process,"exe",&after,0)<0 || before.st_dev!=after.st_dev ||
                before.st_ino!=after.st_ino) return {};
            return std::string(path);
        }
    }

    auto local_process_path(std::uint32_t inode,std::uint32_t uid) -> std::string {
        // Restrict the observation to same-UID process leaders visible in
        // the proxy's procfs. A TCP socket does not carry a peer PID.
        if (uid!=::geteuid()) return {};
        auto proc=open_directory(AT_FDCWD,"/proc");
        if (!proc) return {};
        auto proc_fd=::dirfd(proc.get());
        struct statfs filesystem{};
        struct stat mount_namespace{};
        std::array<char,32> self;
        if (::fstatfs(proc_fd,&filesystem)<0 || filesystem.f_type!=PROC_SUPER_MAGIC ||
            read_link(proc_fd,"self",self)!=std::to_string(::getpid()) ||
            ::fstatat(proc_fd,"self/ns/mnt",&mount_namespace,0)<0) return {};

        auto deadline=Clock::now()+std::chrono::milliseconds(20);
        unsigned processes=4096,descriptors=32768;
        auto socket=std::format("socket:[{}]",inode);
        Directory holder, holder_fds;
        std::string matching_fd, path;
        for (;;) {
            errno=0;
            auto* entry=::readdir(proc.get());
            if (!entry) {
                if (errno || !holder || Clock::now()>=deadline ||
                    executable(::dirfd(holder.get()),::dirfd(holder_fds.get()),matching_fd.c_str(),socket,mount_namespace)!=path)
                    return {};
                return path;
            }
            if (!decimal_name(entry->d_name)) continue;
            if (!processes-- || Clock::now()>=deadline) return {};
            auto process=open_directory(proc_fd,entry->d_name);
            if (!process) {
                if (errno==ENOENT || errno==ESRCH) continue;
                return {};
            }
            auto process_fd=::dirfd(process.get());
            auto owner=effective_uid(process_fd);
            if (!owner) {
                struct stat info{};
                if (::fstatat(process_fd,"status",&info,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT) continue;
                // Missing credentials may hide a second same-UID holder.
                return {};
            }
            if (*owner!=uid) continue;
            auto fds=open_directory(process_fd,"fd");
            if (!fds) {
                if (errno==ENOENT || errno==ESRCH) continue;
                return {};
            }
            auto fds_fd=::dirfd(fds.get());
            for (;;) {
                errno=0;
                auto* fd=::readdir(fds.get());
                if (!fd) {
                    if (errno) return {};
                    break;
                }
                if (!decimal_name(fd->d_name)) continue;
                if (!descriptors-- || Clock::now()>=deadline) return {};
                std::array<char,64> link;
                if (read_link(fds_fd,fd->d_name,link)!=socket) {
                    if (errno==EACCES || errno==EPERM) return {};
                    continue;
                }
                if (holder) return {};
                path=executable(process_fd,fds_fd,fd->d_name,socket,mount_namespace);
                if (path.empty()) return {};
                matching_fd=fd->d_name;
                holder=std::move(process);
                holder_fds=std::move(fds);
                break;
            }
        }
    }
}
