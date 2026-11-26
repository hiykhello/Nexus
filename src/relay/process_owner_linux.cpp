module;
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

module relay;
import std;
import containers.inplace_vector;
import platform.platform_defaults;
import platform.unique_fd;

namespace relay {
    namespace {
        using Fd = platform::UniqueFd;

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
            if (file.get()<0) return {};
            std::array<char,4096> bytes;
            auto size=::read(file.get(),bytes.data(),bytes.size());
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
            if (exe.get()<0 || ::fstat(exe.get(),&before)<0 ||
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

        auto status_gid(int process) -> std::optional<std::uint32_t> {
            Fd file(::openat(process, "status", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
            if (file.get() < 0) return {};
            std::array<char, 4096> bytes;
            auto size = ::read(file.get(), bytes.data(), bytes.size());
            if (size <= 0) return {};
            auto status = std::string_view(bytes.data(), static_cast<std::size_t>(size));
            auto start = status.find("\nGid:\t");
            if (start == status.npos) return {};
            status.remove_prefix(start + 6);
            auto separator = status.find('\t');
            if (separator == status.npos) return {};
            status.remove_prefix(separator + 1);
            std::uint32_t gid = 0;
            auto [end, error] = std::from_chars(status.data(), status.data() + status.size(), gid);
            if (error != std::errc{} || end == status.data() + status.size() || *end != '\t') return {};
            return gid;
        }

        auto cmdline_package(int process) -> std::string {
            Fd file(::openat(process, "cmdline", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
            if (file.get() < 0) return {};
            std::array<char, 256> bytes{};
            auto size = ::read(file.get(), bytes.data(), bytes.size() - 1);
            if (size <= 0) return {};
            std::string_view raw(bytes.data(), static_cast<std::size_t>(size));
            auto nul = raw.find('\0');
            auto arg0 = nul == std::string_view::npos ? raw : raw.substr(0, nul);
            if (auto colon = arg0.find(':'); colon != std::string_view::npos) arg0 = arg0.substr(0, colon);
            if (!arg0.empty() && arg0.find('/') == std::string_view::npos && arg0.contains('.') &&
                std::ranges::all_of(arg0, [](unsigned char c) {
                    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                           (c >= '0' && c <= '9') || c == '.' || c == '_';
                }))
                return std::string(arg0);
            return {};
        }
    }

    auto local_process_details(std::uint32_t inode, std::uint32_t uid,
        std::optional<std::uint32_t>& gid_out, std::string& package_out,
        containers::inplace_vector<std::string, 8>& paths_out) -> void {
        // Restrict the observation to same-UID process leaders visible in
        // the proxy's procfs. A TCP socket does not carry a peer PID.
        if (uid!=::geteuid()) return;
        auto proc=open_directory(AT_FDCWD,"/proc");
        if (!proc) return;
        auto proc_fd=::dirfd(proc.get());
        struct statfs filesystem{};
        struct stat mount_namespace{};
        std::array<char,32> self;
        if (::fstatfs(proc_fd,&filesystem)<0 || filesystem.f_type!=PROC_SUPER_MAGIC ||
            read_link(proc_fd,"self",self)!=std::to_string(::getpid()) ||
            ::fstatat(proc_fd,"self/ns/mnt",&mount_namespace,0)<0) return;

        auto deadline=Clock::now()+std::chrono::milliseconds(20);
        unsigned processes=4096,descriptors=32768;
        auto socket=std::format("socket:[{}]",inode);
        struct Holder {
            Directory process, fds;
            std::string fd_name, path;
        };
        containers::inplace_vector<Holder, 8> holders;
        for (;;) {
            errno=0;
            auto* entry=::readdir(proc.get());
            if (!entry) {
                if (errno || Clock::now()>=deadline) return;
                for (auto& h : holders) {
                    if (executable(::dirfd(h.process.get()),::dirfd(h.fds.get()),h.fd_name.c_str(),socket,mount_namespace)!=h.path)
                        continue;
                    if (!gid_out) gid_out = status_gid(::dirfd(h.process.get()));
                    if (package_out.empty()) package_out = cmdline_package(::dirfd(h.process.get()));
                    if (paths_out.size() < paths_out.capacity()) paths_out.push_back(std::move(h.path));
                }
                return;
            }
            if (!decimal_name(entry->d_name)) continue;
            if (!processes-- || Clock::now()>=deadline) return;
            auto process=open_directory(proc_fd,entry->d_name);
            if (!process) {
                if (errno==ENOENT || errno==ESRCH) continue;
                return;
            }
            auto process_fd=::dirfd(process.get());
            auto owner=effective_uid(process_fd);
            if (!owner) {
                struct stat info{};
                if (::fstatat(process_fd,"status",&info,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT) continue;
                // Missing credentials may hide a second same-UID holder.
                return;
            }
            if (*owner!=uid) continue;
            auto fds=open_directory(process_fd,"fd");
            if (!fds) {
                if (errno==ENOENT || errno==ESRCH) continue;
                return;
            }
            auto fds_fd=::dirfd(fds.get());
            for (;;) {
                errno=0;
                auto* fd=::readdir(fds.get());
                if (!fd) {
                    if (errno) return;
                    break;
                }
                if (!decimal_name(fd->d_name)) continue;
                if (!descriptors-- || Clock::now()>=deadline) return;
                std::array<char,64> link;
                if (read_link(fds_fd,fd->d_name,link)!=socket) {
                    if (errno==EACCES || errno==EPERM) return;
                    continue;
                }
                auto candidate=executable(process_fd,fds_fd,fd->d_name,socket,mount_namespace);
                if (!candidate.empty() &&
                    !std::ranges::any_of(holders, [&](auto const& h) { return h.path == candidate; }) &&
                    holders.size() < holders.capacity()) {
                    holders.push_back(Holder{std::move(process),std::move(fds),fd->d_name,std::move(candidate)});
                }
                break;
            }
        }
    }

    auto local_process_path(std::uint32_t inode, std::uint32_t uid) -> std::string {
        std::optional<std::uint32_t> gid;
        std::string pkg;
        containers::inplace_vector<std::string, 8> paths;
        local_process_details(inode, uid, gid, pkg, paths);
        return paths.empty() ? std::string{} : std::move(paths.front());
    }
}
