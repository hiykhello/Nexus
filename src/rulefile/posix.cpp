module;
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

module rulefile;
import std;
import rules;

namespace rulefile {
    namespace {
        auto system_error(std::string_view action) -> std::unexpected<std::string> {
            return std::unexpected(std::string(action) + ": " + std::strerror(errno));
        }

        struct Fd {
            int value = -1;
            explicit Fd(int fd = -1) : value(fd) {}
            Fd(Fd const&) = delete;
            auto operator=(Fd const&) -> Fd& = delete;
            ~Fd() { if (value >= 0) ::close(value); }
            auto close_checked() -> bool {
                auto fd = std::exchange(value, -1);
                return fd < 0 || ::close(fd) == 0;
            }
        };

        struct TemporaryDirectory {
            int parent;
            std::string name;
            Fd dir;
            struct stat identity{};
            bool verified = false;

            explicit TemporaryDirectory(int parent_fd) : parent(parent_fd) {}
            ~TemporaryDirectory() {
                if (verified && ::unlinkat(dir.value, "result", 0) < 0 && errno != ENOENT)
                    std::cerr << "warning: cannot remove temporary file: " << std::strerror(errno) << '\n';
                if (!name.empty()) {
                    struct stat current{};
                    if (!verified || ::fstatat(parent, name.c_str(), &current, AT_SYMLINK_NOFOLLOW) < 0 ||
                        current.st_dev != identity.st_dev || current.st_ino != identity.st_ino) {
                        std::cerr << "warning: cannot verify temporary directory " << name << " for cleanup\n";
                    } else if (::unlinkat(parent, name.c_str(), AT_REMOVEDIR) < 0 && errno != ENOENT) {
                        std::cerr << "warning: cannot remove temporary directory " << name << ": " << std::strerror(errno) << '\n';
                    }
                }
            }

            auto create() -> std::expected<void, std::string> {
                auto prefix = ".nexus-rule-convert-" + std::to_string(::getpid()) + "-";
                for (unsigned i = 0; i < 128; ++i) {
                    auto candidate = prefix + std::to_string(i);
                    if (::mkdirat(parent, candidate.c_str(), 0700) == 0) {
                        name = std::move(candidate);
                        dir.value = ::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                        if (dir.value < 0) return system_error("open temporary directory");
                        if (::fstat(dir.value, &identity) < 0) return system_error("inspect temporary directory");
                        if (identity.st_uid != ::geteuid() || (identity.st_mode & 077) != 0)
                            return std::unexpected("temporary directory is not private");
                        verified = true;
                        return {};
                    }
                    if (errno != EEXIST) return system_error("create temporary directory");
                }
                return std::unexpected("could not allocate a temporary directory");
            }
        };
    }

    auto read_regular_file(std::string_view path) -> std::expected<std::string, std::string> {
        if (path.find('\0') != std::string_view::npos) return std::unexpected("invalid input path");
        std::string name(path);
        Fd input(::open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK));
        if (input.value < 0) return system_error("open input");
        struct stat info{};
        if (::fstat(input.value, &info) < 0) return system_error("inspect input");
        if (!S_ISREG(info.st_mode)) return std::unexpected("input must be a regular file");
        if (info.st_size > ::rules::max_input_bytes) return std::unexpected("input exceeds 1 MiB");
        std::string data;
        char buffer[8192];
        for (;;) {
            auto n = ::read(input.value, buffer, sizeof(buffer));
            if (n == 0) return data;
            if (n < 0) {
                if (errno == EINTR) continue;
                return system_error("read input");
            }
            if (static_cast<std::size_t>(n) > ::rules::max_input_bytes - data.size())
                return std::unexpected("input exceeds 1 MiB");
            data.append(buffer, static_cast<std::size_t>(n));
        }
    }

    namespace { constexpr std::size_t private_file_capacity=1048577; }
    PrivateFile::PrivateFile(std::unique_ptr<char[]>&& data,std::size_t size) noexcept : data_(std::move(data)),size_(size) {}
    PrivateFile::~PrivateFile() { if (data_) explicit_bzero(data_.get(),private_file_capacity); }
    PrivateFile::PrivateFile(PrivateFile&& other) noexcept : data_(std::move(other.data_)),size_(std::exchange(other.size_,0)) {}
    auto PrivateFile::operator=(PrivateFile&& other) noexcept -> PrivateFile& {
        if (this!=&other) {
            if (data_) explicit_bzero(data_.get(),private_file_capacity);
            data_=std::move(other.data_); size_=std::exchange(other.size_,0);
        }
        return *this;
    }
    auto read_private_file(std::string_view path) -> std::expected<PrivateFile,std::string> {
        if (path.empty() || path.front()!='/' || path.find('\0')!=path.npos)
            return std::unexpected("private file path must be absolute");
        std::string name(path);
        Fd input(::open(name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        if (input.value<0) return system_error("open private file");
        struct stat info{};
        if (::fstat(input.value,&info)<0) return system_error("inspect private file");
        if (!S_ISREG(info.st_mode) || info.st_uid!=::geteuid() || (info.st_mode & 07077)!=0)
            return std::unexpected("private file must be a private regular file owned by the current user");
        if (info.st_size>1048576) return std::unexpected("private file exceeds 1 MiB");
        PrivateFile data(std::make_unique_for_overwrite<char[]>(private_file_capacity),0);
        while (data.size_<private_file_capacity) {
            auto n=::read(input.value,data.data_.get()+data.size_,private_file_capacity-data.size_);
            if (n==0) break;
            if (n<0) { if (errno==EINTR) continue; return system_error("read private file"); }
            data.size_+=static_cast<std::size_t>(n);
        }
        if (!data.size_ || data.size_>1048576) return std::unexpected("private file must contain 1..1048576 bytes");
        return data;
    }

    auto read_password_file(std::string_view path) -> std::expected<std::string, std::string> {
        if (path.empty() || path.front() != '/' || path.find('\0') != path.npos)
            return std::unexpected("password path must be absolute");
        std::string name(path);
        Fd input(::open(name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        if (input.value < 0) return system_error("open password file");
        struct stat info{};
        if (::fstat(input.value, &info) < 0) return system_error("inspect password file");
        if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid() || (info.st_mode & 07077) != 0)
            return std::unexpected("password file must be a private regular file owned by the current user");
        std::array<char, 257> data{};
        struct WipeBuffer {
            std::array<char, 257>& bytes;
            ~WipeBuffer() { explicit_bzero(bytes.data(), bytes.size()); }
        } wipe{data};
        std::size_t size = 0;
        while (size < data.size()) {
            auto n = ::read(input.value, data.data() + size, data.size() - size);
            if (n == 0) break;
            if (n < 0) {
                if (errno == EINTR) continue;
                return system_error("read password file");
            }
            size += static_cast<std::size_t>(n);
        }
        if (size && data[size - 1] == '\n') --size;
        if (size == 0 || size > 255 || !std::all_of(data.begin(), data.begin() + size,
            [](unsigned char c) { return c >= 32 && c <= 126; }))
            return std::unexpected("password must be 1..255 printable ASCII bytes with at most one trailing newline");
        return std::string(data.data(), size);
    }

    static auto publish(std::string_view path, std::string_view data, bool replace) -> std::expected<void, std::string> {
        if (path.find('\0') != std::string_view::npos) return std::unexpected("invalid output path");
        std::filesystem::path output{std::string(path)};
        auto filename = output.filename().string();
        if (filename.empty() || filename == "." || filename == "..") return std::unexpected("invalid output filename");
        auto parent_path = output.parent_path().empty() ? std::filesystem::path(".") : output.parent_path();
        Fd parent(::open(parent_path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
        if (parent.value < 0) return system_error("open output directory");
        TemporaryDirectory temp(parent.value);
        if (auto result = temp.create(); !result) return result;
        Fd file(::openat(temp.dir.value, "result", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (file.value < 0) return system_error("create temporary file");
        std::size_t written = 0;
        while (written < data.size()) {
            auto n = ::write(file.value, data.data() + written, data.size() - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                return system_error("write temporary file");
            }
            if (n == 0) return std::unexpected("write temporary file: no progress");
            written += static_cast<std::size_t>(n);
        }
        if (replace && ::fsync(file.value)<0) return system_error("synchronize temporary file");
        if (!file.close_checked()) return system_error("close temporary file");
        if (replace) {
            if (::renameat(temp.dir.value,"result",parent.value,filename.c_str())<0)
                return system_error("replace output");
            return {};
        }
        if (::linkat(temp.dir.value, "result", parent.value, filename.c_str(), 0) < 0)
            return system_error("publish output (existing files are never overwritten)");
        return {};
    }
    auto publish_new_file(std::string_view path, std::string_view data) -> std::expected<void,std::string> {
        return publish(path,data,false);
    }
    auto replace_file(std::string_view path, std::string_view data) -> std::expected<void,std::string> {
        return publish(path,data,true);
    }

}
