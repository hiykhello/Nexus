module;
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

module rulefile;
import std;
import platform.unique_fd;
import utility;

namespace rulefile {
    namespace {
        auto system_error(std::string_view action) -> std::unexpected<std::string> {
            return std::unexpected(std::string(action) + ": " + std::strerror(errno));
        }

        using Fd = platform::UniqueFd;

        struct TemporaryDirectory {
            int parent;
            std::string name;
            Fd dir;
            struct stat identity{};
            bool verified = false;

            explicit TemporaryDirectory(int parent_fd) : parent(parent_fd) {}
            ~TemporaryDirectory() {
                if (verified && ::unlinkat(dir.get(), "result", 0) < 0 && errno != ENOENT)
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
                        dir.reset(::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
                        if (!dir) return system_error("open temporary directory");
                        if (::fstat(dir.get(), &identity) < 0) return system_error("inspect temporary directory");
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
        if (input.get() < 0) return system_error("open input");
        struct stat info{};
        if (::fstat(input.get(), &info) < 0) return system_error("inspect input");
        if (!S_ISREG(info.st_mode)) return std::unexpected("input must be a regular file");
        if (info.st_size > max_file_bytes) return std::unexpected("input exceeds 32 MiB");
        std::string data;
        char buffer[8192];
        for (;;) {
            auto n = ::read(input.get(), buffer, sizeof(buffer));
            if (n == 0) return data;
            if (n < 0) {
                if (errno == EINTR) continue;
                return system_error("read input");
            }
            if (static_cast<std::size_t>(n) > max_file_bytes - data.size())
                return std::unexpected("input exceeds 32 MiB");
            data.append(buffer, static_cast<std::size_t>(n));
        }
    }

    MappedFile::MappedFile(void* data, std::size_t size, std::uintptr_t handle) noexcept
        : data_(data), size_(size), handle_(handle) {}
    MappedFile::~MappedFile() {
        if (data_ && size_) ::munmap(data_, size_);
    }
    MappedFile::MappedFile(MappedFile&& other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
          handle_(std::exchange(other.handle_, 0)) {}
    auto MappedFile::operator=(MappedFile&& other) noexcept -> MappedFile& {
        if (this != &other) {
            if (data_ && size_) ::munmap(data_, size_);
            data_ = std::exchange(other.data_, nullptr);
            size_ = std::exchange(other.size_, 0);
            handle_ = std::exchange(other.handle_, 0);
        }
        return *this;
    }

    auto map_regular_file(std::string_view path) -> std::expected<MappedFile, std::string> {
        if (path.find('\0') != std::string_view::npos) return std::unexpected("invalid input path");
        std::string name(path);
        int raw_fd = -1;
        for (int tries = 0; tries < 16; ++tries) {
            raw_fd = ::open(name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
            if (raw_fd >= 0 || errno != EINTR) break;
        }
        Fd input(raw_fd);
        if (input.get() < 0) return system_error("open mapped file");
        struct stat info{};
        if (::fstat(input.get(), &info) < 0) return system_error("inspect mapped file");
        if (!S_ISREG(info.st_mode)) return std::unexpected("mapped input must be a regular file");
        if (info.st_size <= 0 || static_cast<std::uint64_t>(info.st_size) > max_file_bytes)
            return std::unexpected("mapped file size must be 1..33554432 bytes");
        auto len = static_cast<std::size_t>(info.st_size);
        // Copy into anonymous private pages + PROT_READ so external in-place truncation never raises SIGBUS.
        void* ptr = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) return system_error("mmap input");
        auto* dst = static_cast<char*>(ptr);
        std::size_t got = 0;
        while (got < len) {
            auto n = ::read(input.get(), dst + got, len - got);
            if (n < 0) {
                if (errno == EINTR) continue;
                int e = errno;
                ::munmap(ptr, len);
                errno = e;
                return system_error("read mapped file");
            }
            if (n == 0) {
                ::munmap(ptr, len);
                return std::unexpected("mapped file changed size during read");
            }
            got += static_cast<std::size_t>(n);
        }
        struct stat after{};
        if (::fstat(input.get(), &after) < 0 || after.st_dev != info.st_dev || after.st_ino != info.st_ino ||
            static_cast<std::size_t>(after.st_size) != len) {
            ::munmap(ptr, len);
            return std::unexpected("mapped file changed during read");
        }
        if (::mprotect(ptr, len, PROT_READ) < 0) {
            int e = errno;
            ::munmap(ptr, len);
            errno = e;
            return system_error("protect mapped file");
        }
        return MappedFile(ptr, len);
    }

    namespace { constexpr std::size_t private_file_capacity=1048577; }
    PrivateFile::PrivateFile(std::unique_ptr<char[]>&& data,std::size_t size) noexcept : data_(std::move(data)),size_(size) {}
    PrivateFile::~PrivateFile() { if (data_) utility::secure_zero(data_.get(),private_file_capacity); }
    PrivateFile::PrivateFile(PrivateFile&& other) noexcept : data_(std::move(other.data_)),size_(std::exchange(other.size_,0)) {}
    auto PrivateFile::operator=(PrivateFile&& other) noexcept -> PrivateFile& {
        if (this!=&other) {
            if (data_) utility::secure_zero(data_.get(),private_file_capacity);
            data_=std::move(other.data_); size_=std::exchange(other.size_,0);
        }
        return *this;
    }
    auto read_private_file(std::string_view path) -> std::expected<PrivateFile,std::string> {
        if (path.empty() || path.front()!='/' || path.find('\0')!=path.npos)
            return std::unexpected("private file path must be absolute");
        std::string name(path);
        Fd input(::open(name.c_str(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        if (input.get()<0) return system_error("open private file");
        struct stat info{};
        if (::fstat(input.get(),&info)<0) return system_error("inspect private file");
        if (!S_ISREG(info.st_mode) || info.st_uid!=::geteuid() || (info.st_mode & 07077)!=0)
            return std::unexpected("private file must be a private regular file owned by the current user");
        if (info.st_size>1048576) return std::unexpected("private file exceeds 1 MiB");
        PrivateFile data(std::make_unique_for_overwrite<char[]>(private_file_capacity),0);
        while (data.size_<private_file_capacity) {
            auto n=::read(input.get(),data.data_.get()+data.size_,private_file_capacity-data.size_);
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
        if (input.get() < 0) return system_error("open password file");
        struct stat info{};
        if (::fstat(input.get(), &info) < 0) return system_error("inspect password file");
        if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid() || (info.st_mode & 07077) != 0)
            return std::unexpected("password file must be a private regular file owned by the current user");
        std::array<char, 257> data{};
        struct WipeBuffer {
            std::array<char, 257>& bytes;
            ~WipeBuffer() { utility::secure_zero(bytes.data(), bytes.size()); }
        } wipe{data};
        std::size_t size = 0;
        while (size < data.size()) {
            auto n = ::read(input.get(), data.data() + size, data.size() - size);
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
        if (parent.get() < 0) return system_error("open output directory");
        TemporaryDirectory temp(parent.get());
        if (auto result = temp.create(); !result) return result;
        Fd file(::openat(temp.dir.get(), "result", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (file.get() < 0) return system_error("create temporary file");
        std::size_t written = 0;
        while (written < data.size()) {
            auto n = ::write(file.get(), data.data() + written, data.size() - written);
            if (n < 0) {
                if (errno == EINTR) continue;
                return system_error("write temporary file");
            }
            if (n == 0) return std::unexpected("write temporary file: no progress");
            written += static_cast<std::size_t>(n);
        }
        if (replace && ::fsync(file.get())<0) return system_error("synchronize temporary file");
        if (!file.close()) return system_error("close temporary file");
        if (replace) {
            if (::renameat(temp.dir.get(),"result",parent.get(),filename.c_str())<0)
                return system_error("replace output");
            return {};
        }
        if (::linkat(temp.dir.get(), "result", parent.get(), filename.c_str(), 0) < 0)
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
