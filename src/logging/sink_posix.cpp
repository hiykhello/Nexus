module;
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
module logging.sink;
import std;
import proxy.v4;
import logging.fd;

namespace logging {
    namespace {
        struct StderrSink {
            FileDescriptor file;
            auto write(this StderrSink& self, std::span<SinkRecord const> lines) noexcept -> SinkResult {
                return write_lines(self.file.get(), lines);
            }
            auto reopen(this StderrSink&) noexcept -> SinkResult {
                return std::unexpected(std::make_error_code(std::errc::operation_not_supported));
            }
        };

        struct OpenFile {
            FileDescriptor fd;
            std::uint64_t size;
        };

        auto private_regular(struct stat const& info) noexcept -> bool {
            return S_ISREG(info.st_mode) && info.st_uid == ::geteuid() && (info.st_mode & 07777) == 0600;
        }

        auto open_directory(std::filesystem::path const& parent) -> std::expected<FileDescriptor, std::error_code> {
#ifdef O_PATH
            constexpr auto flags = O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
#else
            constexpr auto flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
#endif
            FileDescriptor directory(::open(parent.is_absolute() ? "/" : ".", flags));
            if (directory.get() < 0) return std::unexpected(system_error(errno));
            for (auto const& component : parent.relative_path()) {
                if (component.empty() || component == ".") continue;
                FileDescriptor next(::openat(directory.get(), component.c_str(), flags));
                if (next.get() < 0) return std::unexpected(system_error(errno));
                directory = std::move(next);
            }
            return directory;
        }

        auto open_file(int directory, char const* name, bool exclusive) noexcept
            -> std::expected<OpenFile, std::error_code> {
            constexpr auto flags = O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK | O_NOCTTY;
            int raw = ::openat(directory, name, flags | O_CREAT | O_EXCL, 0600);
            bool created = raw >= 0;
            struct stat info{};
            if (!created && errno == EEXIST && !exclusive) {
                if (::fstatat(directory, name, &info, AT_SYMLINK_NOFOLLOW) < 0)
                    return std::unexpected(system_error(errno));
                if (S_ISLNK(info.st_mode)) return std::unexpected(system_error(ELOOP));
                if (!private_regular(info) || info.st_nlink != 1)
                    return std::unexpected(system_error(EACCES));
                raw = ::openat(directory, name, flags);
            }

            if (raw < 0) return std::unexpected(system_error(errno));
            FileDescriptor fd(raw);
            if (created && ::fchmod(raw, 0600) < 0) return std::unexpected(system_error(errno));
            if (::fstat(raw, &info) < 0) return std::unexpected(system_error(errno));
            if (!private_regular(info) || info.st_nlink != 1)
                return std::unexpected(system_error(EACCES));
            return OpenFile{std::move(fd), static_cast<std::uint64_t>(info.st_size)};
        }

        struct FileSink {
            FileDescriptor directory;
            OpenFile file;
            std::vector<std::string> names;
            std::string temporary;
            std::uint64_t max_size;

            auto reopen(this FileSink& self) noexcept -> SinkResult {
                auto opened = open_file(self.directory.get(), self.names.front().c_str(), false);
                if (!opened) return std::unexpected(opened.error());
                self.file = std::move(*opened);
                return {};
            }

            auto check_rotation_paths(this FileSink const& self) noexcept -> std::expected<bool, std::error_code> {
                int dir = self.directory.get();
                struct stat active{}, path{};
                if (::fstat(self.file.fd.get(), &active) < 0)
                    return std::unexpected(system_error(errno));
                if (::fstatat(dir, self.names.front().c_str(), &path, AT_SYMLINK_NOFOLLOW) < 0) {
                    if (errno == ENOENT) return false;
                    return std::unexpected(system_error(errno));
                }
                // An external rename leaves the old descriptor writable while
                // the writer drains it before an explicit reopen.
                if (active.st_dev != path.st_dev || active.st_ino != path.st_ino) return false;
                if (!private_regular(path) || path.st_nlink != 1)
                    return std::unexpected(system_error(EACCES));
                for (auto const& name : std::span(self.names).subspan(1)) {
                    if (::fstatat(dir, name.c_str(), &path, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ENOENT) return std::unexpected(system_error(errno));
                    } else if (!private_regular(path) || path.st_nlink != 1) {
                        return std::unexpected(system_error(EACCES));
                    }
                }
                return true;
            }

            auto rotate(this FileSink& self) noexcept -> std::expected<bool, std::error_code> {
                auto ready = self.check_rotation_paths();
                if (!ready || !*ready) return ready;
                int dir = self.directory.get();
                auto temp = self.temporary.c_str();
                auto active = self.names.front().c_str();
                auto next = open_file(dir, temp, true);
                if (!next) return std::unexpected(next.error());

                // Prepare the replacement first. Until the final rename, the
                // active pathname and descriptor both still point to the old file.
                auto abandon = [dir, temp](int error) -> std::expected<bool, std::error_code> {
                    ::unlinkat(dir, temp, 0);
                    return std::unexpected(system_error(error));
                };
                for (auto index = self.names.size() - 1; index > 1; --index) {
                    auto source = self.names[index - 1].c_str();
                    auto destination = self.names[index].c_str();
                    if (::renameat(dir, source, dir, destination) < 0 && errno != ENOENT)
                        return abandon(errno);
                }
                if (self.names.size() > 1) {
                    auto previous = self.names[1].c_str();
                    if (::unlinkat(dir, previous, 0) < 0 && errno != ENOENT) return abandon(errno);
                    if (::linkat(dir, active, dir, previous, 0) < 0) return abandon(errno);
                }
                if (::renameat(dir, temp, dir, active) < 0) {
                    auto error = errno;
                    if (self.names.size() > 1) ::unlinkat(dir, self.names[1].c_str(), 0);
                    return abandon(error);
                }
                self.file = std::move(*next);
                return true;
            }

            auto write(this FileSink& self, std::span<SinkRecord const> lines) noexcept -> SinkResult {
                auto max_size = self.max_size;
                while (!lines.empty()) {
                    // One oversize record may occupy a file on its own.
                    if (max_size && self.file.size &&
                        lines.front().line.size() > max_size - std::min(self.file.size, max_size)) {
                        auto rotated = self.rotate();
                        if (!rotated) return std::unexpected(rotated.error());
                        if (!*rotated) max_size = 0;
                    }
                    std::size_t count = 1;
                    std::uint64_t bytes = lines.front().line.size();
                    for (; count < lines.size(); ++count) {
                        auto remaining = max_size - std::min(self.file.size + bytes, max_size);
                        if (max_size && lines[count].line.size() > remaining) break;
                        bytes += lines[count].line.size();
                    }
                    auto written = write_lines(self.file.fd.get(), lines.first(count));
                    if (!written) {
                        struct stat info{};
                        if (::fstat(self.file.fd.get(), &info) == 0)
                            self.file.size = static_cast<std::uint64_t>(info.st_size);
                        return written;
                    }
                    self.file.size += bytes;
                    lines = lines.subspan(count);
                }
                return {};
            }
        };
    }

    auto off_sink() noexcept -> Sink { return {}; }

    auto stderr_sink(int fd) -> std::expected<Sink, std::error_code> {
        int copy = ::fcntl(fd, F_DUPFD_CLOEXEC, 0);
        if (copy < 0) return std::unexpected(system_error(errno));
        return pro::make_proxy<SinkFacade, StderrSink>(FileDescriptor(copy));
    }

    auto file_sink(FileOptions options) -> std::expected<Sink, std::error_code> {
        auto basename = options.path.filename().string();
        if (basename.empty() || basename == "." || basename == ".." ||
            options.path.native().contains('\0') || options.max_files == 0 || options.max_files > 128)
            return std::unexpected(system_error(EINVAL));

        auto directory = open_directory(options.path.parent_path());
        if (!directory) return std::unexpected(directory.error());

        std::vector<std::string> names;
        names.reserve(options.max_size_bytes ? options.max_files : 1);
        names.push_back(basename);
        if (options.max_size_bytes) {
            for (std::size_t index = 1; index < options.max_files; ++index)
                names.push_back(basename + "." + std::to_string(index));
        }
        auto file = open_file(directory->get(), basename.c_str(), false);
        if (!file) return std::unexpected(file.error());
        return pro::make_proxy<SinkFacade, FileSink>(
            std::move(*directory), std::move(*file), std::move(names), basename + ".rotate", options.max_size_bytes);
    }

    auto write_batch(Sink& sink, std::span<SinkRecord const> lines) noexcept -> SinkResult {
        return sink ? sink->write(lines) : SinkResult{};
    }

    auto write_batch(Sink& sink, std::span<std::string_view const> lines) noexcept -> SinkResult {
        std::array<SinkRecord, batch_capacity> records;
        while (!lines.empty()) {
            auto count = std::min(lines.size(), records.size());
            for (std::size_t index = 0; index < count; ++index) records[index].line = lines[index];
            auto result = write_batch(sink, std::span(records).first(count));
            if (!result) return result;
            lines = lines.subspan(count);
        }
        return {};
    }

    auto reopen_sink(Sink& sink) noexcept -> SinkResult {
        if (sink) return sink->reopen();
        return std::unexpected(system_error(ENOTSUP));
    }
}
