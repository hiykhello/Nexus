export module rulefile;
import std;

export namespace rulefile {
    inline constexpr std::size_t max_file_bytes = 33554432;
    inline constexpr std::size_t max_mapped_file_bytes = 268435456;

    // Read-only memory-mapped regular file; unmaps on destruction.
    class MappedFile {
        void* data_ = nullptr;
        std::size_t size_ = 0;
        std::uintptr_t handle_ = 0;
        MappedFile(void* data, std::size_t size, std::uintptr_t handle = 0) noexcept;
        friend auto map_regular_file(std::string_view path, std::size_t max_bytes) -> std::expected<MappedFile, std::string>;
    public:
        MappedFile() = default;
        ~MappedFile();
        MappedFile(MappedFile const&) = delete;
        auto operator=(MappedFile const&) -> MappedFile& = delete;
        MappedFile(MappedFile&&) noexcept;
        auto operator=(MappedFile&&) noexcept -> MappedFile&;
        [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t const> {
            return {static_cast<std::uint8_t const*>(data_), size_};
        }
        [[nodiscard]] auto view() const noexcept -> std::string_view {
            return {static_cast<char const*>(data_), size_};
        }
        [[nodiscard]] auto size() const noexcept -> std::size_t { return size_; }
        [[nodiscard]] auto empty() const noexcept -> bool { return size_ == 0; }
    };
    [[nodiscard]] auto map_regular_file(std::string_view path,
        std::size_t max_bytes = max_mapped_file_bytes) -> std::expected<MappedFile, std::string>;

    // Binary private file storage; erases the whole allocation on destruction.
    class PrivateFile {
        std::unique_ptr<char[]> data_;
        std::size_t size_ = 0;
        explicit PrivateFile(std::unique_ptr<char[]>&& data,std::size_t size) noexcept;
        friend auto read_private_file(std::string_view path) -> std::expected<PrivateFile,std::string>;
    public:
        ~PrivateFile();
        PrivateFile(PrivateFile const&) = delete;
        auto operator=(PrivateFile const&) -> PrivateFile& = delete;
        PrivateFile(PrivateFile&&) noexcept;
        auto operator=(PrivateFile&&) noexcept -> PrivateFile&;
        [[nodiscard]] auto bytes() const noexcept -> std::span<char const> { return {data_.get(),size_}; }
    };
    // Absolute path, final component not a symlink, owned by current user, no
    // group/other or special permissions; binary content limited to 1 MiB.
    [[nodiscard]] auto read_private_file(std::string_view path) -> std::expected<PrivateFile,std::string>;
    [[nodiscard]] auto read_regular_file(std::string_view path,
        std::size_t max_bytes = max_file_bytes) -> std::expected<std::string, std::string>;
    // Reads a private, owner-controlled ASCII secret from an absolute path.
    [[nodiscard]] auto read_password_file(std::string_view path) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto publish_new_file(std::string_view path, std::string_view data) -> std::expected<void, std::string>;
    [[nodiscard]] auto replace_file(std::string_view path, std::string_view data) -> std::expected<void, std::string>;
}
