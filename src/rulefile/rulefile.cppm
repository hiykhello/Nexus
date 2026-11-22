export module rulefile;
import std;

export namespace rulefile {
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
    [[nodiscard]] auto read_regular_file(std::string_view path) -> std::expected<std::string, std::string>;
    // Reads a private, owner-controlled ASCII secret from an absolute path.
    [[nodiscard]] auto read_password_file(std::string_view path) -> std::expected<std::string, std::string>;
    [[nodiscard]] auto publish_new_file(std::string_view path, std::string_view data) -> std::expected<void, std::string>;
    [[nodiscard]] auto replace_file(std::string_view path, std::string_view data) -> std::expected<void, std::string>;
}
