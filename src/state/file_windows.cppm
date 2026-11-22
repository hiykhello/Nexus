export module state.file;
import std;
import state.core;
import platform.os_fs;

export namespace state {
    class File {
        void* handle_;
    public:
        explicit File(void* handle = nullptr) noexcept : handle_(handle) {}
        File(File&& other) noexcept : handle_(other.release()) {}
        auto operator=(this File& self, File&& other) noexcept -> File& {
            std::swap(self.handle_, other.handle_);
            return self;
        }
        ~File();
        auto get(this File const& self) noexcept -> void* { return self.handle_; }
        auto release(this File& self) noexcept -> void* { return std::exchange(self.handle_, nullptr); }
    };

    auto open_directory(std::filesystem::path const& path) -> std::expected<File, StateError>;
    auto open_private_directory(std::filesystem::path const& path) -> std::expected<File, StateError>;
    auto ensure_private_directory(std::filesystem::path const& path) -> std::expected<void, StateError>;
    struct DirectoryEntry { std::string name; std::uint64_t size; bool private_file; };
    auto directory_entries(void* directory, std::function_ref<bool(std::string_view)> accept)
        -> std::expected<std::vector<DirectoryEntry>, StateError>;

    auto failure(Stage stage, int number, bool replaced = false) noexcept -> std::unexpected<StateError> {
        return std::unexpected(StateError{stage, {number, std::system_category()}, replaced});
    }

    auto sync_file(void* handle) noexcept -> int {
        return platform::sync_native_handle(reinterpret_cast<std::uintptr_t>(handle));
    }
}
