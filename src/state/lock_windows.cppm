export module state.lock;
import std;
import state.core;

export namespace state {
    class InstanceLock {
        void* directory_;
        void* lock_;
        InstanceLock(void* directory, void* lock) noexcept : directory_(directory), lock_(lock) {}
    public:
        InstanceLock(InstanceLock&& other) noexcept;
        ~InstanceLock();
        [[nodiscard]] static auto open(std::filesystem::path const& path) -> std::expected<InstanceLock, StateError>;
        [[nodiscard]] static auto open_child(std::filesystem::path const& root, std::string const& name)
            -> std::expected<InstanceLock, StateError>;
        [[nodiscard]] static auto open_rulesets(std::filesystem::path const& root) -> std::expected<InstanceLock, StateError>;
        [[nodiscard]] auto directory(this InstanceLock const& self) noexcept -> void* { return self.directory_; }
    };
}
