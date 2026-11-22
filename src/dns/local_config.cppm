export module dns.local_config;
import std;
import nexus.compat;
import dns.message;

export namespace dns {
    enum class LocalConfigError { too_large, too_many_records, invalid_address, invalid_name, invalid_option, no_servers, io_error };
    struct LocalServer { std::array<std::uint8_t,16> address{}; bool ipv6=false; std::uint16_t port=53; auto operator==(LocalServer const&) const -> bool = default; };
    struct LocalHost { std::string name; LocalServer address; auto operator==(LocalHost const&) const -> bool = default; };
    struct LocalConfig {
        std::vector<LocalServer> servers;
        std::vector<std::string> search;
        std::uint32_t timeout_seconds=5, attempts=2, ndots=1;
        bool rotate=false, use_tcp=false;
        auto operator==(LocalConfig const&) const -> bool = default;
    };
    struct LocalSnapshot { LocalConfig config; std::vector<LocalHost> hosts; auto operator==(LocalSnapshot const&) const -> bool = default; };
    // Parse bounded snapshots; this module does not perform file or network I/O.
    [[nodiscard]] auto is_usable_system_dns_server(LocalServer const& server) noexcept -> bool;
    [[nodiscard]] auto parse_local_resolv(std::string_view input) -> std::expected<LocalConfig,LocalConfigError>;
    [[nodiscard]] auto parse_local_hosts(std::string_view input) -> std::expected<std::vector<LocalHost>,LocalConfigError>;
    [[nodiscard]] auto parse_local_address(std::string_view input) -> std::optional<LocalServer>;
    // The original spelling preserves the absolute DNS root marker.
    [[nodiscard]] auto local_search_candidates(LocalConfig const&,std::string_view input,
        std::string const& normalized) -> std::vector<std::string>;
    [[nodiscard]] auto normalize_local_name(std::string_view input) -> std::optional<std::string>;
    // Synchronous bounded file I/O; call during initialization or on an I/O worker,
    // not on a network executor. Both files must be readable.
    [[nodiscard]] auto load_local_snapshot(std::string_view resolv_path, std::string_view hosts_path)
        -> std::expected<LocalSnapshot,LocalConfigError>;
    // File I/O runs on one background thread. A query retains its acquired
    // immutable version; failed reads publish an empty snapshot, not stale data.
    class LocalSnapshotSource {
        std::string resolv_path_, hosts_path_;
        std::chrono::milliseconds interval_;
        nexus::atomic_shared_ptr<LocalSnapshot const> current_;
        std::mutex mutex_;
        std::condition_variable_any wake_;
        std::jthread thread_;
        auto refresh() noexcept -> void;
    public:
        LocalSnapshotSource(std::string resolv_path,std::string hosts_path,std::chrono::milliseconds interval=std::chrono::seconds(1));
        LocalSnapshotSource(LocalSnapshotSource const&)=delete;
        auto operator=(LocalSnapshotSource const&) -> LocalSnapshotSource& = delete;
        [[nodiscard]] auto acquire() const noexcept -> std::shared_ptr<LocalSnapshot const>;
    };
    [[nodiscard]] auto system_local_snapshots() -> LocalSnapshotSource&;
}

namespace dns::detail {
    [[nodiscard]] auto read_local_config_file(std::string_view path, std::size_t max_bytes)
        -> std::expected<std::string, LocalConfigError>;
}
