module;
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
export module dns.fakeip_history_store;
import std;
import dns.fakeip;
import dns.fakeip_history;
import dns.fakeip_recovery;
import dns.fakeip_shared;
export namespace dns {
    enum class FakeIpHistoryStoreError { invalid, permission, busy, missing, corrupt, rollback, io, authentication, crypto };
    enum class FakeIpHistoryStoreMode { create_new, open_existing };
    class FakeIpHistoryStore {
        int directory_=-1, lock_=-1;
        std::array<std::uint8_t,16> instance_{};
        std::array<std::uint8_t,32> key_{};
        std::uint64_t generation_=0;
        std::optional<FakeIpHistorySnapshot> history_;
        bool failed_=false;
        explicit FakeIpHistoryStore(int directory,int lock,std::span<std::uint8_t const,16> instance,
                                    std::span<std::uint8_t const,32> key) : directory_(directory),lock_(lock) {
            std::ranges::copy(instance,instance_.begin()); std::ranges::copy(key,key_.begin());
        }
        [[nodiscard]] auto read_history() -> std::expected<std::optional<FakeIpHistorySnapshot>,FakeIpHistoryStoreError>;
        [[nodiscard]] auto read_highwater() -> std::expected<std::optional<std::uint64_t>,FakeIpHistoryStoreError>;
        [[nodiscard]] auto write_file(std::string_view temporary,std::string_view final,std::span<std::uint8_t const> bytes)
            -> std::expected<void,FakeIpHistoryStoreError>;
        [[nodiscard]] static auto open_impl(std::string_view path,FakeIpHistoryStoreMode mode,
            std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key,bool from_files,std::optional<FakeIpIpv6Range>)
            -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError>;
    public:
        FakeIpHistoryStore(FakeIpHistoryStore const&)=delete;
        auto operator=(FakeIpHistoryStore const&) -> FakeIpHistoryStore& = delete;
        FakeIpHistoryStore(FakeIpHistoryStore&& other) noexcept;
        auto operator=(FakeIpHistoryStore&& other) noexcept -> FakeIpHistoryStore&;
        ~FakeIpHistoryStore();
        [[nodiscard]] static auto open(std::string_view path,std::span<std::uint8_t const,16> instance,
            std::span<std::uint8_t const,32> key, FakeIpHistoryStoreMode mode)
            -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError>;
        // Read the fixed credentials from the locked store directory using
        // strict owner/mode/link checks, then open the store with them.
        [[nodiscard]] static auto open_with_credentials(std::string_view path, FakeIpHistoryStoreMode mode,
            std::optional<FakeIpIpv6Range> ipv6={})
            -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError>;
        [[nodiscard]] auto generation() const noexcept -> std::uint64_t { return generation_; }
        [[nodiscard]] auto failed() const noexcept -> bool { return failed_; }
        [[nodiscard]] auto history() const noexcept -> std::optional<FakeIpHistorySnapshot> const& { return history_; }
        // The directory inode and owner.lock are locked until destruction. All
        // owners must cooperate; replacing the directory can still split ownership.
        // A new snapshot must retain all existing ranges and protection periods.
        // I/O failure poisons the store; destroy and reopen before recovery.
        [[nodiscard]] auto commit(FakeIpHistorySnapshot const& snapshot) -> std::expected<void,FakeIpHistoryStoreError>;
    };

    using FakeIpStartupError = std::variant<FakeIpHistoryStoreError,FakeIpRecoveryError>;
    // Consumes the locked store. History is committed before an owner is
    // returned; the resulting owner and its handles retain the lock. The
    // quarantine starts after commit, so a slow fsync cannot shorten it.
    [[nodiscard]] auto start_fakeip(FakeIpHistoryStore&& store,FakeIpRecoveryPool current,
        std::chrono::seconds transit) -> std::expected<std::shared_ptr<FakeIpShared>,FakeIpStartupError>;
}
