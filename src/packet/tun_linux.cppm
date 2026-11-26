export module packet.tun_linux;
import std;

export namespace packet {
    enum class TunError { invalid_name,invalid_device,already_claimed,wrong_namespace };
    enum class TunFdOwnership { borrow,adopt };
    struct TunCreateOptions {
        bool vnet_hdr = false;
        bool multi_queue = false;
    };
    struct TunIdentity { int fd=-1; std::uint64_t namespace_id=0; std::array<char,16> name{}; };
    using TunFailure = std::variant<TunError, std::error_code>;
    // Owns one nonpersistent Linux TUN device, created exclusively in the
    // caller's current network namespace. No addresses, routes or MTU are set.
    // A descriptor borrower must finish all I/O before this owner is closed or moved.
    class LinuxTun {
        int fd_=-1;
        std::array<char,16> name_{};
        bool network_claimed_=false;
        bool network_claimable_=true;
        bool restore_blocking_=false;
        bool vnet_hdr_=false;
        int orig_status_flags_=0;
        std::uint64_t generation_=1;
        // Zero is a terminal exhausted state; a generation is never reused.
        auto invalidate() noexcept -> void { if (generation_) generation_=generation_==std::numeric_limits<std::uint64_t>::max() ? 0 : generation_+1; }
        [[nodiscard]] auto inspect() const -> std::expected<TunIdentity,TunFailure>;
        LinuxTun(int fd,std::array<char,16> name,bool network_claimable=true,
            bool restore_blocking=false,int orig_status_flags=0,bool vnet_hdr=false) noexcept
            : fd_(fd),name_(name),network_claimable_(network_claimable),
              restore_blocking_(restore_blocking),vnet_hdr_(vnet_hdr),orig_status_flags_(orig_status_flags) {}
    public:
        // Sealed proof of this newly created, nonpersistent owner's identity.
        // Borrowing consumers must stop before the owner moves or closes.
        class NetworkToken {
            friend class LinuxTun;
            LinuxTun* owner_=nullptr;
            TunIdentity identity_;
            std::uint64_t generation_=0;
            NetworkToken(LinuxTun& owner,TunIdentity identity) noexcept : owner_(&owner),identity_(identity),generation_(owner.generation_) {}
        public:
            NetworkToken(NetworkToken const&)=delete;
            auto operator=(NetworkToken const&) -> NetworkToken& = delete;
            NetworkToken(NetworkToken&& other) noexcept : owner_(std::exchange(other.owner_,nullptr)),identity_(other.identity_),generation_(other.generation_) {}
            auto operator=(NetworkToken&&) -> NetworkToken& = delete;
            [[nodiscard]] auto inspect() const -> std::expected<TunIdentity,TunFailure>;
            [[nodiscard]] auto native_handle() const noexcept -> int {
                return owner_ && owner_->generation_==generation_ && owner_->network_claimed_ && owner_->native_handle()==identity_.fd ? identity_.fd : -1;
            }
            [[nodiscard]] auto identity() const noexcept -> TunIdentity const& { return identity_; }
            [[nodiscard]] auto close_device() noexcept -> bool {
                if (native_handle()>=0) owner_->close();
                // claim_network reserves one generation for close. Moving away
                // and assigning back consume additional generations permanently.
                return owner_ && generation_ && owner_->generation_==generation_+1 && owner_->network_claimed_ && owner_->native_handle()<0;
            }
        };
        [[nodiscard]] auto claim_network() & -> std::expected<NetworkToken,TunFailure>;
        auto claim_network() && -> std::expected<NetworkToken,TunFailure> = delete;
        LinuxTun(LinuxTun const&)=delete;
        auto operator=(LinuxTun const&) -> LinuxTun& = delete;
        LinuxTun(LinuxTun&& other) noexcept;
        auto operator=(LinuxTun&& other) noexcept -> LinuxTun&;
        ~LinuxTun();
        // Empty selects a kernel-generated name; '%' templates are rejected.
        [[nodiscard]] static auto create(std::string_view name={}) -> std::expected<LinuxTun,TunFailure>;
        [[nodiscard]] static auto create(std::string_view name, TunCreateOptions options) -> std::expected<LinuxTun,TunFailure>;
        // An attached fd already carries unframed IP packets in nonblocking
        // mode. Borrowing duplicates it without changing status flags. Adoption
        // transfers the original fd on success. The caller manages link state.
        [[nodiscard]] static auto attach(int fd,TunFdOwnership) -> std::expected<LinuxTun,TunFailure>;
        // External mobile descriptors (e.g. Android VpnService.establish()) may
        // lack CAP_NET_ADMIN ioctl inspection or O_NONBLOCK pre-applied.
        [[nodiscard]] static auto attach_external(int fd,TunFdOwnership,bool verify_tun_ioctl=true)
            -> std::expected<LinuxTun,TunFailure>;
        [[nodiscard]] auto native_handle() const noexcept -> int { return fd_; }
        [[nodiscard]] auto name() const noexcept -> std::string_view;
        [[nodiscard]] auto vnet_hdr() const noexcept -> bool { return vnet_hdr_; }
        auto close() noexcept -> void;
    };
}
