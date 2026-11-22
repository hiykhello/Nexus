export module state.owner;
import std;
export import state.snapshot;

export namespace state {
    struct OwnerLimits {
        std::size_t requests = 32;
        // Accepted payload capacity, including the active request. Existing
        // snapshot verification uses one separately bounded payload buffer.
        std::size_t bytes = 4 * 1024 * 1024;
    };

    using CommitResult = std::expected<CommitReceipt, StateError>;

    struct Ticket {
        CommitState state = CommitState::accepted;
        // Empty means the request ended before publication.
        std::future<std::optional<CommitState>> publication;
        std::future<CommitResult> result;
    };

    struct DrainResult {
        bool completed;
        std::size_t pending;
        std::size_t bytes;
    };

    // The owner exclusively holds the instance and performs filesystem I/O.
    // A submitter is responsible for immutable content, revision ordering and
    // selecting the epoch at which its snapshot was captured.
    class StateOwner {
        struct Impl;
        std::unique_ptr<Impl> impl_;
        explicit StateOwner(std::unique_ptr<Impl> impl) noexcept;

    public:
        ~StateOwner();
        [[nodiscard]] static auto start(InstanceLock instance, SnapshotSpec spec, OwnerLimits limits = {},
                                        std::uint64_t initial_epoch = 0)
            -> std::expected<std::unique_ptr<StateOwner>, StateError>;
        [[nodiscard]] auto submit(this StateOwner& self, std::uint64_t revision, std::uint64_t epoch, Bytes payload)
            -> std::expected<Ticket, StateError>;
        [[nodiscard]] auto current_epoch(this StateOwner const& self) noexcept -> std::uint64_t;
        [[nodiscard]] auto advance_epoch(this StateOwner& self) -> std::expected<std::uint64_t, StateError>;
        [[nodiscard]] auto drain(this StateOwner& self, Clock::time_point deadline) -> DrainResult;
    };
}
