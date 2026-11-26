export module http2.server;
import std;
export import http2.headers;
export import memory.budget;
import nghttp2;

export namespace http2 {
    namespace h2 = ::nghttp2;
    // Views are valid only during the callback. All callbacks run synchronously
    // on the caller's thread and must not reenter the session.
    enum class DataDisposition { accepted, pause, failure };
    struct ServerEvents {
        void* context;
        bool (*headers)(void*, std::int32_t, std::span<Header const>, bool trailers, bool end_stream) noexcept;
        DataDisposition (*data)(void*, std::int32_t, std::span<std::byte const>) noexcept;
        bool (*end_stream)(void*, std::int32_t) noexcept;
        void (*closed)(void*, std::int32_t, std::uint32_t) noexcept;
    };
    struct ServerLimits {
        std::uint32_t concurrent_streams;
        std::size_t header_fields;
        std::size_t header_bytes;
        std::size_t response_bytes;
        std::size_t total_response_bytes;
        // Maximum amount of unacknowledged DATA per connection and stream.
        // The value is also the receive window restored by acknowledge/resume.
        std::size_t input_window = 65535;
        // Bound automatically generated PING and SETTINGS acknowledgements
        // when the transport cannot drain output.
        std::size_t outbound_ack_frames = 64;
        // HPACK decoder limit advertised to the peer, and local encoder cap.
        // The decoder starts at the protocol default until SETTINGS applies.
        std::uint32_t decoder_table_bytes = 4096;
        std::size_t encoder_table_bytes = 4096;
        // nghttp2 live allocations, including accounting headers; excludes
        // application buffers, TLS, transport and allocator overhead.
        std::size_t library_memory_bytes = 4 * 1024 * 1024;
        // Limits for application response headers, excluding :status.
        std::size_t response_header_fields = 32;
        std::size_t response_header_bytes = 8192;
        // Shared cap for nghttp2 live allocations, retained response bodies,
        // and logical charges for stream objects, request headers, temporary response fields
        // and the TLS driver's input, ciphertext, output, scratch and transport reservations.
        // Actual header capacities, other TLS buffers, transport, allocator
        // overhead and other transient copies are excluded; this is not a complete budget.
        std::size_t shared_memory_bytes = std::numeric_limits<std::size_t>::max();
        // Bound non-deferred queued outbound control/response frames against flooding.
        std::size_t outbound_queue_frames = 5000;
        // RFC 9113 default 16 KiB frame cap prevents 512 KiB/stream peer buffer bloat on 50 MiB/128 MiB targets.
        std::uint32_t max_frame_size = 16384;
    };
    enum class ServerErrorKind { invalid_argument, invalid_state, allocation, library, reentrant, failed, budget_exceeded };
    struct ServerError { ServerErrorKind kind; int library_code = 0; };
    // Defined only in the allocator boundary test's module implementation unit.
    namespace detail { struct ServerAllocatorTest; }

    class ServerSession {
        friend struct detail::ServerAllocatorTest;
        h2::nghttp2_session* session_ = nullptr;
        struct alignas(std::max_align_t) Allocation { std::size_t size; };
        std::size_t library_limit_, shared_limit_, library_used_ = 0, library_peak_ = 0;
        std::shared_ptr<memory::Budget> budget_;
        bool budget_attached_ = false;

        static auto allocate(std::size_t size, void* context) noexcept -> void*;
        static void deallocate(void* ptr, void* context) noexcept;
        static auto allocate_zero(std::size_t count, std::size_t size, void* context) noexcept -> void*;
        static auto resize(void* ptr, std::size_t size, void* context) noexcept -> void*;

        struct Stream {
            std::int32_t id = 0;
            bool responded = false;
            bool head_request = false;
            bool headers_received = false;
            bool reset_pending = false;
            std::unique_ptr<std::byte[]> response;
            std::size_t response_size = 0;
            std::size_t response_offset = 0;
        };
        static constexpr std::uint32_t kNoSlot = std::numeric_limits<std::uint32_t>::max();
        struct StreamSlot {
            Stream stream{};
            std::uint32_t prev = kNoSlot;
            std::uint32_t next = kNoSlot;
            bool in_use = false;
        };
        HeaderBlock headers_;
        std::size_t max_streams_;
        std::size_t response_limit_;
        std::size_t total_response_limit_;
        std::size_t response_header_fields_, response_header_bytes_;
        std::size_t input_window_;
        std::size_t response_reserved_ = 0, stream_reserved_ = 0, fields_reserved_ = 0, input_reserved_ = 0,
            output_reserved_ = 0, ciphertext_reserved_ = 0, scratch_reserved_ = 0, transport_reserved_ = 0;
    public:
        auto claim_transport() noexcept -> bool { if (active_ || failed_ || terminated_ || transport_claimed_) return false; return transport_claimed_ = true; }
        // One transport owner serializes and releases the allowance after processing borrowed input.
        auto reserve_input(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || input_reserved_ || size > shared_limit_ - shared_memory_used()) return false;
            input_reserved_ = size; return true;
        }
        void release_input() noexcept { input_reserved_ = 0; }
        // The transport owns this reservation until its asynchronous write completes.
        auto reserve_output(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || output_reserved_ || size > shared_limit_ - shared_memory_used()) return false;
            output_reserved_ = size; return true;
        }
        void release_output() noexcept { output_reserved_ = 0; }
        auto reserve_ciphertext(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || ciphertext_reserved_ || size > shared_limit_ - shared_memory_used()) return false;
            ciphertext_reserved_ = size; return true;
        }
        void release_ciphertext() noexcept { ciphertext_reserved_ = 0; }
        auto reserve_scratch(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || scratch_reserved_ || size > shared_limit_ - shared_memory_used()) return false;
            scratch_reserved_ = size; return true;
        }
        void release_scratch() noexcept { scratch_reserved_ = 0; }
        auto reserve_transport(std::size_t size) noexcept -> bool {
            if (active_ || failed_ || !size || transport_reserved_ || size > shared_limit_ - shared_memory_used()) return false;
            transport_reserved_ = size; return true;
        }
        void release_transport() noexcept { transport_reserved_ = 0; }
        // Called outside nghttp2 callbacks; header views are no longer borrowed.
        void fail_transport(bool release = true) noexcept {
            if (!active_) headers_.discard();
            if (release) input_reserved_ = 0;
            failed_ = true; ++revision_;
        }
    private:
        struct FieldsReservation {
            ServerSession& owner;
            ~FieldsReservation() { owner.fields_reserved_ = 0; }
        };
        // Pre-allocated pointer-stable slab sized to max_streams_; nghttp2 retains
        // Stream* in data providers and StreamSlot* in stream user data until close.
        std::vector<StreamSlot> stream_slots_;
        std::uint32_t free_head_ = kNoSlot;
        std::uint32_t active_head_ = kNoSlot;
        std::uint32_t slab_allocated_ = 0;
        std::size_t active_streams_ = 0;
        ServerEvents events_;
        std::uint8_t const* output_ = nullptr;
        std::size_t output_left_ = 0;
        std::uint64_t revision_ = 0;
        bool active_ = false;
        bool failed_ = false, transport_claimed_ = false, terminated_ = false, error_goaway_ = false;
        enum class Shutdown { running, notice, draining };
        Shutdown shutdown_ = Shutdown::running;
        std::int32_t paused_stream_ = 0;
        std::size_t paused_bytes_ = 0;

        [[nodiscard]] auto find_slot(h2::nghttp2_session* session, std::int32_t id) noexcept -> StreamSlot* {
            if (!session || id <= 0) return nullptr;
            auto* slot = static_cast<StreamSlot*>(h2::nghttp2_session_get_stream_user_data(session, id));
            return slot && slot->in_use && slot->stream.id == id ? slot : nullptr;
        }
        [[nodiscard]] auto find_slot(std::int32_t id) noexcept -> StreamSlot* { return find_slot(session_, id); }
        [[nodiscard]] auto acquire_slot(std::int32_t id) noexcept -> StreamSlot* {
            if (active_streams_ >= max_streams_) return nullptr;
            std::uint32_t idx = kNoSlot;
            if (free_head_ != kNoSlot) {
                idx = free_head_;
                free_head_ = stream_slots_[idx].next;
            } else if (slab_allocated_ < stream_slots_.size()) {
                idx = slab_allocated_++;
            } else {
                return nullptr;
            }
            auto& slot = stream_slots_[idx];
            slot.stream = Stream{id};
            slot.in_use = true;
            slot.prev = kNoSlot;
            slot.next = active_head_;
            if (active_head_ != kNoSlot) stream_slots_[active_head_].prev = idx;
            active_head_ = idx;
            ++active_streams_;
            return &slot;
        }
        auto release_slot(StreamSlot* slot) noexcept -> void {
            if (!slot || !slot->in_use) return;
            auto idx = static_cast<std::uint32_t>(slot - stream_slots_.data());
            if (slot->prev != kNoSlot) stream_slots_[slot->prev].next = slot->next;
            else active_head_ = slot->next;
            if (slot->next != kNoSlot) stream_slots_[slot->next].prev = slot->prev;
            slot->stream.response.reset();
            slot->stream = Stream{};
            slot->in_use = false;
            slot->prev = kNoSlot;
            slot->next = free_head_;
            free_head_ = idx;
            --active_streams_;
        }
        auto clear_streams() noexcept -> void {
            for (auto idx = active_head_; idx != kNoSlot;) {
                auto& slot = stream_slots_[idx];
                auto next = slot.next;
                slot.stream.response.reset();
                slot.stream = Stream{};
                slot.in_use = false;
                slot.prev = kNoSlot;
                slot.next = kNoSlot;
                idx = next;
            }
            active_head_ = kNoSlot;
            free_head_ = kNoSlot;
            slab_allocated_ = 0;
            active_streams_ = 0;
        }

        ServerSession(ServerLimits limits, ServerEvents events, std::shared_ptr<memory::Budget> budget);
        auto library_error(int rc) noexcept -> std::unexpected<ServerError>;
        auto response_fields(unsigned status, bool head_request, std::size_t body_size, std::span<Header const> headers,
                             std::array<std::uint8_t, 3>& value, std::array<std::uint8_t, 7>& name) noexcept
            -> std::expected<std::vector<h2::nghttp2_nv>, ServerError>;
        static auto begin(h2::nghttp2_session* session, h2::nghttp2_frame const* frame, void* p) noexcept -> int;
        static auto header(h2::nghttp2_session*, h2::nghttp2_frame const* frame,
                           std::uint8_t const* name, std::size_t n,
                           std::uint8_t const* value, std::size_t v,
                           std::uint8_t, void* p) noexcept -> int;
        static auto frame(h2::nghttp2_session*, h2::nghttp2_frame const* f, void* p) noexcept -> int;
        static auto sent(h2::nghttp2_session*, h2::nghttp2_frame const* frame, void* p) noexcept -> int;
        static auto data(h2::nghttp2_session* session, std::uint8_t, std::int32_t id,
                         std::uint8_t const* bytes, std::size_t length, void* p) noexcept -> int;
        static auto read_response(h2::nghttp2_session*, std::int32_t, std::uint8_t* out,
                                  std::size_t length, std::uint32_t* flags,
                                  h2::nghttp2_data_source* source, void*) noexcept -> h2::nghttp2_ssize;
        static auto closed(h2::nghttp2_session*, std::int32_t id, std::uint32_t code, void* p) noexcept -> int;
    public:
        ServerSession(ServerSession const&) = delete;
        auto operator=(ServerSession const&) -> ServerSession& = delete;
        ~ServerSession();
        static auto create(ServerLimits limits, ServerEvents events, std::shared_ptr<memory::Budget> budget = {})
            -> std::expected<std::unique_ptr<ServerSession>, ServerError>;
        // The caller must deliver this notice and allow time for in-flight
        // requests (normally at least one RTT) before calling finish_shutdown.
        auto start_shutdown() noexcept -> std::expected<void, ServerError>;
        // Queue the final GOAWAY without aborting accepted streams. Continue
        // receiving and draining output until shutdown_complete is true.
        auto finish_shutdown() noexcept -> std::expected<void, ServerError>;
        auto shutdown_complete() const noexcept -> bool;
        // Queue a stream reset. A paused DATA callback must be resumed first;
        // the close event and response-budget release occur during output.
        auto reset_stream(std::int32_t id, std::uint32_t code) noexcept -> std::expected<void, ServerError>;
        // Header names must be lowercase HTTP field names. Pseudo headers,
        // connection-specific fields are not accepted. Content-Length must
        // match the body; for HEAD/304 the caller supplies the selected representation length.
        // nghttp2 copies the fields during submission.
        auto respond_body(std::int32_t id, unsigned status, std::span<std::byte const> body,
                          std::span<Header const> headers = {}) noexcept -> std::expected<void, ServerError>;
        // A final response with no body. Submission is separate from transport
        // delivery; the caller must continue draining output in order.
        auto respond_empty(std::int32_t id, unsigned status, std::span<Header const> headers = {}) noexcept
            -> std::expected<void, ServerError>;
        [[nodiscard]] auto terminated() const noexcept -> bool { return terminated_; }
        [[nodiscard]] auto terminated_by_error() const noexcept -> bool { return terminated_ && error_goaway_; }
        [[nodiscard]] auto response_memory_used() const noexcept -> std::size_t { return response_reserved_; }
        [[nodiscard]] auto library_memory_used() const noexcept -> std::size_t { return library_used_; }
        [[nodiscard]] auto header_memory_charge() const noexcept -> std::size_t { return headers_.memory_charge(); }
        [[nodiscard]] auto stream_memory_charge() const noexcept -> std::size_t { return stream_reserved_; }
        [[nodiscard]] auto input_memory_charge() const noexcept -> std::size_t { return input_reserved_; }
        [[nodiscard]] auto output_memory_charge() const noexcept -> std::size_t { return output_reserved_; }
        [[nodiscard]] auto ciphertext_memory_charge() const noexcept -> std::size_t { return ciphertext_reserved_; }
        [[nodiscard]] auto scratch_memory_charge() const noexcept -> std::size_t { return scratch_reserved_; }
        [[nodiscard]] auto transport_memory_charge() const noexcept -> std::size_t { return transport_reserved_; }
        [[nodiscard]] auto local_memory_used() const noexcept -> std::size_t {
            return library_used_ + response_reserved_ + stream_reserved_ + headers_.memory_charge() + fields_reserved_ +
                input_reserved_ + output_reserved_ + ciphertext_reserved_ + scratch_reserved_ + transport_reserved_;
        }
        [[nodiscard]] auto shared_memory_used() const noexcept -> std::size_t { return local_memory_used() + budget_->reserved(); }
        [[nodiscard]] auto library_memory_peak() const noexcept -> std::size_t { return library_peak_; }
        [[nodiscard]] auto outbound_queue_size() const noexcept -> std::size_t;
        [[nodiscard]] auto revision() const noexcept -> std::uint64_t { return revision_; }
        [[nodiscard]] auto paused_stream() const noexcept -> std::int32_t { return paused_stream_; }
        // A paused input callback has already consumed the bytes that produced
        // its view. The caller retains any unconsumed input and explicitly
        // releases the guard before feeding subsequent bytes.
        auto resume_input(std::int32_t id) noexcept -> std::expected<void, ServerError>;
        auto receive(std::span<std::byte const> input) noexcept -> std::expected<std::size_t, ServerError>;
        // Output is copied before returning; an incomplete nghttp2 chunk stays
        // borrowed internally until later calls finish copying it.
        auto output(std::span<std::byte> destination) noexcept -> std::expected<std::size_t, ServerError>;
    };
}
