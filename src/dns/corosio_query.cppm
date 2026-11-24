export module dns.corosio_query;
import std;
export import functional;
// Query signatures expose these types and the remaining resolver adapters use
// the exported namespace aliases, so their declarations must be reachable.
export import dns.message;
import dns.input_budget;
import platform.socket_options;
export import capy;
export import corosio;

#ifdef NEXUS_TEST_DNS_RECEIVE
extern "C" void nexus_test_dns_received();
#endif
#ifdef NEXUS_TEST_FAKEIP
extern "C" void nexus_test_fakeip_dns_received();
#endif

namespace dns::detail {
    auto prepare_dns_udp(corosio::udp_socket&,corosio::endpoint const&,
        platform::SocketBinding const&) -> std::error_code;
    auto prepare_dns_tcp(corosio::tcp_socket&,corosio::endpoint const&,
        platform::SocketBinding const&) -> std::error_code;
}

export namespace dns::detail {
    namespace dns_capy = ::capy;
    namespace dns_io = ::corosio;
    enum class UdpError { state, invalid_query, transport, timeout, canceled, truncated, response_limit, protocol, budget_exhausted };
    using ProtectedQuery=functional::move_only_function<dns_capy::task<std::expected<Response,UdpError>>(
        dns_io::io_context&,dns_io::endpoint,QueryMessage const&,std::uint16_t,std::chrono::steady_clock::time_point,
        InputBudget&,std::stop_token) const>;

    using Protection=std::shared_ptr<ProtectedQuery const>;
    struct TransportSnapshot {
        std::uint64_t generation;
        std::vector<std::optional<std::size_t>> outbounds;
        std::vector<Protection> queries;

        // The low bits are address views issued by the configured and
        // endpoint registries. Bit 63 is reserved for local resolver views.
        static constexpr unsigned view_bits=16;
        static constexpr std::uint64_t generation_limit=std::uint64_t{1}<<(63-view_bits);

        [[nodiscard]] auto address_view(std::uint64_t view) const noexcept -> std::uint64_t {
            return (generation<<view_bits)|view;
        }
    };
    using TransportSnapshotRef=std::optional<std::weak_ptr<TransportSnapshot const>>;

    // Single use, single executor. The owner must retain this object until query
    // returns, including after cancel(), and must use an unpredictable transaction ID.
    class UdpQuery {
        dns_io::udp_socket socket_;
        InputBudget& receive_budget_;
        platform::SocketBinding const* binding_;
        bool started_ = false, canceled_ = false;
    public:
        explicit UdpQuery(dns_io::io_context& context,InputBudget* receive_budget=nullptr,platform::SocketBinding const* binding=nullptr)
            : socket_(context),receive_budget_(receive_budget ? *receive_budget : default_upstream_receive_budget()),binding_(binding) {}
        UdpQuery(UdpQuery const&) = delete;
        auto operator=(UdpQuery const&) -> UdpQuery& = delete;
        auto cancel() noexcept -> void { canceled_ = true; socket_.cancel(); }
        auto query(dns_io::endpoint upstream, QueryMessage query,
                   std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<Response, UdpError>> {
            co_return co_await query_borrowed(upstream,query,deadline);
        }
        // The caller retains this immutable question until the operation has
        // completed, including cancellation.
        auto query_borrowed(dns_io::endpoint upstream, QueryMessage const& query,
                   std::chrono::steady_clock::time_point deadline,std::optional<std::uint16_t> transaction_id={})
            -> dns_capy::task<std::expected<Response, UdpError>> {
            if (started_) co_return std::unexpected(UdpError::state);
            started_ = true;
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(UdpError::timeout);
            auto request = encode_query(query);
            if (!request) co_return std::unexpected(UdpError::invalid_query);
            auto id=transaction_id.value_or(query.id);
            (*request)[0]=static_cast<std::uint8_t>(id>>8);(*request)[1]=static_cast<std::uint8_t>(id);
            auto open_error=binding_ ? prepare_dns_udp(socket_,upstream,*binding_) :
                socket_.open(upstream.address().family());
            if (open_error) co_return std::unexpected(UdpError::transport);
            auto finish = [this](UdpError error) -> std::expected<Response, UdpError> {
                socket_.close(); return std::unexpected(error);
            };
            auto [send_error, sent] = co_await dns_io::timeout(
                socket_.send_to(dns_capy::const_buffer(request->data(), request->size()), upstream), deadline);
            if (canceled_) co_return finish(UdpError::canceled);
            if (send_error || sent != request->size() || std::chrono::steady_clock::now() >= deadline)
                co_return finish(send_error == dns_capy::cond::timeout || std::chrono::steady_clock::now() >= deadline ?
                                 UdpError::timeout : UdpError::transport);
            Bytes{}.swap(*request);
            auto accepted = query.edns ? std::max<std::size_t>(query.edns->udp_payload_size,512) : 512u;
            // recv_from returns the copied prefix when a datagram exceeds the
            // buffer. Keep one excess byte so that prefix cannot be accepted
            // as a complete response, or its TC bit trigger TCP fallback.
            auto capacity=std::min<std::size_t>(65535,accepted+1);
            auto lease=receive_budget_.acquire(capacity);if(!lease)co_return finish(UdpError::budget_exhausted);
            auto storage=std::make_unique<std::uint8_t[]>(capacity);
            auto buffer=std::span(storage.get(),capacity);
            for (unsigned received = 0; received < 32; ++received) {
                dns_io::endpoint source;
                auto [error, size] = co_await dns_io::timeout(
                    socket_.recv_from(dns_capy::mutable_buffer(buffer.data(), buffer.size()), source), deadline);
                if (canceled_) co_return finish(UdpError::canceled);
                if (error || std::chrono::steady_clock::now() >= deadline)
                    co_return finish(error == dns_capy::cond::timeout || std::chrono::steady_clock::now() >= deadline ?
                                     UdpError::timeout : UdpError::transport);
#ifdef NEXUS_TEST_DNS_RECEIVE
                nexus_test_dns_received();
#endif
#ifdef NEXUS_TEST_FAKEIP
                nexus_test_fakeip_dns_received();
#endif
                if (source != upstream || size > accepted) continue;
                auto parsed = parse_response(std::span(buffer).first(size), id, query.question);
                if (parsed) { socket_.close(); co_return std::move(*parsed); }
                if (parsed.error() == MessageError::truncated) co_return finish(UdpError::truncated);
            }
            co_return finish(UdpError::response_limit);
        }
        auto query_borrowed(dns_io::endpoint,QueryMessage&&,std::chrono::steady_clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
        auto query_borrowed(dns_io::endpoint,QueryMessage const&&,std::chrono::steady_clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
    };
    // Single use; owner retains this object until the coroutine finishes.
    class TcpQuery {
        dns_io::tcp_socket socket_;
        InputBudget& receive_budget_;
        platform::SocketBinding const* binding_;
        bool started_ = false, canceled_ = false;
        using Clock = std::chrono::steady_clock;
        auto transfer(std::span<std::uint8_t> bytes, bool write, Clock::time_point deadline)
            -> dns_capy::task<std::error_code> {
            while (!bytes.empty()) {
                if (Clock::now() >= deadline) co_return std::make_error_code(std::errc::timed_out);
                auto [error, n] = write ?
                    co_await dns_io::timeout(socket_.write_some(dns_capy::const_buffer(bytes.data(),bytes.size())),deadline) :
                    co_await dns_io::timeout(socket_.read_some(dns_capy::mutable_buffer(bytes.data(),bytes.size())),deadline);
                if (error) co_return error;
                if (!n) co_return std::make_error_code(std::errc::connection_reset);
                bytes = bytes.subspan(n);
            }
            co_return std::error_code{};
        }
    public:
        explicit TcpQuery(dns_io::io_context& context,InputBudget* receive_budget=nullptr,platform::SocketBinding const* binding=nullptr)
            : socket_(context),receive_budget_(receive_budget ? *receive_budget : default_upstream_receive_budget()),binding_(binding) {}
        TcpQuery(TcpQuery const&) = delete;
        auto operator=(TcpQuery const&) -> TcpQuery& = delete;
        auto cancel() noexcept -> void { canceled_ = true; socket_.cancel(); }
        auto query(dns_io::endpoint upstream, QueryMessage query, Clock::time_point deadline)
            -> dns_capy::task<std::expected<Response, UdpError>> {
            co_return co_await query_borrowed(upstream,query,deadline);
        }
        // The caller retains the immutable question through completion.
        auto query_borrowed(dns_io::endpoint upstream, QueryMessage const& query, Clock::time_point deadline,std::optional<std::uint16_t> transaction_id={})
            -> dns_capy::task<std::expected<Response, UdpError>> {
            if (started_) co_return std::unexpected(UdpError::state);
            started_ = true;
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (Clock::now() >= deadline) co_return std::unexpected(UdpError::timeout);
            auto message = encode_query(query);
            if (!message) co_return std::unexpected(UdpError::invalid_query);
            auto id=transaction_id.value_or(query.id);
            (*message)[0]=static_cast<std::uint8_t>(id>>8);(*message)[1]=static_cast<std::uint8_t>(id);
            Bytes frame{static_cast<std::uint8_t>(message->size() >> 8), static_cast<std::uint8_t>(message->size())};
            frame.insert(frame.end(),message->begin(),message->end());
            Bytes{}.swap(*message);
            auto finish = [this](UdpError error) -> std::expected<Response,UdpError> {
                socket_.close(); return std::unexpected(error);
            };
            auto classify = [this,deadline](std::error_code error) {
                if (canceled_) return UdpError::canceled;
                return error == dns_capy::cond::timeout || error == std::errc::timed_out || Clock::now() >= deadline ?
                    UdpError::timeout : UdpError::transport;
            };
            if (binding_ && prepare_dns_tcp(socket_,upstream,*binding_))
                co_return finish(UdpError::transport);
            auto [connect_error] = co_await dns_io::timeout(socket_.connect(upstream),deadline);
            if (connect_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(connect_error));
            auto write_error = co_await transfer(frame,true,deadline);
            if (write_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(write_error));
            Bytes{}.swap(frame);
            std::array<std::uint8_t,2> length{};
            auto read_error = co_await transfer(length,false,deadline);
            if (read_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(read_error));
            auto size = (std::size_t(length[0]) << 8) | length[1];
            if (size < 12) co_return finish(UdpError::protocol);
            auto lease=receive_budget_.acquire(size);if(!lease)co_return finish(UdpError::budget_exhausted);
            auto storage=std::make_unique<std::uint8_t[]>(size);
            auto response=std::span(storage.get(),size);
            read_error = co_await transfer(response,false,deadline);
            if (read_error || canceled_ || Clock::now() >= deadline) co_return finish(classify(read_error));
            auto parsed = parse_response(response,id,query.question);
            if (!parsed) co_return finish(parsed.error()==MessageError::truncated ? UdpError::truncated : UdpError::protocol);
            socket_.close(); co_return std::move(*parsed);
        }
        auto query_borrowed(dns_io::endpoint,QueryMessage&&,Clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
        auto query_borrowed(dns_io::endpoint,QueryMessage const&&,Clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
    };
    class FallbackQuery {
        dns_io::io_context& context_;
        ProtectedQuery const* protection_;
        InputBudget& receive_budget_;
        std::optional<std::stop_source> stop_;
        UdpQuery udp_;
        TcpQuery tcp_;
        bool canceled_ = false, tcp_only_ = false;
    public:
        explicit FallbackQuery(dns_io::io_context& context,bool tcp_only=false,InputBudget* receive_budget=nullptr,
            ProtectedQuery const* protection=nullptr,platform::SocketBinding const* binding=nullptr)
            : context_(context),protection_(protection),
              receive_budget_(receive_budget ? *receive_budget : default_upstream_receive_budget()),
              udp_(context,receive_budget,binding),tcp_(context,receive_budget,binding),tcp_only_(tcp_only) {
            if (protection_) stop_.emplace();
        }
        auto cancel() noexcept -> void {
            canceled_=true;
            if (protection_) stop_->request_stop();
            else {udp_.cancel();tcp_.cancel();}
        }
        auto query(dns_io::endpoint upstream, QueryMessage query,
                   std::chrono::steady_clock::time_point deadline)
            -> dns_capy::task<std::expected<Response,UdpError>> {
            co_return co_await query_borrowed(upstream,query,deadline);
        }
        // The caller owns the query until both UDP and any TCP fallback drain.
        auto query_borrowed(dns_io::endpoint upstream, QueryMessage const& query,
                   std::chrono::steady_clock::time_point deadline,std::optional<std::uint16_t> transaction_id={})
            -> dns_capy::task<std::expected<Response,UdpError>> {
            if (protection_)
                co_return co_await (*protection_)(context_,upstream,query,transaction_id.value_or(query.id),deadline,receive_budget_,stop_->get_token());
            if (tcp_only_) co_return co_await tcp_.query_borrowed(upstream,query,deadline,transaction_id);
            auto result = co_await udp_.query_borrowed(upstream,query,deadline,transaction_id);
            if (canceled_) co_return std::unexpected(UdpError::canceled);
            if (result || result.error()!=UdpError::truncated) co_return result;
            co_return co_await tcp_.query_borrowed(upstream,query,deadline,transaction_id);
        }
        auto query_borrowed(dns_io::endpoint,QueryMessage&&,std::chrono::steady_clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
        auto query_borrowed(dns_io::endpoint,QueryMessage const&&,std::chrono::steady_clock::time_point,std::optional<std::uint16_t> = {})
            -> dns_capy::task<std::expected<Response,UdpError>> = delete;
    };

    [[nodiscard]] auto make_bound_query(platform::SocketBinding binding,bool tcp_only) -> ProtectedQuery;
}
