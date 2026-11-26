module relay:xhttp_inbound_types;
import std;
import http.connect;
import http.header;
import memory.budget;
import rules;
import socks5;
import tls.byte_stream;
import vless;
import vless.server_profile;
import vless.tls_server;
import xhttp.config;
import xhttp.server;
import xhttp.wire;
import relay.stream_relay;
import relay.vless_mux;
import utility;
import capy;
import corosio;
import :types;
import :session_interface;
import :internal_decls;
import :reality_tcp_server;
import :xhttp_http1;

namespace relay::vless_xhttp {
    struct Split {
        capy::async_event change, paired, space;
        xhttp::Pairing sides;
        xhttp::Reassembly input;
        std::uint64_t sequence = 0;
        bool upload_end = false;
        Split(xhttp::Limits limits, std::shared_ptr<memory::Budget> const& budget)
            : sides{Clock::now() + limits.pair_timeout}, input(limits, budget) {}
    };

    struct InboundProfile {
        vless::ServerProfile vless;
        xhttp::Profile transport;
        std::vector<std::string> names;
        std::shared_ptr<memory::Budget> budget;
        std::unordered_map<std::string, std::shared_ptr<Split>, utility::TransparentStringHash, std::equal_to<>> sessions;
        bool secure;
        std::optional<RealityTcpProfile> reality;
        std::size_t streaming = 0;
        auto find(std::string_view key) -> std::pair<std::shared_ptr<Split>, bool> {
            if (auto item = sessions.find(key); item != sessions.end()) return {item->second, false};
            if (sessions.size() + streaming >= transport.limits.sessions) return {};
            auto session = std::make_shared<Split>(transport.limits, budget);
            sessions.emplace(std::string(key), session);
            return {std::move(session), true};
        }
        auto retire(std::string_view key, std::shared_ptr<Split> const& split, bool unpaired_only) noexcept -> void {
            if (unpaired_only && split->sides.download) return;
            split->sides.closed = true;
            split->input.close();
            split->change.set(); split->paired.set(); split->space.set();
            auto entry = sessions.find(key);
            if (entry != sessions.end() && entry->second == split) sessions.erase(entry);
        }
    };

    struct SplitOwner {
        InboundProfile& profile;
        std::string_view id;
        std::shared_ptr<Split> const& split;
        bool active, orphan = false;
        ~SplitOwner() { if (active) profile.retire(id, split, orphan); }
    };

    inline auto read_split(Split& split, std::span<std::uint8_t> output, Deadline until)
        -> capy::task<std::expected<std::size_t, IoError>> {
        while (!output.empty()) {
            if (split.sides.closed) co_return std::unexpected(IoError::io);
            if (auto size = split.input.read(output)) {
                split.space.set();
                co_return size;
            }
            if (split.upload_end) co_return 0;
            auto deadline = until.value_or(Clock::now() + std::chrono::minutes(5));
            if (!split.sides.paired()) deadline = std::min(deadline, split.sides.deadline);
            if (Clock::now() >= deadline) co_return std::unexpected(IoError::timeout);
            split.change.clear();
            auto [error] = co_await corosio::timeout(split.change.wait(), deadline);
            if (error) co_return std::unexpected(IoError::io);
        }
        co_return 0;
    }

    class DownloadStream {
        Lower& lower_;
        Split& split_;
    public:
        DownloadStream(Lower& lower, Split& split) noexcept : lower_(lower), split_(split) {}
        auto cancel() noexcept -> void { lower_.cancel(); }
        auto packet_up() const noexcept -> bool { return true; }
        auto read(std::span<std::uint8_t> output, Deadline until = {}) { return read_split(split_, output, until); }
        auto send(std::span<std::uint8_t const> input, Deadline until = {}) -> capy::task<bool> {
            if (input.empty()) co_return true;
            std::array<char, 2 * sizeof(std::size_t) + 2> head;
            auto [end, error] = std::to_chars(head.data(), head.data() + head.size() - 2, input.size(), 16);
            if (error != std::errc{}) co_return false;
            *end++ = '\r'; *end++ = '\n';
            co_return co_await lower_.send(bytes(std::string_view(head.data(), end)), until) &&
                co_await lower_.send(input, until) && co_await lower_.send(bytes("\r\n"), until);
        }
        auto close_output(Deadline until = {}) -> capy::task<bool> {
            co_return co_await lower_.send(bytes("0\r\n\r\n"), until) && co_await lower_.close_output(until);
        }
    };

    template<class Incoming>
    struct MuxStream {
        Session& session;
        Incoming& incoming;
        auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t, int>> {
            auto result = co_await incoming.read(data);
            if (!result) co_return std::unexpected(1);
            session.touched = Clock::now();
            co_return *result;
        }
        auto write(std::span<std::uint8_t const> data) { session.touched = Clock::now(); return incoming.send(data); }
        auto cancel() noexcept -> void { session.close(); }
    };

    struct MuxLookup {
        auto operator()(Session& session, corosio::io_context& context, std::string name, std::uint16_t port, Clock::time_point until) const {
            return resolve_udp_domain(session, context, std::move(name), port, until);
        }
    };

    template<class Stream>
    auto payload(Session& session, corosio::io_context& context, rules::RouteMatcher const& policy,
                 InboundProfile const& profile, Stream& stream, Clock::time_point deadline) -> capy::task<capy::results<>> {
        struct Done {
            Session& session;
            ~Done() { session.close(); }
        } done{session};
        auto handshake = profile.vless.vless_handshake();
        if (!handshake) co_return capy::results<>{};
        vless::detail::TlsInbound<Socket, false, Stream&> incoming(stream, std::move(*handshake));
        if (!incoming.allow_mux()) co_return capy::results<>{};
        auto header = co_await incoming.read_header(deadline);
        if (!header || session.closed) co_return capy::results<>{};
        bool is_mux = std::holds_alternative<vless::UserId>(*header);
        if (!profile.names.empty()) {
            auto const& id = is_mux ? std::get<vless::UserId>(*header) : std::get<vless::TcpRequest>(*header).user;
            auto index = profile.vless.user_index(id);
            if (!index || !session.admit_principal(profile.names[*index])) co_return capy::results<>{};
        }
        if (is_mux) {
            if (!co_await incoming.complete_dial(true, deadline)) co_return capy::results<>{};
            session.relaying = true;
            MuxStream lower{session, incoming};
            vless_mux::Resolver<Session, MuxLookup> resolver{session, context};
            auto source = source_endpoint(session, policy);
            vless_mux::Server mux(lower, resolver, policy, 256, 65535, source ? &*source : nullptr, session.auth_user,
                session.direct_tcp_options ? &session.direct_tcp_options->binding : nullptr, vless_mux::FlowAccounting(session));
            (void)co_await capy::when_all(vless_mux::read(session, mux), vless_mux::poll(session, mux), vless_mux::timeout(session, mux, resolver));
            co_return capy::results<>{};
        }
        auto const& request = std::get<vless::TcpRequest>(*header);
        socks5::Request target;
        target.status = socks5::Status::accepted; target.port = request.port;
        target.address_type = request.kind == vless::AddressKind::ipv4 ? 1 : request.kind == vless::AddressKind::ipv6 ? 4 : 3;
        target.address_length = static_cast<std::uint8_t>(request.address.size());
        std::ranges::copy(request.address, target.address.begin());
        session.begin_traffic(TrafficProtocol::vless, target.port);
        auto dialed = session.datagram_source ?
            co_await dial_destination(session, context, policy, target, *session.datagram_source, deadline) :
            co_await dial_destination(session, context, policy, target, deadline);
        if (dialed || session.closed) co_return capy::results<>{};
        if (!co_await incoming.complete_dial(true, deadline)) co_return capy::results<>{};
        session.relaying = true;
        auto download = [&]() -> capy::task<capy::results<>> {
            // Downlink completion retires an upload with no wire-level EOF.
            (void)co_await stream_relay::download(session, incoming);
            session.close();
            co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
        };
        if constexpr (requires { stream.packet_up(); }) {
            if (stream.packet_up()) {
                (void)co_await capy::when_all(stream_relay::direction(session, stream_relay::upload(session, incoming)), download());
                co_return capy::results<>{};
            }
        }
        (void)co_await capy::when_all(stream_relay::direction(session, stream_relay::upload(session, incoming)),
            stream_relay::direction(session, stream_relay::download(session, incoming)));
        co_return capy::results<>{};
    }

    inline auto watch_download(Session& session, Lower& lower) -> capy::task<capy::results<>> {
        std::array<std::uint8_t, 1> buffer;
        (void)co_await lower.read(buffer);
        session.close();
        co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
    }

    inline auto response_head(InboundProfile const& profile, std::string_view status, bool stream, bool close) -> std::optional<std::string> {
        auto random = entropy();
        if (!random) return {};
        std::string head = "HTTP/1.1 "; head += status;
        head += "\r\nX-Padding: "; head += xhttp::padding_bytes(profile.transport.padding, *random);
        if (stream) head += "\r\nTransfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\nCache-Control: no-store";
        else head += "\r\nContent-Length: 0";
        if (close) head += "\r\nConnection: close";
        head += "\r\n\r\n";
        return head;
    }

    inline auto read_request(Lower& lower, std::string& input, Clock::time_point deadline)
        -> capy::task<std::optional<RequestHead>> {
        std::array<std::uint8_t, 4096> block;
        for (;;) {
            auto head = http::inspect_header(input);
            if (head.status == http::HeaderStatus::complete) co_return parse_request(head);
            if (head.status != http::HeaderStatus::incomplete) co_return std::nullopt;
            auto size = co_await lower.read(block, deadline);
            if (!size || !*size) co_return std::nullopt;
            input.append(reinterpret_cast<char const*>(block.data()), *size);
        }
    }
}
