export module shadowtls.stream;
import std;
import shadowtls.v3;
import crypto;
import tls.profiles;
import tls.fingerprint;
import tls.client_session_handshake;
import net.socket_stream;
import net.stream_relay;
import platform.ip_address;
import nexus.thirdparty.capy;

export namespace shadowtls {
    using StreamClock = std::chrono::steady_clock;

    template<class Socket>
    class VerifiedSocket {
        net::SocketByteStream<Socket> transport_;
        VerifiedStream crypto_;
        TlsRecordReader reader_;
        std::vector<std::uint8_t> unread_wire_;
        std::size_t unread_pos_ = 0;
        std::vector<std::uint8_t> decoded_;
        std::size_t decoded_pos_ = 0;
        nex::capy::async_mutex write_lock_;
        bool alert_sent_ = false;
        bool eof_ = false;
        bool canceled_ = false;

    public:
        VerifiedSocket(Socket& socket, VerifiedStream crypto,
                       std::vector<std::uint8_t> unread_wire = {},
                       std::vector<std::uint8_t> initial_payload = {}) noexcept
            : transport_(socket), crypto_(std::move(crypto)),
              unread_wire_(std::move(unread_wire)), decoded_(std::move(initial_payload)) {}

        auto cancel() noexcept -> void {
            canceled_ = true;
            transport_.cancel();
        }

        auto send(std::span<std::uint8_t const> bytes, net::StreamDeadline deadline = {}) -> nex::capy::task<bool> {
            if (canceled_) co_return false;
            auto encoded = crypto_.encode(bytes);
            if (!encoded) { cancel(); co_return false; }
            if (encoded->empty()) co_return true;
            auto [ec, guard] = co_await write_lock_.scoped_lock();
            if (ec || canceled_) co_return false;
            auto ok = co_await transport_.send(*encoded, deadline);
            if (!ok) cancel();
            co_return ok;
        }

        auto read(std::span<std::uint8_t> output, net::StreamDeadline deadline = {})
            -> nex::capy::task<std::expected<std::size_t, std::string>> {
            if (output.empty()) co_return 0;
            for (;;) {
                if (decoded_pos_ < decoded_.size()) {
                    auto n = std::min(output.size(), decoded_.size() - decoded_pos_);
                    std::copy_n(decoded_.begin() + static_cast<std::ptrdiff_t>(decoded_pos_), n, output.begin());
                    decoded_pos_ += n;
                    if (decoded_pos_ == decoded_.size()) {
                        decoded_.clear();
                        decoded_pos_ = 0;
                    }
                    co_return n;
                }
                if (eof_) co_return 0;
                if (canceled_) co_return std::unexpected("ShadowTLS stream canceled");
                while (unread_pos_ < unread_wire_.size()) {
                    auto step = reader_.feed(std::span(unread_wire_).subspan(unread_pos_));
                    unread_pos_ += step.consumed;
                    if (unread_pos_ == unread_wire_.size()) {
                        unread_wire_.clear();
                        unread_pos_ = 0;
                    }
                    if (step.status == RecordStatus::malformed || step.status == RecordStatus::too_large) {
                        cancel();
                        co_return std::unexpected("malformed ShadowTLS TLS record");
                    }
                    if (step.status != RecordStatus::complete) continue;
                    auto dec = crypto_.decode(step.record);
                    reader_.consume();
                    if (dec.status == VerifiedStream::DecodeStatus::ignored_handshake) continue;
                    if (dec.status == VerifiedStream::DecodeStatus::alert_closed) {
                        eof_ = true;
                        co_return 0;
                    }
                    if (dec.status != VerifiedStream::DecodeStatus::payload) {
                        cancel();
                        co_return std::unexpected("ShadowTLS record authentication failed");
                    }
                    decoded_.assign(dec.payload.begin(), dec.payload.end());
                    decoded_pos_ = 0;
                    break;
                }
                if (decoded_pos_ < decoded_.size() || eof_) continue;
                unread_wire_.resize(16640);
                unread_pos_ = 0;
                auto got = co_await transport_.read(unread_wire_, deadline);
                if (!got) {
                    cancel();
                    co_return std::unexpected("ShadowTLS socket read failed");
                }
                if (!*got) {
                    unread_wire_.clear();
                    if (reader_.pending()) {
                        cancel();
                        co_return std::unexpected("truncated ShadowTLS TLS record");
                    }
                    eof_ = true;
                    co_return 0;
                }
                unread_wire_.resize(*got);
            }
        }

        auto close_output(net::StreamDeadline deadline = {}) -> nex::capy::task<bool> {
            if (canceled_) co_return false;
            auto [ec, guard] = co_await write_lock_.scoped_lock();
            if (ec || canceled_) co_return false;
            if (!alert_sent_) {
                alert_sent_ = true;
                auto alert = encode_alert_record();
                if (!alert || !co_await transport_.send(*alert, deadline)) {
                    cancel();
                    co_return false;
                }
            }
            co_return co_await transport_.close_output(deadline);
        }
    };

    struct HandshakeClientResult {
        VerifiedStream stream;
        std::vector<std::uint8_t> unread_wire;
    };

    template<class Socket>
    auto handshake_client(
        Socket& socket,
        tls::ClientProfile const& profile,
        tls::Fingerprint fingerprint,
        std::string_view password,
        StreamClock::time_point deadline,
        std::int64_t verification_time,
        bool strict_tls13 = true) -> nex::capy::task<std::expected<HandshakeClientResult, std::string>> {
        if (password.empty()) co_return std::unexpected("ShadowTLS password required");
        if (StreamClock::now() >= deadline) co_return std::unexpected("ShadowTLS handshake deadline exceeded");
        auto ip = platform::parse_ip_address(profile.server_name);
        auto sni = ip ? std::optional<std::string_view>{} : std::optional<std::string_view>{profile.server_name};
        std::array<std::string_view, 16> alpn{};
        if (profile.alpn.size() > alpn.size()) co_return std::unexpected("too many ALPN protocols");
        for (std::size_t i = 0; i < profile.alpn.size(); ++i) alpn[i] = profile.alpn[i];
        auto fp_cfg = tls::make_profile_fingerprint_config(
            fingerprint, profile.key_share, profile.hybrid_only, tls::HandshakeTransport::tcp);
        auto shaped = tls::make_fingerprint_hello(sni, std::span(alpn).first(profile.alpn.size()), fp_cfg);
        if (!shaped) co_return std::unexpected("invalid ShadowTLS ClientHello configuration");
        if (shaped->hello.session_id.size() != tls_random_size) {
            shaped->hello.session_id.resize(tls_random_size);
            if (!crypto::random_bytes(shaped->hello.session_id))
                co_return std::unexpected("ShadowTLS CSPRNG failed");
        }
        std::vector<std::span<std::uint8_t const>> anchor_views;
        anchor_views.reserve(profile.anchors.size());
        for (auto const& cert : profile.anchors) anchor_views.emplace_back(cert);
        auto peer_name = ip
            ? ip->view()
            : std::span(reinterpret_cast<std::uint8_t const*>(profile.server_name.data()), profile.server_name.size());
        auto tls_hs = tls::ClientSessionHandshake::create(
            std::move(shaped->hello), shaped->initial_groups(), anchor_views,
            ip ? tls::PeerNameKind::ip : tls::PeerNameKind::dns, peer_name, verification_time);
        if (!tls_hs) co_return std::unexpected("invalid ShadowTLS TLS session");
        if (!profile.certificate_pins.empty()) tls_hs->set_certificate_pins(profile.certificate_pins);

        auto raw_ch = tls_hs->initial_record();
        if (!raw_ch || raw_ch->size() <= tls_header_size)
            co_return std::unexpected("cannot build ShadowTLS ClientHello");
        std::vector<std::uint8_t> ch_body(raw_ch->begin() + tls_header_size, raw_ch->end());
        std::array<std::uint8_t, 28> random28{};
        if (!crypto::random_bytes(random28) ||
            !stamp_client_hello_session_id(password, ch_body, random28))
            co_return std::unexpected("cannot stamp ShadowTLS ClientHello session_id");
        std::span<std::uint8_t const> stamped_sid(ch_body.data() + 39, tls_random_size);
        if (!tls_hs->replace_session_id(stamped_sid))
            co_return std::unexpected("cannot update ShadowTLS ClientHello session_id");
        auto ch_record = tls_hs->initial_record();
        if (!ch_record) co_return std::unexpected("cannot encode stamped ClientHello");

        net::SocketByteStream<Socket> transport(socket);
        if (!co_await transport.send(*ch_record, deadline) || !tls_hs->sent())
            co_return std::unexpected("failed sending ShadowTLS ClientHello");

        TlsRecordReader reader;
        std::optional<std::array<std::uint8_t, tls_random_size>> server_random;
        std::optional<ClientHandshakeUnmasker> unmasker;
        std::array<std::uint8_t, 16640> rx{};
        std::vector<std::uint8_t> leftover;

        while (!tls_hs->complete()) {
            auto n = co_await transport.read(rx, deadline);
            if (!n || !*n) co_return std::unexpected("ShadowTLS server closed during handshake");
            auto chunk = std::span(rx).first(*n);
            while (!chunk.empty() && !tls_hs->complete()) {
                auto step = reader.feed(chunk);
                chunk = chunk.subspan(step.consumed);
                if (step.status == RecordStatus::malformed || step.status == RecordStatus::too_large)
                    co_return std::unexpected("malformed ShadowTLS handshake record");
                if (step.status != RecordStatus::complete) continue;
                auto rec = step.record;
                std::vector<std::uint8_t> plain_rec;
                std::span<std::uint8_t const> feed_bytes = rec;
                if (rec[0] == tls_record_handshake && !server_random) {
                    if (auto sr = extract_server_random(rec)) {
                        if (strict_tls13 && !is_server_hello_tls13(rec))
                            co_return std::unexpected("ShadowTLS v3 requires TLS 1.3 ServerHello");
                        auto um = ClientHandshakeUnmasker::create(password, *sr);
                        if (!um) co_return std::unexpected("ShadowTLS unmasker setup failed");
                        server_random = *sr;
                        unmasker.emplace(std::move(*um));
                    }
                } else if (rec[0] == tls_record_application_data) {
                    if (!unmasker) co_return std::unexpected("unexpected ShadowTLS ApplicationData before ServerHello");
                    auto dec = unmasker->unmask_record(rec);
                    if (!dec) co_return std::unexpected("ShadowTLS handshake HMAC mismatch");
                    plain_rec = std::move(*dec);
                    feed_bytes = plain_rec;
                }
                while (!feed_bytes.empty()) {
                    auto fed = tls_hs->feed(feed_bytes);
                    if (!fed) co_return std::unexpected("ShadowTLS TLS authentication failed");
                    feed_bytes = feed_bytes.subspan(fed->consumed);
                    if (fed->outbound) {
                        if (!co_await transport.send(*fed->outbound, deadline) || !tls_hs->sent())
                            co_return std::unexpected("failed writing ShadowTLS TLS response");
                    }
                }
                reader.consume();
                if (tls_hs->complete()) {
                    leftover.assign(chunk.begin(), chunk.end());
                    break;
                }
            }
        }
        if (!server_random || !unmasker)
            co_return std::unexpected("ShadowTLS handshake missing ServerHello");
        auto verified = VerifiedStream::create(
            StreamRole::client, password, *server_random, std::move(*unmasker).take_hmac(), false);
        if (!verified) co_return std::unexpected("ShadowTLS VerifiedStream setup failed");
        co_return HandshakeClientResult{std::move(*verified), std::move(leftover)};
    }

    template<class Socket>
    struct ServerSession {
        std::size_t user_index = 0;
        VerifiedStream stream;
        std::vector<std::uint8_t> unread_wire;
        std::vector<std::uint8_t> initial_payload;
    };

    // Perform ShadowTLS v3 server handshake relay + cutover against a caller-supplied connected
    // handshake socket. Returns nullopt (without error) when ClientHello did not authenticate
    // and transparent pass-through relay to handshake_socket already completed.
    template<class ClientSocket, class HandshakeSocket>
    auto handshake_server(
        ClientSocket& client,
        HandshakeSocket& handshake_socket,
        std::span<std::string const> passwords,
        std::span<std::uint8_t const> first_client_record,
        std::span<std::uint8_t const> first_client_leftover,
        std::size_t matched_user,
        StreamClock::time_point deadline,
        bool strict_tls13 = true) -> nex::capy::task<std::expected<ServerSession<ClientSocket>, std::string>> {
        net::SocketByteStream<ClientSocket> cli(client);
        net::SocketByteStream<HandshakeSocket> hs(handshake_socket);
        if (!co_await hs.send(first_client_record, deadline))
            co_return std::unexpected("failed writing ClientHello to handshake server");

        TlsRecordReader hs_reader;
        std::optional<std::array<std::uint8_t, tls_random_size>> server_random;
        std::array<std::uint8_t, 16640> hs_rx{};
        std::vector<std::uint8_t> hs_unread;
        while (!server_random) {
            auto n = co_await hs.read(hs_rx, deadline);
            if (!n || !*n) co_return std::unexpected("handshake server closed before ServerHello");
            auto chunk = std::span(hs_rx).first(*n);
            while (!chunk.empty()) {
                auto step = hs_reader.feed(chunk);
                chunk = chunk.subspan(step.consumed);
                if (step.status != RecordStatus::complete && step.status != RecordStatus::incomplete)
                    co_return std::unexpected("malformed record from handshake server");
                if (step.status != RecordStatus::complete) continue;
                if (!co_await cli.send(step.record, deadline))
                    co_return std::unexpected("failed forwarding ServerHello to client");
                if (auto sr = extract_server_random(step.record)) {
                    if (strict_tls13 && !is_server_hello_tls13(step.record))
                        co_return std::unexpected("ShadowTLS v3 requires TLS 1.3 handshake server");
                    server_random = *sr;
                    hs_unread.assign(chunk.begin(), chunk.end());
                }
                hs_reader.consume();
                if (server_random) break;
            }
        }
        auto const& pass = passwords[matched_user];
        auto masker = ServerHandshakeMasker::create(pass, *server_random);
        auto stream = VerifiedStream::create(StreamRole::server, pass, *server_random, {}, true);
        if (!masker || !stream) co_return std::unexpected("ShadowTLS server state setup failed");

        bool cutover_done = false;
        std::vector<std::uint8_t> cli_unread;
        std::vector<std::uint8_t> init_payload;
        std::optional<std::string> relay_err;

        auto pump_hs_to_cli = [&]() -> nex::capy::task<nex::capy::results<>> {
            std::vector<std::uint8_t> pending = std::move(hs_unread);
            for (;;) {
                std::span<std::uint8_t const> span = pending;
                while (!span.empty()) {
                    auto step = hs_reader.feed(span);
                    span = span.subspan(step.consumed);
                    if (step.status != RecordStatus::complete && step.status != RecordStatus::incomplete) co_return nex::capy::results<>{};
                    if (step.status != RecordStatus::complete) continue;
                    auto rec = step.record;
                    if (rec[0] == tls_record_application_data) {
                        auto masked = masker->mask_record(rec);
                        if (!masked || !co_await cli.send(*masked)) { hs_reader.consume(); co_return nex::capy::results<>{}; }
                    } else if (!co_await cli.send(rec)) {
                        hs_reader.consume();
                        co_return nex::capy::results<>{};
                    }
                    hs_reader.consume();
                }
                pending.resize(16640);
                auto n = co_await hs.read(pending);
                if (!n || !*n) co_return nex::capy::results<>{};
                pending.resize(*n);
            }
        };

        auto pump_cli_to_hs = [&]() -> nex::capy::task<nex::capy::results<>> {
            TlsRecordReader cli_reader;
            std::vector<std::uint8_t> pending(first_client_leftover.begin(), first_client_leftover.end());
            for (;;) {
                std::span<std::uint8_t const> span = pending;
                while (!span.empty()) {
                    auto step = cli_reader.feed(span);
                    span = span.subspan(step.consumed);
                    if (step.status != RecordStatus::complete && step.status != RecordStatus::incomplete) {
                        relay_err = "malformed client TLS record";
                        hs.cancel();
                        co_return nex::capy::results<>{};
                    }
                    if (step.status != RecordStatus::complete) continue;
                    auto rec = step.record;
                    auto probe = stream->accept_cutover_record(rec);
                    if (probe.status == VerifiedStream::DecodeStatus::payload) {
                        init_payload.assign(probe.payload.begin(), probe.payload.end());
                        cli_unread.assign(span.begin(), span.end());
                        cutover_done = true;
                        hs.cancel();
                        co_return nex::capy::results<>{};
                    }
                    if (!co_await hs.send(rec, deadline)) {
                        cli_reader.consume();
                        if (!cutover_done) relay_err = "failed relaying client TLS handshake";
                        co_return nex::capy::results<>{};
                    }
                    cli_reader.consume();
                }
                pending.resize(16640);
                auto n = co_await cli.read(pending, deadline);
                if (!n || !*n) {
                    relay_err = "client closed before ShadowTLS cutover";
                    hs.cancel();
                    co_return nex::capy::results<>{};
                }
                pending.resize(*n);
            }
        };

        (void)co_await nex::capy::when_all(pump_hs_to_cli(), pump_cli_to_hs());
        if (!cutover_done)
            co_return std::unexpected(relay_err.value_or("ShadowTLS server cutover failed"));
        co_return ServerSession<ClientSocket>{
            matched_user, std::move(*stream), std::move(cli_unread), std::move(init_payload)
        };
    }

    template<class ClientSocket, class HandshakeSocket>
    auto relay_plain_tls(
        ClientSocket& client,
        HandshakeSocket& handshake_socket,
        std::span<std::uint8_t const> first_client_record,
        std::span<std::uint8_t const> first_client_leftover,
        StreamClock::time_point deadline) -> nex::capy::task<void> {
        net::SocketByteStream<ClientSocket> cli(client);
        net::SocketByteStream<HandshakeSocket> hs(handshake_socket);
        if (!co_await hs.send(first_client_record, deadline)) { hs.cancel(); cli.cancel(); co_return; }
        if (!first_client_leftover.empty() && !co_await hs.send(first_client_leftover, deadline)) { hs.cancel(); cli.cancel(); co_return; }
        auto copy_dir = [&](auto& from, auto& to) -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t, 16384> buf{};
            for (;;) {
                auto n = co_await from.read(buf);
                if (!n || !*n) { (void)co_await to.close_output(); co_return nex::capy::results<>{}; }
                if (!co_await to.send(std::span(buf).first(*n))) { from.cancel(); to.cancel(); co_return nex::capy::results<>{}; }
            }
        };
        (void)co_await nex::capy::when_all(copy_dir(cli, hs), copy_dir(hs, cli));
    }
}
