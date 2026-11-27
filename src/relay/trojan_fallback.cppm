// Trojan inbound fallback target selection, zero-byte-loss header probe, and decoy relay.
module;
#include <boost/corosio/socket_option.hpp>

module relay:trojan_fallback;
import std;
import capy;
import corosio;
import config;
import crypto;
import tls.corosio_application;
import tls.byte_stream;
import trojan;
import trojan.auth;
import trojan.stream;
import :types;
import :session_interface;
import :internal_decls;

namespace relay::trojan_in {
    inline auto select_fallback_target(
        std::optional<config::FallbackTarget> const& default_target,
        std::span<std::pair<std::string, config::FallbackTarget> const> by_alpn,
        std::string_view negotiated_alpn) noexcept -> config::FallbackTarget const* {
        if (!negotiated_alpn.empty()) {
            for (auto const& [alpn, target] : by_alpn) {
                if (alpn == negotiated_alpn) return &target;
            }
        }
        return default_target ? &*default_target : nullptr;
    }

    inline auto trojan_prefix_plausible(std::span<std::uint8_t const> buf) noexcept -> bool {
        auto const key_len = std::min<std::size_t>(buf.size(), 56);
        for (std::size_t i = 0; i < key_len; ++i) {
            auto const c = buf[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        if (buf.size() >= 57 && buf[56] != '\r') return false;
        if (buf.size() >= 58 && buf[57] != '\n') return false;
        if (buf.size() >= 59 && buf[58] != 1 && buf[58] != 3) return false;
        if (buf.size() >= 60 && buf[59] != 1 && buf[59] != 3 && buf[59] != 4) return false;
        return true;
    }

    // Adapter serving leftover post-header bytes before delegating to the live TLS ByteStream.
    class PrefixedTlsStream {
        tls::detail::ByteStream<corosio::tcp_socket>& inner_;
        std::vector<std::uint8_t> unread_;
        std::size_t pos_ = 0;
    public:
        PrefixedTlsStream(tls::detail::ByteStream<corosio::tcp_socket>& inner,
                          std::vector<std::uint8_t> unread) noexcept
            : inner_(inner), unread_(std::move(unread)) {}
        ~PrefixedTlsStream() { crypto::cleanse(unread_); }

        auto read_request(tls::detail::ApplicationDeadline = {})
            -> capy::task<std::optional<trojan::detail::AcceptedRequest>> {
            co_return std::nullopt;
        }
        auto read(std::span<std::uint8_t> out, tls::detail::ApplicationDeadline d = {})
            -> capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>> {
            if (out.empty()) co_return std::unexpected(tls::detail::ByteStreamError::state);
            if (pos_ < unread_.size()) {
                auto const n = std::min(out.size(), unread_.size() - pos_);
                std::copy_n(unread_.data() + pos_, n, out.begin());
                pos_ += n;
                if (pos_ == unread_.size()) {
                    crypto::cleanse(unread_);
                    unread_.clear();
                    pos_ = 0;
                }
                co_return n;
            }
            co_return co_await inner_.read(out, d);
        }
        auto read_sniff(std::span<std::uint8_t> out, tls::detail::ApplicationDeadline d)
            -> capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>> {
            if (out.empty()) co_return std::unexpected(tls::detail::ByteStreamError::state);
            if (pos_ < unread_.size()) {
                auto const n = std::min(out.size(), unread_.size() - pos_);
                std::copy_n(unread_.data() + pos_, n, out.begin());
                pos_ += n;
                if (pos_ == unread_.size()) {
                    crypto::cleanse(unread_);
                    unread_.clear();
                    pos_ = 0;
                }
                co_return n;
            }
            co_return co_await inner_.read(out, d, tls::detail::ReadTimeoutPolicy::preserve_connection);
        }
        auto send(std::span<std::uint8_t const> b, tls::detail::ApplicationDeadline d = {}) {
            return inner_.send(b, d);
        }
        auto close_output() { return inner_.close_output(); }
        auto cancel() noexcept -> void { inner_.cancel(); }
    };

    struct TrojanProbeOutcome {
        std::optional<trojan::detail::AcceptedRequest> accepted;
        std::vector<std::uint8_t> bytes; // Leftover payload if accepted, or exact raw prefix if fallback.
        bool fallback = false;
    };

    inline auto probe_trojan_header(
        tls::detail::ByteStream<corosio::tcp_socket>& stream,
        trojan::UserTable const& users,
        Clock::time_point deadline) -> capy::task<TrojanProbeOutcome> {
        TrojanProbeOutcome out;
        trojan::RequestDecoder decoder;
        std::array<std::uint8_t, 4096> chunk{};
        struct WipeChunk { std::array<std::uint8_t, 4096>& b; ~WipeChunk() { crypto::cleanse(b); } } wipe{chunk};
        constexpr std::size_t kMaxProbeBytes = 4096;
        while (out.bytes.size() < kMaxProbeBytes) {
            auto const space = std::min(chunk.size(), kMaxProbeBytes - out.bytes.size());
            auto got = co_await stream.read(std::span(chunk).first(space), deadline);
            if (!got) {
                crypto::cleanse(out.bytes);
                out.bytes.clear();
                co_return out;
            }
            if (!*got) {
                out.fallback = !out.bytes.empty();
                co_return out;
            }
            auto const prev = out.bytes.size();
            out.bytes.insert(out.bytes.end(), chunk.begin(), chunk.begin() + static_cast<std::ptrdiff_t>(*got));
            if (!trojan_prefix_plausible(out.bytes)) {
                out.fallback = true;
                co_return out;
            }
            auto const fed = decoder.feed(std::span(out.bytes).subspan(prev));
            if (fed.status == trojan::Status::incomplete) continue;
            if (fed.status != trojan::Status::accepted) {
                out.fallback = true;
                co_return out;
            }
            auto const* hdr = decoder.request();
            auto user = hdr ? users.authenticate(hdr->key) : std::nullopt;
            if (!user) {
                out.fallback = true;
                co_return out;
            }
            auto const total_consumed = prev + fed.consumed;
            out.accepted = trojan::detail::AcceptedRequest{hdr->request, *user};
            std::vector<std::uint8_t> leftover;
            if (total_consumed < out.bytes.size()) {
                leftover.assign(out.bytes.begin() + static_cast<std::ptrdiff_t>(total_consumed), out.bytes.end());
            }
            crypto::cleanse(out.bytes);
            out.bytes = std::move(leftover);
            co_return out;
        }
        out.fallback = true;
        co_return out;
    }

    inline auto dial_fallback_backend(
        Session& session, corosio::io_context& context,
        config::FallbackTarget const& target, Clock::time_point deadline) -> capy::task<bool> {
        auto const connect_limit = std::min(deadline, Clock::now() + std::chrono::seconds(5));
        if (Clock::now() >= connect_limit || session.closed) co_return false;
        DnsSlot slot;
        auto eps = co_await resolve_local_owned(session, context, slot, target.host, target.port, connect_limit);
        if (!eps || eps->empty() || session.closed) co_return false;
        for (auto const& ep : *eps) {
            if (!ep.port() || ep.address().is_unspecified()) continue;
            session.target.close();
            if (session.target.open(ep.address().family())) continue;
            auto [err] = co_await corosio::timeout(session.target.connect(ep), connect_limit);
            if (!err && !session.closed) co_return true;
        }
        co_return false;
    }

    inline auto relay_trojan_fallback(
        Session& session, corosio::io_context& context,
        tls::detail::ByteStream<corosio::tcp_socket>& tls_stream,
        config::FallbackTarget const& target,
        std::vector<std::uint8_t> initial_plaintext,
        Clock::time_point deadline) -> capy::task<> {
        struct WipeInitial { std::vector<std::uint8_t>& b; ~WipeInitial() { crypto::cleanse(b); } } wipe{initial_plaintext};
        if (!co_await dial_fallback_backend(session, context, target, deadline)) co_return;
        session.relaying = true;
        session.touched = Clock::now();
        session.lifetime_deadline = session.started + std::chrono::minutes(10);
        std::stop_callback stop_cb(session.stop.get_token(), [&]() noexcept {
            tls_stream.cancel();
            session.target.close();
        });
        auto write_all_backend = [&](std::span<std::uint8_t const> data) -> capy::task<bool> {
            while (!data.empty() && !session.closed) {
                auto [we, w] = co_await session.target.write_some(capy::const_buffer(data.data(), data.size()));
                if (we || !w || w > data.size()) co_return false;
                data = data.subspan(w);
                session.touched = Clock::now();
            }
            co_return !session.closed;
        };
        if (!initial_plaintext.empty()) {
            bool const replayed = co_await write_all_backend(initial_plaintext);
            crypto::cleanse(initial_plaintext);
            initial_plaintext.clear();
            if (!replayed) {
                tls_stream.cancel();
                session.target.close();
                co_return;
            }
        }
        auto abort_both = [&]() noexcept {
            (void)session.target.set_option(::boost::corosio::socket_option::linger(true, 0));
            tls_stream.cancel();
            session.target.close();
        };
        auto client_to_backend = [&]() -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 16384> buf{};
            while (!session.closed) {
                auto got = co_await tls_stream.read(buf);
                if (!got) { abort_both(); co_return capy::results<>{}; }
                if (!*got) { (void)session.target.shutdown(corosio::shutdown_send); co_return capy::results<>{}; }
                if (!co_await write_all_backend(std::span(buf).first(*got))) {
                    abort_both();
                    co_return capy::results<>{};
                }
            }
            co_return capy::results<>{};
        };
        auto backend_to_client = [&]() -> capy::task<capy::results<>> {
            std::array<std::uint8_t, 16384> buf{};
            while (!session.closed) {
                auto [re, n] = co_await session.target.read_some(capy::mutable_buffer(buf.data(), buf.size()));
                if (re == capy::cond::eof || (!re && n == 0)) {
                    (void)co_await tls_stream.close_output();
                    co_return capy::results<>{};
                }
                if (re || n > buf.size()) { abort_both(); co_return capy::results<>{}; }
                session.touched = Clock::now();
                if (!co_await tls_stream.send(std::span(buf).first(n))) {
                    abort_both();
                    co_return capy::results<>{};
                }
                session.touched = Clock::now();
            }
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(client_to_backend(), backend_to_client());
    }
}
