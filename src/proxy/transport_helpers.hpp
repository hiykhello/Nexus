// Private transport helpers shared by Trojan and AnyTLS (WS / HTTPUpgrade / gRPC).
#pragma once

namespace proxy::transport_detail {
    inline auto compile_httpupgrade(HttpUpgradeTransport const& cfg, bool client, std::string_view fallback_host)
        -> std::expected<httpupgrade::Profile, std::string> {
        std::vector<httpupgrade::Field> fields;
        fields.reserve(cfg.headers.size());
        for (auto const& h : cfg.headers) fields.push_back({h.name, h.value});
        auto host = cfg.host.empty() ? fallback_host : std::string_view(cfg.host);
        auto built = client
            ? httpupgrade::Profile::client(host, cfg.path, fields, cfg.websocket)
            : httpupgrade::Profile::server(cfg.host, cfg.path, fields, cfg.websocket);
        if (!built) return std::unexpected("invalid HTTPUpgrade/WebSocket transport profile");
        return std::move(*built);
    }

    struct GrpcSettings {
        grpc::RequestProfile request;
        grpc::ResponsePolicy response = grpc::ResponsePolicy::standard;
        grpc::Limits limits{};
        std::size_t max_sessions = 64;
        bool tcp_fast_open = false;
    };

    inline auto compile_grpc(GrpcTransport const& cfg, bool client, std::string_view fallback_host)
        -> std::expected<GrpcSettings, std::string> {
        if (client && (!cfg.max_sessions || cfg.max_sessions > 256))
            return std::unexpected("invalid gRPC max-sessions");
        if (!client && (cfg.response_policy != GrpcTransport::ResponsePolicy::standard || cfg.authority.empty()))
            return std::unexpected("invalid gRPC inbound policy/authority");
        std::string authority = cfg.authority;
        if (client && authority.empty()) {
            authority = std::string(fallback_host);
            if (auto ip = platform::parse_ip_address(authority); ip && ip->size == 16)
                authority = "[" + authority + "]";
        }
        auto req = grpc::RequestProfile::create(cfg.service_name, authority, true);
        auto resp = cfg.response_policy == GrpcTransport::ResponsePolicy::standard
            ? grpc::ResponsePolicy::standard : grpc::ResponsePolicy::sing_box_lite;
        grpc::Limits lim{cfg.input_window, cfg.message_bytes, cfg.hunk_bytes,
                         cfg.output_bytes, cfg.output_messages, cfg.library_bytes};
        if (!req || !grpc::Session::create(client ? grpc::Role::client : grpc::Role::server, *req, resp, lim))
            return std::unexpected("invalid gRPC request/limits");
        return GrpcSettings{std::move(*req), resp, lim, cfg.max_sessions, cfg.tcp_fast_open};
    }

    template<class Stream>
    auto handshake_ws_or_hu(Stream& stream, httpupgrade::Profile const& profile, Clock::time_point deadline)
        -> nex::capy::task<bool> {
        if (profile.websocket()) {
            auto ws = co_await stream.activate_websocket(profile, deadline);
            co_return ws.has_value();
        }
        auto ready = profile.is_client()
            ? co_await httpupgrade::connect(stream, profile, deadline)
            : co_await httpupgrade::accept(stream, profile, deadline);
        if (!ready) co_return false;
        co_return stream.prepend_owned(std::move(ready->unread));
    }

    template<class Rpc>
    struct GrpcByteStream {
        Rpc& rpc;
        Session* touch = nullptr;

        auto read(std::span<std::uint8_t> bytes, std::optional<Clock::time_point> deadline = {})
            -> nex::capy::task<std::expected<std::size_t, tls::detail::ByteStreamError>> {
            auto lim = deadline.value_or(Clock::now() + std::chrono::seconds(300));
            auto r = co_await rpc.read(bytes, lim);
            if (!r) co_return std::unexpected(Clock::now() >= lim
                ? tls::detail::ByteStreamError::timeout : tls::detail::ByteStreamError::io);
            if (*r && touch) touch->touched = Clock::now();
            co_return *r;
        }
        auto send(std::span<std::uint8_t const> bytes, std::optional<Clock::time_point> deadline = {})
            -> nex::capy::task<bool> {
            auto lim = deadline.value_or(Clock::now() + std::chrono::seconds(300));
            auto ok = co_await rpc.send(bytes, lim);
            if (ok && touch) touch->touched = Clock::now();
            co_return ok;
        }
        auto close_output(std::optional<Clock::time_point> deadline = {}) -> nex::capy::task<bool> {
            co_return co_await rpc.close_output(deadline.value_or(Clock::now() + std::chrono::seconds(300)));
        }
        auto cancel() noexcept -> void { rpc.cancel(); }
    };
}
