#pragma once

namespace proxy::naive_in_detail {
    inline auto load_naive_users(std::span<config::NaiveUser const> src)
        -> std::expected<std::vector<naive::UserCredential>, std::string> {
        std::vector<naive::UserCredential> out;
        out.reserve(src.size());
        for (auto const& u : src) {
            auto pw = rulefile::read_password_file(u.password_file);
            if (!pw) return std::unexpected("NaiveProxy user password-file: " + pw.error());
            out.emplace_back(u.name, u.username, *pw);
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(pw->data()), pw->size()));
        }
        return out;
    }

    inline auto match_basic_single(std::string_view header, Credentials const& creds) -> bool {
        std::string_view user(reinterpret_cast<char const*>(creds.username.data()), creds.username_size);
        std::string_view pass(reinterpret_cast<char const*>(creds.password.data()), creds.password_size);
        std::array<naive::UserCredential, 1> list{naive::UserCredential{std::string(user), std::string(user), std::string(pass)}};
        return naive::verify_basic_auth(header, list).has_value();
    }

    template<class In>
    auto sniff_naive_stream(void* stream, sniff::TcpSniffer& sniffer, Clock::time_point deadline)
        -> nex::capy::task<sniff::TcpReadResult> {
        auto& in = *static_cast<In*>(stream);
        std::array<std::uint8_t, 4096> bytes{};
        for (;;) {
            auto st = sniffer.limit();
            if (st.status != sniff::TcpStatus::need_more) co_return {sniff::TcpReadStop::classified, st, {}};
            if (Clock::now() >= deadline) co_return {sniff::TcpReadStop::deadline, st, {}};
            auto count = co_await in.read(std::span(bytes).first(std::min(bytes.size(), sniffer.remaining())), deadline);
            if (!count) co_return {sniff::TcpReadStop::io_error, sniffer.current(), std::make_error_code(std::errc::io_error)};
            if (!*count) co_return {sniff::TcpReadStop::eof, sniffer.finish(), {}};
            auto step = sniffer.feed(std::span(bytes).first(*count));
            if (step.consumed != *count)
                co_return {sniff::TcpReadStop::io_error, step, std::make_error_code(std::errc::protocol_error)};
        }
    }

    template<class In>
    auto dial_naive_target(Session& child, nex::corosio::io_context& context, rules::RouteMatcher const& policy,
                           socks5::Request const& target, In& incoming) -> nex::capy::task<std::uint8_t> {
        if (child.ordered_tcp) {
            bool ok = co_await route_ordered_stream_tcp(child, context, target, &incoming, &sniff_naive_stream<In>);
            co_return ok ? std::uint8_t{0} : std::uint8_t{1};
        }
        co_return co_await dial_destination(child, context, policy, target);
    }

    inline auto init_naive_child(Session& child, Session& parent, Clock::time_point deadline) -> void {
        child.transport_owner = &parent;
        child.register_child_traffic();
        child.datagram_source = parent.datagram_source;
        child.ingress = parent.ingress;
        child.route_snapshot = parent.route_snapshot;
        child.ordered_tcp = parent.ordered_tcp;
        child.principal_policy = parent.principal_policy;
        child.inbound = parent.inbound;
        child.dns = parent.dns;
        child.local_dns = parent.local_dns;
        child.reverse_cache = parent.reverse_cache;
        child.reverse_view = parent.reverse_view;
#ifdef NEXUS_ENABLE_FAKEIP
        child.fakeip = parent.fakeip;
        child.fakeip_view = parent.fakeip_view;
#endif
        child.tunnel_factories = parent.tunnel_factories;
        child.direct_connect_timeout_ms = parent.direct_connect_timeout_ms;
        child.direct_tcp_options = parent.direct_tcp_options;
        child.started = child.touched = Clock::now();
        child.handshake_deadline = deadline;
    }
}
