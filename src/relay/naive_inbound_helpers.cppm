module relay:naive_inbound_helpers;
import std;
import config;
import crypto;
import naive.padding;
import rulefile;
import rules;
import socks5;
import sniff.tcp;
import capy;
import corosio;
import :types;
import :session_interface;
import :internal_decls;

namespace relay::naive_in_detail {
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
        -> capy::task<sniff::TcpReadResult> {
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
    auto dial_naive_target(Session& child, corosio::io_context& context, rules::RouteProgram const& policy,
                           socks5::Request const& target, In& incoming) -> capy::task<std::uint8_t> {
        if (child.ordered_tcp) {
            bool ok = co_await route_ordered_stream_tcp(child, context, target, &incoming, &sniff_naive_stream<In>);
            co_return ok ? std::uint8_t{0} : std::uint8_t{1};
        }
        co_return co_await dial_destination(child, context, policy, target);
    }

    inline auto init_naive_child(Session& child, Session& parent, Clock::time_point deadline) -> void {
        init_multiplexed_child(child, parent, deadline);
    }
}
