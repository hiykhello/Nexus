// HTTP/2 single-request driver for `nexus tools fetch`.
export module cli.tools_fetch_h2;
import std;
import capy;
import cli.tools_fetch;
import http2.client_channel;
import http2.headers;

export namespace cli::fetch {
    inline constexpr bool h2_available = true;

    template<class Lower>
    auto exchange_h2(Lower& lower, std::string_view method, std::string_view authority, std::string_view target,
        std::span<FetchHeader const> req_headers, std::string_view req_body,
        std::chrono::steady_clock::time_point started, std::chrono::steady_clock::time_point deadline,
        std::size_t preview_limit, FetchResult& out) -> capy::task<std::expected<void, std::string>> {
        using Clock = std::chrono::steady_clock;
        auto client = http2::Client<4>::create();
        if (!client) co_return std::unexpected("cannot initialize HTTP/2 client");

        std::vector<std::pair<std::string, std::string>> owned_headers;
        owned_headers.reserve(req_headers.size() + 2);
        bool has_cl = false;
        for (auto const& h : req_headers) {
            std::string lo(h.name);
            for (char& c : lo) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lo == "host" || lo == "connection" || lo == "keep-alive" || lo == "proxy-connection" ||
                lo == "transfer-encoding" || lo == "upgrade" || lo == "accept-encoding") continue;
            if (lo == "content-length") has_cl = true;
            owned_headers.emplace_back(std::move(lo), h.value);
        }
        if (method == "POST" && !has_cl)
            owned_headers.emplace_back("content-length", std::to_string(req_body.size()));

        std::vector<http2::FieldView> fields{
            {":method", method}, {":scheme", "https"}, {":authority", authority},
            {":path", target}, {"accept-encoding", "identity"},
        };
        fields.reserve(fields.size() + owned_headers.size());
        for (auto const& [k, v] : owned_headers) fields.push_back({k, v});

        http2::ClientChannel<Lower, 4> channel(lower, std::move(*client), deadline);
        http2::BodyView body_view{
            {reinterpret_cast<std::uint8_t const*>(req_body.data()), req_body.size()},
            true
        };
        auto ticket = channel.submit(fields, body_view);
        if (!ticket) co_return std::unexpected("HTTP/2 request submission failed");

        std::expected<void, std::string> status_res = std::unexpected("HTTP/2 response incomplete");
        auto drive = [&]() -> capy::task<capy::results<>> { co_return co_await channel.run(); };
        auto reader = [&]() -> capy::task<capy::results<>> {
            struct CancelGuard {
                http2::ClientChannel<Lower, 4>& ch;
                ~CancelGuard() { ch.cancel(); }
            } guard{channel};

            bool got_headers = false;
            constexpr std::size_t kMaxBodyBytes = 16 * 1024 * 1024;
            while (Clock::now() < deadline) {
                auto resp = channel.response(*ticket);
                if (!resp || resp->failure) {
                    status_res = std::unexpected("HTTP/2 stream failed");
                    break;
                }
                if (!got_headers && resp->status) {
                    got_headers = true;
                    out.status = resp->status;
                    out.protocol = "h2";
                    out.ttfb_ms = std::chrono::duration<double, std::milli>(Clock::now() - started).count();
                    for (auto const& f : resp->headers) {
                        if (!f.name.starts_with(':')) out.headers.push_back({f.name, f.value});
                    }
                }
                auto bytes = channel.peek(*ticket);
                if (!bytes) { status_res = std::unexpected("HTTP/2 stream buffer error"); break; }
                if (!bytes->empty()) {
                    auto chunk_sz = bytes->size();
                    if (out.body_bytes + chunk_sz > kMaxBodyBytes) {
                        status_res = std::unexpected("HTTP/2 response body exceeded 16 MiB limit");
                        break;
                    }
                    if (out.body_preview.size() < preview_limit) {
                        auto take = std::min(preview_limit - out.body_preview.size(), chunk_sz);
                        out.body_preview.append(reinterpret_cast<char const*>(bytes->data()), take);
                        if (take < chunk_sz) out.body_truncated = true;
                    } else if (preview_limit > 0) {
                        out.body_truncated = true;
                    }
                    out.body_bytes += chunk_sz;
                    if (!channel.consume(*ticket, chunk_sz)) break;
                    continue;
                }
                if (resp->closed) {
                    if (got_headers && resp->remote_end) status_res = {};
                    else status_res = std::unexpected("HTTP/2 response truncated");
                    break;
                }
                if (!co_await channel.wait_change(deadline)) {
                    status_res = std::unexpected("HTTP/2 response timed out");
                    break;
                }
            }
            co_return capy::results<>{};
        };
        (void)co_await capy::when_all(drive(), reader());
        co_return status_res;
    }
}
