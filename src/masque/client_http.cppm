// MASQUE HTTP/3 request/response client operations module.
export module masque.client_http;
import std;
import capy;
import corosio;
import http.header;
import net.datagram_driver;
import nghttp3;
import ngtcp2;
export import masque.client_hooks;

export namespace masque::detail {
    struct ClientHttpOps {
        using Clock = std::chrono::steady_clock;

        template<class Client>
        static auto wait_http_ready(Client& client, Clock::time_point deadline, std::stop_token external = {})
            -> capy::task<bool> {
            std::stop_callback cancel(external, [&client] noexcept { client.driver_.changed().set(); });
            while (!external.stop_requested() && client.factory_.bundle && !client.factory_.bundle->app.stopping() &&
                   !client.factory_.bundle->app.can_request()) {
                client.driver_.changed().clear();
                if (external.stop_requested()) co_return false;
                auto [error] = co_await corosio::timeout(client.driver_.changed().wait(), deadline);
                if (error || !client.driver_.running()) co_return false;
            }
            co_return !external.stop_requested() && client.factory_.bundle && client.factory_.bundle->app.can_request() &&
                Clock::now() < deadline;
        }

        template<class Client>
        [[nodiscard]] static auto retryable_http_handshake(Client const& client, Clock::time_point deadline) noexcept -> bool {
            if (client.factory_.failure) return client.factory_.failure == ngtcp2::err_handshake_timeout;
            auto const& failure = client.driver_.failure();
            if (!failure) return Clock::now() >= deadline;
            auto* socket = std::get_if<net::DatagramFailure>(&*failure);
            return socket && (socket->system == std::errc::network_unreachable ||
                socket->system == std::errc::host_unreachable || socket->system == std::errc::connection_refused);
        }

        template<class Client>
        [[nodiscard]] static auto reusable_http(Client const& client) noexcept -> bool {
            return client.factory_.bundle && client.factory_.bundle->app.can_request() &&
                !client.factory_.bundle->hooks.conn_closed && !client.factory_.bundle->hooks.http_goaway;
        }

        template<class Client>
        [[nodiscard]] static auto can_submit_http(Client const& client) noexcept -> bool {
            return reusable_http(client) && client.factory_.bundle->hooks.stream < 0 &&
                std::ranges::any_of(client.factory_.bundle->hooks.responses, [](auto const& entry) {
                    return !entry;
                });
        }

        template<class Client, class Bundle>
        static auto release_http(Client& client, Bundle& bundle, std::optional<typename ClientHooks::Response>& entry) noexcept -> void {
            auto& response = *entry;
            bundle.app.discard_body(std::exchange(response.uncredited, 0));
            if (response.closed) entry.reset();
            else {
                response.returned = true;
                if (!response.complete && !response.reset_sent) {
                    response.rejected = true;
                    response.reset = true;
                    if (bundle.app.flush_pending()) client.request_stop();
                }
            }
            client.driver_.notify();
        }

        template<class Client>
        static auto exchange_http(Client& client, std::string_view path, std::size_t limit, Clock::time_point deadline,
            std::optional<HttpPost> post, std::span<http::HeaderField const> headers = {}, bool allow_not_modified = false,
            bool allow_redirect = false, std::optional<HttpBodySink> sink = {}, std::optional<HttpHeaderSink> observe = {},
            std::stop_token external = {}) -> capy::task<std::expected<HttpResponse, HttpError>> {
            using Bundle = typename Client::Bundle;
            if (!co_await wait_http_ready(client, deadline, external)) co_return std::unexpected(HttpError::transport);
            std::stop_callback cancel(external, [&client] noexcept { client.driver_.changed().set(); });
            auto& bundle = *client.factory_.bundle;
            auto& hooks = bundle.hooks;
            auto stop = co_await capy::this_coro::stop_token;
            std::optional<typename ClientHooks::Response>* entry = nullptr;
            for (;;) {
                if (stop.stop_requested() || external.stop_requested() || Clock::now() >= deadline ||
                    !reusable_http(client) || hooks.stream >= 0)
                    co_return std::unexpected(HttpError::transport);
                auto it = std::ranges::find_if(hooks.responses, [](auto const& candidate) { return !candidate; });
                if (it == hooks.responses.end()) co_return std::unexpected(HttpError::transport);
                std::int64_t id = -1;
                auto error = ngtcp2::ngtcp2_conn_open_bidi_stream(bundle.session.transport().native(), &id, nullptr);
                if (!error) {
                    it->emplace(id, limit);
                    entry = &*it;
                    break;
                }
                if (error != ngtcp2::err_stream_id_blocked) co_return std::unexpected(HttpError::transport);
                client.driver_.changed().clear();
                if (external.stop_requested()) co_return std::unexpected(HttpError::transport);
                auto [wait_error] = co_await corosio::timeout(client.driver_.changed().wait(), deadline);
                if (wait_error || !client.driver_.running()) co_return std::unexpected(HttpError::transport);
            }
            struct Release {
                Client& client;
                Bundle& bundle;
                std::optional<typename ClientHooks::Response>& entry;
                ~Release() { release_http(client, bundle, entry); }
            } release{client, bundle, *entry};
            auto& response = **entry;
            response.allow_not_modified = allow_not_modified;
            response.allow_redirect = allow_redirect;
            response.streaming = sink.has_value();
            std::array fields{Client::field(":method", post ? "POST" : "GET"), Client::field(":scheme", "https"),
                Client::field(":authority", client.profile_.authority()), Client::field(":path", path),
                Client::field("accept-encoding", "identity"), Client::field("accept", {}),
                Client::field("content-type", {}), Client::field("content-length", {})};
            std::string length;
            auto count = std::size_t{5};
            if (post) {
                length = std::to_string(post->bytes.size());
                fields[5] = Client::field("accept", post->media_type);
                fields[6] = Client::field("content-type", post->media_type);
                fields[7] = Client::field("content-length", length);
                count = fields.size();
                response.request.emplace(post->bytes.begin(), post->bytes.end());
            }
            auto request_fields = std::span<nghttp3::nghttp3_nv const>(fields).first(count);
            std::vector<nghttp3::nghttp3_nv> extended;
            if (!headers.empty()) {
                extended.reserve(count + headers.size());
                extended.assign(request_fields.begin(), request_fields.end());
                for (auto const& header : headers) {
                    auto value = Client::field(header.name, header.value);
                    value.flags = nghttp3::nv_flag_never_index;
                    extended.push_back(value);
                }
                request_fields = extended;
            }
            if (bundle.app.h3().request(response.id, request_fields, post.has_value()))
                co_return std::unexpected(HttpError::transport);
            client.driver_.notify();
            while (!stop.stop_requested() && !external.stop_requested() && !response.rejected && !hooks.conn_closed &&
                   !bundle.app.stopping() && Clock::now() < deadline) {
                if (observe && response.headers) {
                    for (auto const& [name, value] : response.result.fields)
                        if (!name.starts_with(':')) (*observe)(name, value);
                    observe.reset();
                }
                if (sink && !response.result.body.empty()) {
                    // The driver may append to the receive buffer while the sink waits.
                    // The bytes occupy QUIC receive credit until the sink accepts them.
                    auto chunk = std::exchange(response.result.body, std::string{});
                    if (!co_await (*sink)(chunk, deadline) || stop.stop_requested() || Clock::now() >= deadline)
                        break;
                    if (response.complete || response.closed || response.rejected)
                        bundle.app.discard_body(chunk.size());
                    else if (!bundle.app.consume_body(response.id, chunk.size())) break;
                    response.uncredited -= chunk.size();
                    client.driver_.notify();
                    continue;
                }
                if (response.complete) co_return std::move(response.result);
                client.driver_.changed().clear();
                if (external.stop_requested()) break;
                auto [error] = co_await corosio::timeout(client.driver_.changed().wait(), deadline);
                if (error || !client.driver_.running()) break;
            }
            co_return std::unexpected(response.rejected ? HttpError::response : HttpError::transport);
        }

        template<class Client>
        static auto get_response(Client& client, std::string_view path, std::size_t limit, Clock::time_point deadline,
            std::span<http::HeaderField const> headers, bool allow_not_modified, bool allow_redirect = false,
            std::optional<HttpBodySink> sink = {}, std::optional<HttpHeaderSink> observe = {})
            -> capy::task<std::optional<HttpResponse>> {
            auto result = co_await exchange_http(client, path, limit, deadline, {}, headers, allow_not_modified, allow_redirect, sink, observe);
            if (!result) co_return std::nullopt;
            co_return std::move(*result);
        }

        template<class Client>
        static auto get(Client& client, std::string_view path, std::size_t limit, Clock::time_point deadline)
            -> capy::task<std::optional<std::string>> {
            auto response = co_await get_response(client, path, limit, deadline, {}, false);
            if (!response) co_return std::nullopt;
            co_return std::move(response->body);
        }

        template<class Client>
        static auto post(Client& client, std::string_view path, HttpPost body, std::size_t limit, Clock::time_point deadline,
            std::stop_token stop = {}) -> capy::task<std::expected<HttpResponse, HttpError>> {
            return exchange_http(client, path, limit, deadline, body, {}, false, false, {}, {}, stop);
        }
    };
}
