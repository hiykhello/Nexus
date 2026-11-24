module relay:xhttp_http3_server;
import std;
import http2.client_types;
import http2.server_streams;
import xhttp.wire;
import capy;
import :types;
import :session_interface;
import :xhttp_http1;
import :xhttp_http3_streams;
import :xhttp_http3_channel;

namespace relay::vless_xhttp {
    template<class Channel>
    class Http3Request {
        Channel& channel_;
        Session& owner_;
        std::int64_t id_;
    public:
        Http3Request(Channel& channel, Session& owner, std::int64_t id) noexcept : channel_(channel), owner_(owner), id_(id) {}
        ~Http3Request() { cancel(); }
        auto inspect() noexcept -> std::optional<http2::IncomingView> {
            auto* stream = channel_.state(id_);
            if (!stream || stream->failed || stream->retired) return {};
            return http2::IncomingView{stream->headers, stream->fin_written, stream->remote_end, stream->closed, {}};
        }
        auto failure() noexcept -> bool { return !inspect(); }
        auto wait(Deadline until = {}) { return channel_.wait(until); }
        auto cancel() noexcept -> void { channel_.release(id_); }
        template<class Profile>
        auto respond(Profile const& profile, std::string_view status, bool body) -> bool {
            auto random = entropy();
            if (!random) return false;
            auto padding = xhttp::padding_bytes(profile.transport.padding, *random);
            std::array fields{h3_field(":status", status), h3_field("x-padding", padding),
                h3_field("x-accel-buffering", "no"), h3_field("cache-control", "no-store")};
            return channel_.respond(id_, std::span(fields).first(body ? fields.size() : 2), body);
        }
        auto read(std::span<std::uint8_t> output, Deadline until = {}) -> capy::task<std::expected<std::size_t, IoError>> {
            auto result = co_await channel_.read(id_, output, until);
            if (result && *result) owner_.touched = Clock::now();
            co_return result;
        }
        auto send(std::span<std::uint8_t const> input, Deadline until = {}) -> capy::task<bool> {
            if (!channel_.body(id_, input, false)) co_return false;
            auto sent = co_await channel_.wait_sent(id_, false, until);
            if (sent) owner_.touched = Clock::now();
            co_return sent;
        }
        auto wait_sent(Deadline until = {}) { return channel_.wait_sent(id_, true, until); }
        auto close_output(Deadline until = {}) -> capy::task<bool> {
            if (!channel_.body(id_, {}, true)) co_return false;
            co_return co_await wait_sent(until);
        }
    };
}
