export module naive.h2_server;
import std;
import naive.padding;
import naive.h2_connect;
import http2.headers;
import http2.client_types;
import http2.server_streams;
import http2.driver;
import nexus.thirdparty.capy;

export namespace naive {
    struct H2ServerDriverPolicy {
        using Failure = http2::ClientFailure;
        static auto canceled_failure() noexcept -> Failure { return {http2::ClientError::canceled}; }
        static auto transport_failure(bool timeout) noexcept -> Failure {
            return {timeout ? http2::ClientError::timeout : http2::ClientError::transport};
        }
        static auto protocol_failure() noexcept -> Failure { return {http2::ClientError::http2}; }
        template<class Error>
        static auto read_failure(Error const&, bool timeout) noexcept -> Failure {
            return {timeout ? http2::ClientError::timeout : http2::ClientError::transport};
        }
        static auto input_complete(http2::ServerStreams<kH2StreamCapacity> const& session) noexcept -> bool {
            return session.draining() && session.all_closed();
        }
        static auto finish_after_drain(http2::ServerStreams<kH2StreamCapacity> const& session) noexcept -> bool {
            return input_complete(session);
        }
        static auto on_stop(http2::ServerStreams<kH2StreamCapacity>& session, Failure failure) noexcept -> void {
            session.cancel(failure);
        }
        template<class Driver>
        static auto after_receive(Driver&) noexcept -> void {}
    };

    template<class Lower>
    using H2ServerDriver = http2::detail::Driver<Lower, http2::ServerStreams<kH2StreamCapacity>, H2ServerDriverPolicy>;

    template<class Lower>
    class H2ServerStream {
        H2ServerDriver<Lower>& driver_;
        http2::StreamTicket ticket_;
        PaddingEncoder encoder_{false};
        PaddingDecoder decoder_{false};
        std::vector<std::uint8_t> encoded_;
        std::vector<std::uint8_t> decoded_;
        std::size_t decoded_offset_ = 0;
        bool responded_ = false;
        bool released_ = false;

    public:
        H2ServerStream(H2ServerDriver<Lower>& driver, http2::StreamTicket ticket) noexcept
            : driver_(driver), ticket_(ticket) {}
        ~H2ServerStream() { release(); }
        H2ServerStream(H2ServerStream const&) = delete;
        auto operator=(H2ServerStream const&) -> H2ServerStream& = delete;

        auto release() noexcept -> void {
            if (std::exchange(released_, true)) return;
            auto state = driver_.protocol().inspect(ticket_);
            driver_.protocol().release(ticket_, !state || !state->local_end || !state->remote_end);
            driver_.wake();
        }

        auto arm_padding(bool enabled) noexcept -> void {
            encoder_ = PaddingEncoder{enabled};
            decoder_ = PaddingDecoder{enabled};
        }

        auto inspect() noexcept { return driver_.protocol().inspect(ticket_); }

        auto failure() noexcept -> bool {
            auto st = inspect();
            return !st || st->failure.has_value();
        }

        auto wait(Deadline until = {}) { return driver_.wait_change(until); }

        auto respond(std::span<http2::FieldView const> fields, bool end_stream) -> bool {
            if (!driver_.protocol().respond(ticket_, fields, end_stream)) return false;
            responded_ = true;
            driver_.wake();
            return true;
        }

        auto send_raw_chunk(std::span<std::uint8_t const> bytes, bool end_stream, Deadline until = {}) -> nex::capy::task<bool> {
            if (!responded_) co_return false;
            for (;;) {
                auto res = driver_.protocol().provide(ticket_, {bytes, end_stream});
                if (!res) co_return false;
                if (*res) break;
                if (!co_await driver_.wait_change(until)) co_return false;
            }
            driver_.wake();
            for (;;) {
                auto sent = driver_.protocol().tx_consumed(ticket_);
                if (!sent) co_return false;
                if (*sent) break;
                if (!co_await driver_.wait_change(until)) co_return false;
            }
            if (end_stream) {
                for (;;) {
                    auto st = inspect();
                    if (!st || st->failure) co_return false;
                    if (st->local_end && driver_.output_drained()) co_return true;
                    if (!co_await driver_.wait_change(until)) co_return false;
                }
            }
            co_return true;
        }

        auto respond_decoy(std::uint16_t status, Deadline until = {}) -> nex::capy::task<bool> {
            auto status_str = std::to_string(status);
            auto body = decoy_html_body(status);
            auto len_str = std::to_string(body.size());
            std::array<http2::FieldView, 4> hdrs{
                http2::FieldView{":status", status_str},
                http2::FieldView{"content-type", "text/html; charset=utf-8"},
                http2::FieldView{"server", "nginx"},
                http2::FieldView{"content-length", len_str},
            };
            if (!respond(hdrs, false)) co_return false;
            co_return co_await send_raw_chunk(
                {reinterpret_cast<std::uint8_t const*>(body.data()), body.size()}, true, until);
        }

        auto respond_407(Deadline until = {}) -> nex::capy::task<bool> {
            std::array<http2::FieldView, 3> hdrs{
                http2::FieldView{":status", "407"},
                http2::FieldView{"proxy-authenticate", "Basic realm=\"Nexus\""},
                http2::FieldView{"content-length", "0"},
            };
            if (!respond(hdrs, true)) co_return false;
            for (;;) {
                auto st = inspect();
                if (!st || st->failure) co_return false;
                if (st->local_end && driver_.output_drained()) co_return true;
                if (!co_await driver_.wait_change(until)) co_return false;
            }
        }

        auto read(std::span<std::uint8_t> out, Deadline until = {})
            -> nex::capy::task<std::expected<std::size_t, std::string>> {
            if (out.empty()) co_return std::size_t{0};
            std::array<std::uint8_t, 16384> scratch{};
            for (;;) {
                if (decoded_offset_ < decoded_.size()) {
                    auto count = std::min(out.size(), decoded_.size() - decoded_offset_);
                    std::copy_n(decoded_.begin() + static_cast<std::ptrdiff_t>(decoded_offset_), count, out.begin());
                    decoded_offset_ += count;
                    if (decoded_offset_ == decoded_.size()) {
                        decoded_.clear();
                        decoded_offset_ = 0;
                    }
                    co_return count;
                }
                auto res = driver_.protocol().pull(ticket_, decoder_.in_passthrough() ? out : std::span(scratch));
                if (!res) co_return std::unexpected("HTTP/2 server pull failed");
                if (*res) {
                    driver_.wake();
                    if (!**res) co_return std::size_t{0};
                    if (decoder_.in_passthrough()) co_return **res;
                    decoded_.clear();
                    decoded_offset_ = 0;
                    if (!decoder_.feed(std::span(scratch).first(**res), decoded_))
                        co_return std::unexpected("NaiveProxy padding decode failed");
                    continue;
                }
                if (!co_await driver_.wait_change(until))
                    co_return std::unexpected("HTTP/2 server read closed");
            }
        }

        auto send(std::span<std::uint8_t const> in, Deadline until = {}) -> nex::capy::task<bool> {
            if (in.empty()) co_return true;
            std::span<std::uint8_t const> wire = in;
            if (!encoder_.in_passthrough()) {
                encoded_.clear();
                encoder_.encode(in, encoded_);
                wire = encoded_;
            }
            while (!wire.empty()) {
                auto chunk = wire.first(std::min<std::size_t>(wire.size(), 1024 * 1024));
                if (!co_await send_raw_chunk(chunk, false, until)) co_return false;
                wire = wire.subspan(chunk.size());
            }
            co_return true;
        }

        auto close_output(Deadline until = {}) -> nex::capy::task<bool> {
            co_return co_await send_raw_chunk({}, true, until);
        }

        auto cancel() noexcept -> void { release(); }
    };
}
