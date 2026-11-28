module relay:xhttp_http2_server;
import std;
import http2.driver;
import http2.server_streams;
import http2.client_types;
import http2.headers;
import memory.budget;
import rules;
import xhttp.config;
import xhttp.server;
import xhttp.wire;
import capy;
import corosio;
import :types;
import :session_interface;
import :xhttp_http1;
import :xhttp_inbound_types;

namespace relay::vless_xhttp {
    using H2Ticket = http2::StreamTicket;
    using H2Session = http2::ServerStreams<16>;
    struct H2Policy {
        using Failure = http2::ClientFailure;
        static auto canceled_failure() noexcept -> Failure { return {http2::ClientError::canceled}; }
        static auto transport_failure(bool timeout) noexcept -> Failure { return {timeout ? http2::ClientError::timeout : http2::ClientError::transport}; }
        static auto protocol_failure() noexcept -> Failure { return {http2::ClientError::http2}; }
        static auto input_complete(H2Session const& session) noexcept -> bool { return session.draining() && session.all_closed(); }
        static auto finish_after_drain(H2Session const& session) noexcept -> bool { return input_complete(session); }
        static auto on_stop(H2Session& session, Failure failure) noexcept -> void { session.cancel(failure); }
        template<class Driver> static auto after_receive(Driver&) noexcept -> void {}
    };
    using H2Driver = http2::detail::Driver<Lower, H2Session, H2Policy>;

    class H2Request {
        H2Driver& driver_;
        Session& owner_;
        H2Ticket ticket_;
        bool responded_ = false;
    public:
        H2Request(H2Driver& driver, Session& owner, H2Ticket ticket) noexcept : driver_(driver), owner_(owner), ticket_(ticket) {}
        ~H2Request() {
            auto state = inspect();
            driver_.protocol().release(ticket_, !state || !state->local_end || !state->remote_end);
            driver_.wake();
        }
        auto inspect() noexcept -> std::expected<http2::IncomingView, http2::ClientFailure> { return driver_.protocol().inspect(ticket_); }
        auto failure() noexcept -> bool { auto state = inspect(); return !state || state->failure.has_value(); }
        auto wait(Deadline until = {}) { return driver_.wait_change(until); }
        auto cancel() noexcept -> void { driver_.protocol().release(ticket_); driver_.wake(); }
        auto respond(InboundProfile const& profile, std::string_view status, bool stream) -> bool {
            auto random = entropy();
            if (!random) return false;
            auto padding = xhttp::padding_bytes(profile.transport.padding, *random);
            std::array fields{http2::FieldView{":status", status}, http2::FieldView{"x-padding", padding},
                http2::FieldView{"x-accel-buffering", "no"}, http2::FieldView{"cache-control", "no-store"}};
            auto count = stream ? fields.size() : 2;
            if (!driver_.protocol().respond(ticket_, std::span(fields).first(count), !stream)) return false;
            responded_ = true;
            driver_.wake();
            return true;
        }
        auto read(std::span<std::uint8_t> out, Deadline until = {})
            -> capy::task<std::expected<std::size_t, IoError>> {
            for (;;) {
                auto result = driver_.protocol().pull(ticket_, out);
                if (!result) co_return std::unexpected(IoError::io);
                if (*result) {
                    if (**result) { owner_.touched = Clock::now(); driver_.wake(); }
                    co_return **result;
                }
                if (!co_await wait(until)) co_return std::unexpected(until && Clock::now() >= *until ? IoError::timeout : IoError::io);
            }
        }
        auto send(std::span<std::uint8_t const> input, Deadline until = {}) -> capy::task<bool> {
            if (!responded_) co_return false;
            auto result = driver_.protocol().provide(ticket_, {input, false});
            if (!result || !*result) co_return false;
            driver_.wake();
            for (;;) {
                auto sent = driver_.protocol().tx_consumed(ticket_);
                if (!sent) co_return false;
                if (*sent) { owner_.touched = Clock::now(); co_return true; }
                if (!co_await wait(until)) co_return false;
            }
        }
        auto wait_sent(Deadline until = {}) -> capy::task<bool> {
            for (;;) {
                auto state = inspect();
                if (!state || state->failure) co_return false;
                if (state->local_end && driver_.output_drained()) co_return true;
                if (!co_await wait(until)) co_return false;
            }
        }
        auto close_output(Deadline until = {}) -> capy::task<bool> {
            auto result = driver_.protocol().provide(ticket_, {{}, true});
            if (!result || !*result) co_return false;
            driver_.wake();
            co_return co_await wait_sent(until);
        }
    };

    struct RequestMetadata {
        xhttp::RequestKind kind;
        std::string session;
        std::optional<std::uint64_t> sequence;
        std::optional<std::size_t> length;
    };

    inline auto request_metadata(InboundProfile const& profile, http2::IncomingView view) -> std::optional<RequestMetadata> {
        std::string_view method, target, authority;
        std::optional<std::size_t> length;
        std::vector<xhttp::Field> fields;
        for (auto const& field : view.headers) {
            if (field.name == ":method") method = field.value;
            else if (field.name == ":path") target = field.value;
            else if (field.name == ":authority") authority = field.value;
            else if (field.name == "content-length") {
                std::size_t count = 0;
                auto [end, error] = std::from_chars(field.value.data(), field.value.data() + field.value.size(), count);
                if (error != std::errc{} || end != field.value.data() + field.value.size() || length) return {};
                length = count;
            } else if (!field.name.starts_with(':')) fields.emplace_back(field.name, field.value);
        }
        auto const& endpoint = profile.transport.endpoint;
        if ((!endpoint.authority.empty() && endpoint.authority != authority) ||
            !xhttp::check_padding(profile.transport.padding, target, fields)) return {};
        auto path = xhttp::metadata(target, endpoint.path);
        if (!path) return {};
        auto kind = xhttp::classify(method, *path, profile.transport.mode, endpoint.version);
        if (!kind || (*kind == xhttp::RequestKind::download && (length.value_or(0) != 0 || !view.remote_end)) ||
            (*kind == xhttp::RequestKind::packet && (!length || !*length || *length > profile.transport.limits.post_bytes))) return {};
        return RequestMetadata{*kind, std::string(path->session), path->sequence, length};
    }

    template<class Request>
    auto accept_packet(Request& request, InboundProfile& profile, RequestMetadata const& meta, Clock::time_point until)
        -> capy::task<std::optional<std::pair<std::shared_ptr<Split>, bool>>> {
        auto charge = memory::Budget::reserve(profile.budget, *meta.length + 128);
        if (!charge) co_return std::nullopt;
        std::vector<std::uint8_t> input(*meta.length);
        std::size_t offset = 0;
        while (offset < input.size()) {
            auto size = co_await request.read(std::span(input).subspan(offset), until);
            if (!size || !*size) co_return std::nullopt;
            offset += *size;
        }
        std::array<std::uint8_t, 1> extra;
        auto ended = co_await request.read(extra, until);
        if (!ended || *ended) co_return std::nullopt;
        auto [split, created] = profile.find(meta.session);
        if (!split) co_return std::nullopt;
        auto& sides = split->sides;
        auto kind = xhttp::RequestKind::packet;
        if (sides.closed || sides.expired(Clock::now()) || (sides.upload && sides.upload != kind) ||
            !split->input.submit_owned(*meta.sequence, std::move(input), std::move(*charge))) {
            if (created) profile.retire(meta.session, split, true);
            co_return std::nullopt;
        }
        (void)sides.attach(kind, Clock::now());
        split->change.set();
        co_return std::pair{std::move(split), created};
    }

    template<class Request>
    auto stream_upload(Request& request, InboundProfile const& profile, Split& split) -> capy::task<> {
        std::array<std::uint8_t, 16384> input;
        auto const& limits = profile.transport.limits;
        auto block = std::span(input).first(std::min({input.size(), limits.post_bytes, limits.buffer_bytes}));
        while (!split.sides.closed) {
            auto deadline = split.sides.paired() ? Clock::now() + std::chrono::minutes(5) : split.sides.deadline;
            auto size = co_await request.read(block, deadline);
            if (!size) break;
            if (!*size) {
                split.upload_end = true;
                split.change.set();
                (void)co_await request.close_output(deadline);
                co_return;
            }
            while (!split.sides.closed && (split.input.pending() >= limits.buffered_posts ||
                    *size > limits.buffer_bytes - split.input.buffered_bytes())) {
                split.space.clear();
                auto [error] = co_await corosio::timeout(split.space.wait(), deadline);
                if (error) break;
            }
            if (!split.input.submit(split.sequence++, block.first(*size))) break;
            split.change.set();
        }
        split.input.close();
        split.sides.closed = true;
        split.change.set();
    }

    template<class Request>
    class SplitDownload {
        Request& response_;
        Split& split_;
    public:
        SplitDownload(Request& response, Split& split) noexcept : response_(response), split_(split) {}
        auto read(std::span<std::uint8_t> out, Deadline until = {}) { return read_split(split_, out, until); }
        auto packet_up() const noexcept -> bool { return split_.sides.upload == xhttp::RequestKind::packet; }
        auto send(std::span<std::uint8_t const> data, Deadline until = {}) { return response_.send(data, until); }
        auto close_output(Deadline until = {}) { return response_.close_output(until); }
        auto cancel() noexcept -> void { response_.cancel(); }
    };

    struct RelaySlots { bool primary = true; };

    template<class Request, class Stream>
    auto serve_stream_payload(Session& parent, corosio::io_context& context, rules::RouteProgram const& policy,
            InboundProfile const& profile, Request& request, Stream& stream, Clock::time_point until, RelaySlots& slots)
        -> capy::task<> {
        std::optional<SessionQuota::Lease> lease;
        bool primary = slots.primary;
        if (primary) slots.primary = false;
        else if (parent.quota) {
            lease = parent.quota->try_acquire();
            if (!lease) co_return;
        }
        struct Primary { RelaySlots& slots; bool loan; ~Primary() { if (loan) slots.primary = true; } } primary_guard{slots, primary};
        Session child(context);
        child.quota = std::move(lease);
        init_multiplexed_child(child, parent, until);
        std::stop_callback stopping(parent.stop.get_token(), [&]() noexcept { child.close(); });
        auto watch = [&]() -> capy::task<capy::results<>> {
            while (!child.closed && !request.failure() && co_await request.wait()) {}
            child.close();
            co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
        };
        auto relay = [&]() -> capy::task<capy::results<>> {
            (void)co_await payload(child, context, policy, profile, stream, until);
            co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
        };
        (void)co_await capy::when_all(watch(), relay());
    }

    template<class Request>
    auto handle_request(Session& session, corosio::io_context& context, rules::RouteProgram const& policy,
        InboundProfile& profile, Request& request, RelaySlots& slots) -> capy::task<> {
        auto until = Clock::now() + std::chrono::seconds(10);
        auto view = request.inspect();
        auto meta = view ? request_metadata(profile, *view) : std::nullopt;
        if (!meta) {
            if (request.respond(profile, "400", false)) (void)co_await request.wait_sent(until);
            co_return;
        }
        using Kind = xhttp::RequestKind;
        if (meta->kind == Kind::stream) {
            if (profile.sessions.size() + profile.streaming >= profile.transport.limits.sessions) {
                if (request.respond(profile, "503", false)) (void)co_await request.wait_sent(until);
                co_return;
            }
            ++profile.streaming;
            struct Release { InboundProfile& profile; ~Release() { --profile.streaming; } } release{profile};
            if (request.respond(profile, "200", true)) co_await serve_stream_payload(session, context, policy, profile, request, request, until, slots);
            co_return;
        }
        if (meta->kind == Kind::packet) {
            auto accepted = co_await accept_packet(request, profile, *meta, until);
            if (request.respond(profile, accepted ? "200" : "409", false)) (void)co_await request.wait_sent(until);
            if (accepted && accepted->second) {
                SplitOwner orphan{profile, meta->session, accepted->first, true, true};
                (void)co_await corosio::timeout(accepted->first->paired.wait(), accepted->first->sides.deadline);
            }
            co_return;
        }
        auto [split, created] = profile.find(meta->session);
        if (!split || !split->sides.attach(meta->kind, Clock::now())) {
            if (request.respond(profile, "409", false)) (void)co_await request.wait_sent(until);
            co_return;
        }
        if (meta->kind == Kind::upload) {
            SplitOwner orphan{profile, meta->session, split, created, true};
            split->change.set();
            if (request.respond(profile, "200", true)) co_await stream_upload(request, profile, *split);
            if (created && !split->sides.download && split->upload_end)
                (void)co_await corosio::timeout(split->paired.wait(), split->sides.deadline);
            co_return;
        }
        SplitOwner owner{profile, meta->session, split, true, false};
        split->paired.set();
        split->change.set();
        SplitDownload down(request, *split);
        if (request.respond(profile, "200", true))
            co_await serve_stream_payload(session, context, policy, profile, request, down, split->sides.deadline, slots);
    }

    inline auto h2_worker(Session& session, corosio::io_context& context, rules::RouteProgram const& policy,
        InboundProfile& profile, H2Driver& driver, RelaySlots& slots) -> capy::task<capy::results<>> {
        while (!session.closed) {
            auto accepted = driver.protocol().accept();
            if (!accepted) {
                if (!co_await driver.wait_change()) break;
                continue;
            }
            H2Request request(driver, session, *accepted);
            try { co_await handle_request(session, context, policy, profile, request, slots); }
            catch (...) { request.cancel(); }
        }
        co_return capy::results<>{};
    }
}
