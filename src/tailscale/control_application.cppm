export module tailscale.control_application;
import std;
import tailscale.control;
import tailscale.control_messages;
import tailscale.map_session;
import tailscale.snapshot;
import http2.client_channel;
import memory.budget;
import nexus.thirdparty.capy;

export namespace tailscale::control_application {
    namespace cm = control_messages;
    using Clock = std::chrono::steady_clock;
    enum class Error { allocation, register_encoding, register_denied, endpoint_update, map_request,
                       map_stream, map_policy, timeout, ended };

    struct Options {
        std::string_view authority;
        cm::RegisterRequest registration;
        std::span<const cm::Endpoint> endpoints;
        std::uint64_t connection_generation;
        std::chrono::seconds map_idle = std::chrono::seconds(90);
        bool* registered = nullptr;
        std::optional<cm::DiscoKey> disco;
    };

    namespace detail {
        using Bytes = std::span<const std::uint8_t>;
        using Body = std::vector<std::uint8_t>;
        using capy_result = std::expected<void, Error>;

        inline auto fields(std::string_view authority, std::string_view path, std::string_view length)
            -> std::array<http2::FieldView,6> {
            return {{{":method", "POST"}, {":scheme", "https"}, {":authority", authority},
                     {":path", path}, {"content-type", "application/json"}, {"content-length", length}}};
        }

        template<class Channel>
        auto submit(Channel& channel, std::string_view authority, std::string_view path, Bytes body) {
            auto length = std::to_string(body.size());
            return channel.submit(fields(authority, path, length), {body, true});
        }

        template<class Channel> struct Borrow {
            Channel& channel;
            bool released = false;
            ~Borrow() { if (!released) channel.cancel(); }
        };

        struct Response {
            unsigned status = 0;
            Body body;
        };

        template<class Channel>
        auto collect(Channel& channel, http2::StreamTicket ticket, Clock::time_point deadline)
            -> nex::capy::task<std::optional<Response>> {
            constexpr std::size_t max_reply = 16384;
            Response result;
            while (Clock::now() < deadline) {
                auto response = channel.response(ticket);
                auto data = channel.peek(ticket);
                if (!response || !data || response->failure) co_return std::nullopt;
                result.status = response->status;
                if (!data->empty()) {
                    if (data->size() > max_reply - result.body.size()) co_return std::nullopt;
                    result.body.append_range(*data);
                    if (!channel.consume(ticket, data->size())) co_return std::nullopt;
                    continue;
                }
                if (response->remote_end && response->closed) {
                    auto released = channel.release(ticket);
                    if (!released) co_return std::nullopt;
                    if (*released) co_return result;
                }
                if (!co_await channel.wait_change(deadline)) break;
            }
            co_return std::nullopt;
        }

        inline auto bytes(std::string_view value) noexcept -> Bytes {
            return {reinterpret_cast<const std::uint8_t*>(value.data()), value.size()};
        }

        template<class Channel>
        auto update_endpoints(Channel& channel, Options const& options, Clock::time_point deadline)
            -> nex::capy::task<capy_result> {
            auto update = cm::encode_map_request(options.registration.node, cm::MapRequestMode::endpoints, options.endpoints, options.disco);
            if (!update) co_return std::unexpected(Error::endpoint_update);
            auto ticket = submit(channel, options.authority, "/machine/map", bytes(*update));
            if (!ticket) co_return std::unexpected(Error::endpoint_update);
            Borrow update_body{channel};
            auto updated = co_await collect(channel, *ticket, deadline);
            if (!updated || updated->status != 200 || !updated->body.empty())
                co_return std::unexpected(Error::endpoint_update);
            update_body.released = true;
            co_return capy_result{};
        }

        template<class Channel>
        auto register_and_update(Channel& channel, Options const& options, Clock::time_point deadline)
            -> nex::capy::task<capy_result> {
            if (!options.registered || !*options.registered) {
                std::array<std::uint8_t, 16384> storage{};
                auto wire = cm::encode_register(storage, options.registration);
                if (!wire) co_return std::unexpected(Error::register_encoding);
                auto registration = submit(channel, options.authority, "/machine/register", wire->bytes());
                if (!registration) co_return std::unexpected(Error::register_denied);
                Borrow registration_body{channel};
                auto reply = co_await collect(channel, *registration, deadline);
                if (!reply) co_return std::unexpected(Error::register_denied);
                registration_body.released = true;
                wire->clear();
                auto decision = cm::parse_register(reply->status, reply->body);
                if (!decision || decision->state != cm::RegistrationState::authorized)
                    co_return std::unexpected(Error::register_denied);
                if (options.registered) *options.registered = true;
            }

            co_return co_await update_endpoints(channel,options,deadline);
        }
    }

    template<class Channel>
    auto update_endpoints(Channel& channel, std::string_view authority, control::NodePublic node,
                          std::span<cm::Endpoint const> endpoints, std::optional<cm::DiscoKey> disco,
                          Clock::time_point deadline) -> nex::capy::task<std::expected<void, Error>> {
        Options options{authority,{node},endpoints,0};
        options.disco=disco;
        co_return co_await detail::update_endpoints(channel,options,deadline);
    }

    // Run alongside the authenticated connection's single H2 driver and join
    // both tasks before destroying it. Sink installs a view synchronously. It
    // must stop forwarding on revoke and must never retain borrowed Map data.
    template<class Channel, class Sink>
    auto run(Channel& channel, Options const& options, Sink& sink,
             std::shared_ptr<memory::Budget> const& budget, Clock::time_point deadline)
        -> nex::capy::task<detail::capy_result> {
        struct Drain {
            Channel& channel;
            Sink& sink;
            ~Drain() { sink.revoke(); channel.cancel(); }
        } drain{channel, sink};
        using State = map_session::State;
        using Scratch = snapshot::Scratch;
        auto charge = memory::Budget::reserve(budget, cm::max_json_bytes + sizeof(State) +
                                               sizeof(cm::MapCandidate) + sizeof(Scratch) + 65536);
        if (!charge) co_return std::unexpected(Error::allocation);
        if (!options.connection_generation || options.map_idle <= std::chrono::seconds(0))
            co_return std::unexpected(Error::map_request);
        auto registered = co_await detail::register_and_update(channel, options, deadline);
        if (!registered) co_return std::unexpected(registered.error());

        auto frame = std::make_unique<std::uint8_t[]>(cm::max_json_bytes);
        auto candidate = std::make_unique<cm::MapCandidate>();
        auto state = std::make_unique<State>();
        auto scratch = std::make_unique<Scratch>();
        struct RevokeBeforeStateDestruction {
            Sink& sink;
            ~RevokeBeforeStateDestruction() { sink.revoke(); }
        } revoke{sink};
        auto request = cm::encode_map_request(options.registration.node, cm::MapRequestMode::stream, {}, options.disco);
        if (!request) co_return std::unexpected(Error::map_request);
        auto ticket = detail::submit(channel, options.authority, "/machine/map", detail::bytes(*request));
        if (!ticket) co_return std::unexpected(Error::map_request);
        detail::Borrow map_body{channel};
        map_session::Session map({options.registration.node, options.connection_generation, ticket->generation},
                                 std::span(frame.get(), cm::max_json_bytes), *candidate, *state, *scratch);
        if (!map.active()) co_return std::unexpected(Error::map_stream);

        auto expires = deadline;
        std::uint64_t revision = 0;
        while (Clock::now() < expires) {
            auto response = channel.response(*ticket);
            auto data = channel.peek(*ticket);
            if (!response || !data || response->failure || (response->status && response->status != 200))
                co_return std::unexpected(Error::map_stream);
            if (!data->empty()) {
                if (response->status != 200) co_return std::unexpected(Error::map_stream);
                auto ordinal = map.ordinal();
                auto result = map.feed(*data);
                if (result.error || result.consumed != data->size()) co_return std::unexpected(Error::map_policy);
                if (auto next = state->revision(); next && next != revision) {
                    if (!sink.install(*state)) co_return std::unexpected(Error::map_policy);
                    revision = next;
                }
                if (!channel.consume(*ticket, result.consumed)) co_return std::unexpected(Error::map_stream);
                if (state->ready() && map.ordinal() != ordinal) expires = Clock::now() + options.map_idle;
                continue;
            }
            if (response->remote_end && response->closed) {
                if (!map.eof()) co_return std::unexpected(Error::map_stream);
                co_return std::unexpected(Error::ended);
            }
            if (!co_await channel.wait_change(expires)) break;
        }
        co_return std::unexpected(Error::timeout);
    }
}
