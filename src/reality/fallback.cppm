export module reality.fallback;
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace reality {
    namespace detail {
        // Each direction owns its buffer until its outstanding write completes.
        template<class Socket,class Touch,class Reset>
        auto fallback_direction(Socket& source, Socket& destination, std::span<std::uint8_t const> prefix,
            std::span<std::uint8_t const> suffix, Touch& touch,Reset& reset)
            -> nex::capy::quitter<bool> {
            auto propagate=[&](std::error_code error,Socket& peer) {
                if (error==std::errc::connection_reset || error==std::errc::connection_aborted ||
                    error==std::errc::broken_pipe) reset(peer);
            };
            auto write = [&](std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                while (!bytes.empty()) {
                    auto [error,n]=co_await destination.write_some(nex::capy::const_buffer(bytes.data(),bytes.size()));
                    if (error || !n || n>bytes.size()) {propagate(error,source);co_return false;}
                    touch(); bytes=bytes.subspan(n);
                }
                co_return true;
            };
            if (!co_await write(prefix) || !co_await write(suffix)) co_return false;
            std::array<std::uint8_t,16384> bytes{};
            for (;;) {
                auto [error,n]=co_await source.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size()));
                if (error==nex::capy::cond::eof) co_return !destination.shutdown(nex::corosio::shutdown_send);
                if (error || !n || n>bytes.size()) {propagate(error,destination);co_return false;}
                touch();
                if (!co_await write(std::span{bytes}.first(n))) co_return false;
            }
        }
        template<class Socket>
        auto fallback_join_direction(Socket& first,Socket& second, nex::capy::quitter<bool> direction)
            -> nex::capy::task<nex::capy::results<>> {
            try {
                if (co_await std::move(direction)) co_return nex::capy::results<>{};
                first.cancel(); second.cancel();
                co_return nex::capy::results<>{std::make_error_code(std::errc::io_error)};
            } catch (...) { first.cancel(); second.cancel(); throw; }
        }
    }
    // Connected sockets and prefix outlive the operation. Prefix is forwarded
    // and suffix before reading further client bytes; both directions preserve half-close.
    // Cancellation is owned by the caller, which must cancel both sockets and
    // drain this task before destroying them or either span.
    struct NoTouch { void operator()() const noexcept {} };
    struct NoReset { void operator()(auto&) const noexcept {} };
    template<class Socket,class Touch=NoTouch,class Reset=NoReset>
    auto fallback(Socket& client,Socket& cover,std::span<std::uint8_t const> prefix,
                  std::span<std::uint8_t const> suffix = {}, Touch touch = {}, Reset reset = {}) -> nex::capy::task<bool> {
        try {
            auto [error,first,second]=co_await nex::capy::when_all(
                detail::fallback_join_direction(client,cover,detail::fallback_direction(client,cover,prefix,suffix,touch,reset)),
                detail::fallback_join_direction(client,cover,detail::fallback_direction(cover,client,{},{},touch,reset)));
            co_return !error;
        } catch (...) { client.cancel(); cover.cancel(); throw; }
    }
}
