export module httpupgrade.stream;
import std;
import httpupgrade;
import net.socket_stream;
import net.buffered_input;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace httpupgrade {
    using Clock=std::chrono::steady_clock;
    using Deadline=net::StreamDeadline;
    using net::SocketByteStream;
    enum class Error { state,transport,timeout,rejected,truncated };
    struct Failure { Error error; Status status=Status::incomplete; };
    // Owning, bounded handoff. The caller feeds these bytes to the next
    // protocol before reading the same lower stream again. HTTPUpgrade has
    // no data-phase records or per-block wrapper after this handoff.
    struct Ready { std::vector<std::uint8_t> unread; };
    namespace detail {
        template<class Stream>
        struct CancelGuard {
            Stream& stream;
            bool released=false;
            ~CancelGuard() { if (!released) stream.cancel(); }
        };
        struct HeaderReadState {
            using Result=std::expected<Ready,Failure>;
            net::BufferedInput<4096> window;
            HeaderDecoder decoder;
            explicit HeaderReadState(Profile const& profile) : decoder(profile) {}
            auto input() noexcept -> net::BufferedInput<4096>& {return window;}
            auto abort() noexcept -> void {decoder.close();}
            auto feed(std::span<std::uint8_t> input) noexcept -> net::InputStep {
                auto fed=decoder.feed(input);
                return {fed.consumed,1,fed.status==Status::incomplete ? net::InputAction::more :
                    fed.status==Status::accepted ? net::InputAction::complete : net::InputAction::fail};
            }
            auto finish(net::InputStatus status) -> Result {
                if (status==net::InputStatus::ready) {
                    Ready result;auto unread=window.pending();result.unread.assign(unread.begin(),unread.end());return result;
                }
                if (status==net::InputStatus::timeout) return std::unexpected(Failure{Error::timeout});
                if (status==net::InputStatus::eof) return std::unexpected(Failure{Error::truncated,decoder.finish()});
                if (status==net::InputStatus::consumer) return std::unexpected(Failure{Error::rejected,decoder.status()});
                return std::unexpected(Failure{Error::transport});
            }
        };
        template<class Stream>
        auto read_header(Stream& stream,Profile const& profile,Clock::time_point deadline)
            -> nex::capy::task<std::expected<Ready,Failure>> {
            return net::BufferedInput<4096>::drive(stream,[&profile] {return HeaderReadState(profile);},deadline);
        }
    }
    // Stream exposes read(span, optional absolute deadline), complete
    // send(span, deadline) and cancel(). TLS/authentication, dialing and
    // ownership remain with that stream. All header operations reuse the
    // caller's deadline, with no reset after partial input or output.
    template<class Stream>
    auto connect(Stream& stream,Profile const& profile,Clock::time_point deadline)
        -> nex::capy::task<std::expected<Ready,Failure>> {
        detail::CancelGuard guard{stream};
        if (!profile.is_client()) co_return std::unexpected(Failure{Error::state});
        if (Clock::now()>=deadline) co_return std::unexpected(Failure{Error::timeout});
        auto wire=profile.wire();
        if (!co_await stream.send({reinterpret_cast<std::uint8_t const*>(wire.data()),wire.size()},deadline))
            co_return std::unexpected(Failure{Clock::now()>=deadline ? Error::timeout : Error::transport});
        auto accepted=co_await detail::read_header(stream,profile,deadline);
        if (!accepted) co_return std::unexpected(accepted.error());
        guard.released=true; co_return std::move(*accepted);
    }
    template<class Stream>
    auto accept(Stream& stream,Profile const& profile,Clock::time_point deadline)
        -> nex::capy::task<std::expected<Ready,Failure>> {
        detail::CancelGuard guard{stream};
        if (profile.is_client()) co_return std::unexpected(Failure{Error::state});
        auto accepted=co_await detail::read_header(stream,profile,deadline);
        if (!accepted) co_return std::unexpected(accepted.error());
        if (Clock::now()>=deadline) co_return std::unexpected(Failure{Error::timeout});
        auto wire=profile.wire();
        if (!co_await stream.send({reinterpret_cast<std::uint8_t const*>(wire.data()),wire.size()},deadline))
            co_return std::unexpected(Failure{Clock::now()>=deadline ? Error::timeout : Error::transport});
        if (Clock::now()>=deadline) co_return std::unexpected(Failure{Error::timeout});
        guard.released=true; co_return std::move(*accepted);
    }
}
