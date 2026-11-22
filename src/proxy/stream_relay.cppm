export module proxy.stream_relay;
import std;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import net.stream_relay;

export namespace proxy::stream_relay {
    // Inbound supplies read, send and close_output operations for a byte stream.
    // Session owns either the direct socket or the selected outbound stream.
    // Both directions run on the session's executor; its owner must drain them.
    struct NoHooks {};

    // A successful dial fixes the tunnel choice until both directions drain.
    // Session::close cancels that tunnel without replacing it.
    template<class Hooks,class Session,class Inbound,bool Upload,bool Tunnel>
    struct InboundAdapter {
        Session& session;
        Inbound& incoming;
        static constexpr bool socket_input=!Upload && !Tunnel;
        static constexpr bool socket_output=Upload && !Tunnel;
        static constexpr bool locked_output=false;

        auto start() -> bool {
            if constexpr (Upload) { if constexpr (requires { Hooks::upload(); }) Hooks::upload(); }
            else { if constexpr (requires { Hooks::download(); }) Hooks::download(); }
            return true;
        }
        auto read(std::span<std::uint8_t> bytes) {
            if constexpr (Upload) return incoming.read(bytes);
            else if constexpr (Tunnel) return session.tunnel->read(bytes);
            else return session.target.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size()));
        }
        template<class Error> auto eof(Error const& error,std::size_t) { return nex::capy::is_eof(error); }
        template<class Error> auto invalid_read(Error const& error,std::size_t n,std::size_t size) {
            return error || !n || n>size || session.closed;
        }
        template<class Result> auto invalid_read(Result const& result) { return !result || session.closed; }
        auto read_failed() {}
        auto after_read() { session.touched=std::chrono::steady_clock::now(); }
        auto meters_output() const requires requires {session.meters_principal_bytes();} {
            return session.meters_principal_bytes();
        }
        auto reserve_output(std::size_t size) requires requires {session.reserve_principal_stream(Upload,size);} {
            return session.reserve_principal_stream(Upload,size);
        }
        auto close_now() requires (Upload && !Tunnel) { return !session.target.shutdown(nex::corosio::shutdown_send); }
        auto close_output() requires (!Upload || Tunnel) {
            if constexpr (Upload) return session.tunnel->close_output();
            else return incoming.close_output();
        }
        auto write(std::span<std::uint8_t const> bytes) {
            if constexpr (!Upload) return incoming.send(bytes);
            else if constexpr (Tunnel) return session.tunnel->send(bytes);
            else return session.target.write_some(nex::capy::const_buffer(bytes.data(),bytes.size()));
        }
        template<class Error> auto invalid_write(Error const& error,std::size_t n,std::size_t size) {
            return error || !n || n>size || session.closed;
        }
        auto write_failed() {}
        auto after_write() {}
        auto delivered(std::size_t size) {
            if constexpr (Upload || !requires {incoming.accounts_download;})
                session.count_traffic(Upload,size);
        }
    };

    template<class Hooks=NoHooks,class Session,class Inbound>
    auto upload(Session& session,Inbound& incoming) -> nex::capy::quitter<bool> {
        if (session.tunnel) return net::stream_relay::transfer<nex::capy::quitter>(InboundAdapter<Hooks,Session,Inbound,true,true>{session,incoming});
        return net::stream_relay::transfer<nex::capy::quitter>(InboundAdapter<Hooks,Session,Inbound,true,false>{session,incoming});
    }

    template<class Hooks=NoHooks,class Session,class Inbound>
    auto download(Session& session,Inbound& incoming) -> nex::capy::quitter<bool> {
        if (session.tunnel) return net::stream_relay::transfer<nex::capy::quitter>(InboundAdapter<Hooks,Session,Inbound,false,true>{session,incoming});
        return net::stream_relay::transfer<nex::capy::quitter>(InboundAdapter<Hooks,Session,Inbound,false,false>{session,incoming});
    }

    // A failed direction closes the session before the join cancels and drains
    // its sibling. Successful EOF leaves the other direction running.
    template<class Observer=NoHooks,class Session>
    auto direction(Session& session,nex::capy::quitter<bool> operation) -> nex::capy::task<nex::capy::results<>> {
        [[maybe_unused]] Observer observer;
        try {
            if (co_await std::move(operation)) co_return nex::capy::results<>{};
            session.close();
            co_return nex::capy::results<>{std::make_error_code(std::errc::io_error)};
        } catch (...) {
            session.close();
            throw;
        }
    }
}
