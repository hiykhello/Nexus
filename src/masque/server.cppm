export module masque.server;
import std;
import masque.session;
import masque.http3;
import masque.udp_owner;
import masque.udp_session;
import masque.datagram;
import masque.capsule;
import masque.connect_ip;
import masque.ip_server;
import quic.connection;
import quic.http3;
import quic.http3_headers;
import net.udp_socket;
import ngtcp2;
import nghttp3;

export namespace masque {
    enum class SocketWatchState : std::uint8_t { inactive, ready, paused };

    struct StreamAccounting {
        void* owner=nullptr;
        bool (*open)(void*,std::int64_t,std::uint16_t,bool)=nullptr;
        void (*count)(void*,std::int64_t,bool,std::size_t) noexcept=nullptr;
        void (*close)(void*,std::int64_t) noexcept=nullptr;
        auto opened(std::int64_t id,std::uint16_t port,bool ip=false) const -> bool {
            return !open || open(owner,id,port,ip);
        }
        auto delivered(std::int64_t id,bool upstream,std::size_t bytes) const noexcept -> void {
            if (count && bytes) count(owner,id,upstream,bytes);
        }
        auto retired(std::int64_t id) const noexcept -> void {
            if (close) close(owner,id);
        }
    };

    // Server business owner, executor confined. Host resolves every claimed
    // target asynchronously, calls resolved() with a policy-checked numeric
    // candidate, and binds its QUIC connection. Host cancels and joins DNS,
    // poll and driver work before joined()/QUIC stop. Policy and allocator
    // contexts outlive this owner. URI handling is the well-known template.
    template<class Tls,class Policy,std::size_t Streams=16,std::size_t Mtu=1150> class UdpServer {
        static_assert(Streams && Mtu>8 && Mtu<=65527);
        using Self=UdpServer;
        struct State {
            std::int64_t id=-1;
            quic::Http3Headers<32,8192> headers;
            UdpCapsules<Mtu> capsules;
            std::optional<UdpHandle> handle;
            std::unique_ptr<IpServerStream> ip;
            std::array<std::uint8_t,std::max(Mtu,ip_server_mtu)+9> output{};
            std::size_t output_size=0,acked=0,output_payload=0;
            bool route_pending=false,claimed=false,ready=false,closed=false,submitted=false,rx_open=true,tx_open=true;
        };
    public:
        using Application=Session<Tls,Self>;
        using Transport=typename Application::Transport;
        struct Route {UdpHandle handle;std::string host;std::uint16_t port;};
        struct Packet {std::uint64_t stream;std::span<std::uint8_t const> payload;};
    private:
        std::array<std::optional<State>,Streams> states_;
        Policy& policy_;
        StreamAccounting accounting_;
        std::string authority_;
        IpServerPort* ip_port_;
        UdpOwner<Policy,Streams> owner_;
        Application application_;
        Transport* transport_=nullptr;
        std::array<std::optional<std::pair<std::int64_t,std::uint64_t>>,Streams> aborts_{};
        std::size_t cursor_=0;
        bool stopping_=false;
        bool ip_withdrawing_=false;
        auto find(std::int64_t id) noexcept -> State* {for(auto& s:states_)if(s && s->id==id)return &*s;return nullptr;}
        auto create(std::int64_t id) noexcept -> State* {for(auto& s:states_)if(!s){s.emplace();s->id=id;return &*s;}return nullptr;}
        auto revoke(State& state,std::uint64_t code) noexcept -> void {
            if(state.closed)return;state.closed=true;state.ready=false;state.route_pending=false;
            if(state.ip)state.ip->stop();
            if(state.handle)owner_.close(*state.handle);
            accounting_.retired(state.id);
            for(auto& abort:aborts_)if(!abort){abort=std::pair{state.id,code};changed();return;}
            std::terminate(); // at most one queued abort per bounded state
        }
        auto send_udp(State& state,std::span<std::uint8_t const> payload) -> bool {
            auto result=owner_.send(*state.handle,payload);
            if (result && *result==OwnerSend::sent) accounting_.delivered(state.id,true,payload.size());
            return result.has_value();
        }
        static auto field(std::string_view name,std::string_view value) noexcept -> nghttp3::nghttp3_nv {
            return {reinterpret_cast<std::uint8_t const*>(name.data()),reinterpret_cast<std::uint8_t const*>(value.data()),name.size(),value.size(),nghttp3::nv_flag_none};
        }
        auto response(std::int64_t id,bool accepted) -> int {
            std::array<nghttp3::nghttp3_nv,2> fields{field(":status",accepted ? "200" : "403"),field("capsule-protocol","?1")};
            return application_.h3().response(id,std::span(fields).first(accepted ? 2 : 1),accepted);
        }
        auto begin_ip(State& state, ConnectIpRequest request, bool fin) -> int {
            auto scope=parse_default_ip_path(request.path);
            if(fin || ip_withdrawing_ || !ip_port_ || !*ip_port_ || request.scheme!="https" || request.authority!=authority_ ||
               !policy_.authenticate(state.headers.fields()) || !scope) {
                state.closed=true;return response(state.id,false);
            }
            state.ip=std::make_unique<IpServerStream>(*ip_port_,std::move(*scope));
            if(!state.ip->start()) {state.ip.reset();state.closed=true;return response(state.id,false);}
            if (!accounting_.opened(state.id,0,true)) {
                state.ip->stop();state.closed=true;return response(state.id,false);
            }
            if(auto error=response(state.id,true)) {
                state.ip->stop();state.closed=true;accounting_.retired(state.id);return error;
            }
            state.ready=true;changed();return 0;
        }
    public:
        UdpServer(Tls& tls,Policy& policy,std::string authority,nghttp3::nghttp3_mem const& memory,IpServerPort* ip_port=nullptr)
            :policy_(policy),authority_(authority),ip_port_(ip_port),owner_(policy,std::move(authority)),application_(tls,*this,true,memory) {}
        UdpServer(UdpServer const&)=delete;
        auto operator=(UdpServer const&) -> UdpServer& = delete;
        auto close_stream(std::int64_t id) -> bool {
            if (auto* state=find(id)) revoke(*state,0x10c);
            return application_.flush_pending()==0;
        }
        auto observe_traffic(StreamAccounting accounting) noexcept -> void {accounting_=accounting;}
        auto attach(Transport& transport) noexcept -> void {transport_=&transport;application_.attach(transport);}
        auto application() noexcept -> Application& {return application_;}
        auto attach_transport(Transport& transport) noexcept -> void {attach(transport);}
        auto request_stop() noexcept -> void {stop();}
        auto stopping() const noexcept -> bool {return stopping_;}
        auto time(std::uint64_t now) noexcept -> void {application_.time(now);}
        auto output(std::span<std::uint8_t> bytes,std::uint64_t now,ngtcp2::ngtcp2_path* path=nullptr) -> std::expected<std::size_t,int> {return application_.output(bytes,now,path);}
        auto application_error() const noexcept -> std::uint64_t {return application_.application_error();}
        auto add_connection_id(ngtcp2::ngtcp2_cid const& id,ngtcp2::ngtcp2_stateless_reset_token const& token) noexcept -> int {
            if constexpr (requires {policy_.add_connection_id(id,token);}) return policy_.add_connection_id(id,token);
            else return 0;
        }
        auto remove_connection_id(ngtcp2::ngtcp2_cid const& id) noexcept -> int {
            if constexpr (requires {policy_.remove_connection_id(id);}) return policy_.remove_connection_id(id);
            else return 0;
        }
        // Host registrations must carry this generation-bearing handle.
        // Revalidate it after readiness; descriptor reuse alone is not identity.
        auto socket_handle(UdpHandle handle) noexcept -> std::optional<int> {return owner_.native_handle(handle);}
#ifdef NEXUS_TEST_MASQUE_HOST_LIFETIME
        auto close_for_test(UdpHandle handle) noexcept -> void {
            for(auto& state:states_)if(state && state->handle==handle){revoke(*state,0x10c);(void)application_.flush_pending();return;}
        }
#endif
        auto stream_capacity() const noexcept -> std::size_t {return Streams;}
        auto changed() noexcept -> void {static_assert(noexcept(policy_.changed()));policy_.changed();}
        auto pending(std::size_t slot) -> std::optional<Route> {
            if(slot>=Streams)return {};
            for(auto& state:states_)if(state && state->route_pending && !state->claimed && state->handle && state->handle->slot==slot) {
                auto target=owner_.pending(*state->handle);if(!target)continue;
                state->claimed=true;return Route{*state->handle,std::string(target->host),target->port};
            }
            return {};
        }
        auto pending_current(UdpHandle handle) noexcept -> bool {
            for(auto& state:states_)if(state && state->handle==handle && state->route_pending && !state->closed)return true;
            return false;
        }
        // Late DNS result after cancel/stop cannot reopen its generation.
        auto resolved(UdpHandle handle,net::UdpEndpoint endpoint) -> bool {
            if(stopping_)return false;
            for(auto& state:states_)if(state && state->handle==handle && state->route_pending && !state->closed) {
                if(!owner_.permits(handle,endpoint))return false;
                auto result=owner_.finish_resolve(handle,endpoint);state->route_pending=false;
                if(!result) {
                    if(!state->tx_open || response(state->id,false)) {
                        revoke(*state,0x10c);
                        if(application_.h3().terminal_error() || application_.flush_pending())stop();
                    } else {
                        owner_.close(handle);state->closed=true;accounting_.retired(state->id);
                    }
                    return false;
                }
                if(!state->tx_open || response(state->id,true)) {
                    revoke(*state,0x10c);
                    if(application_.h3().terminal_error() || application_.flush_pending())stop();
                    return false;
                }
                state->ready=true;changed();return true;
            }
            return false;
        }
        auto resolve_failed(UdpHandle handle) -> void {
            if(stopping_)return;
            for(auto& state:states_)if(state && state->handle==handle && state->route_pending && !state->closed) {
                state->route_pending=false;
                if(!state->tx_open || response(state->id,false)) {
                    revoke(*state,0x10c);
                    if(application_.h3().terminal_error() || application_.flush_pending())stop();
                } else {
                    state->closed=true;owner_.close(handle);accounting_.retired(state->id);
                }
                return;
            }
        }
        auto stopping() noexcept -> void {
            if (std::exchange(stopping_,true)) return;
            for (auto& state : states_) if (state) {
                state->ready=false;
                state->closed=true;
                state->route_pending=false;
                if (state->ip) state->ip->stop();
                accounting_.retired(state->id);
            }
            owner_.stop();
            changed();
        }
        auto stop() noexcept -> void {stopping();application_.request_stop();}
        auto joined() noexcept -> void {application_.joined();}
        auto drain() noexcept -> void {application_.drain();}
        auto clean() const noexcept -> bool {return owner_.drained() && application_.clean();}
        auto h3_closed() noexcept -> void {for(auto& s:states_)if(s)s->headers.clear();}
        auto transport_closed() noexcept -> void {stopping();}
        auto stream_state(std::uint64_t id) noexcept -> Http3StreamState {
            auto* s=find(id);return s && s->ready && !s->closed ? Http3StreamState{Http3StreamKind::datagram,s->rx_open,s->tx_open} : Http3StreamState{};
        }
        auto datagram(std::uint64_t id,std::span<std::uint8_t const> wire) -> int {
            auto* state=find(id);if(!state || !state->ready)return 0;
            if (state->ip) {
                auto valid=state->ip->datagram(wire);
                accounting_.delivered(state->id,true,state->ip->take_uploaded());
                if (!valid) revoke(*state,0x10e);
                return 0;
            }
            if(!state->handle)return 0;
            auto parsed=parse_proxy_datagram(wire,true);
            if(!parsed) {revoke(*state,0x33);return 0;}
            if(parsed->context_id)return 0;
            if(!send_udp(*state,parsed->payload))revoke(*state,0x102);
            return 0;
        }
        auto take_abort() noexcept -> std::optional<std::pair<std::int64_t,std::uint64_t>> {for(auto& a:aborts_)if(a)return std::exchange(a,{});return {};}
        auto begin_headers(std::int64_t id,bool trailers) -> int {
            if(stopping_ || trailers || (id&3) || find(id))return nghttp3::err_callback_failure;
            return create(id) ? 0 : nghttp3::err_callback_failure;
        }
        auto header(std::int64_t id,nghttp3::nghttp3_rcbuf* name,nghttp3::nghttp3_rcbuf* value,bool trailers) -> int {
            auto* s=find(id);return !trailers && s && s->headers.append(name,value) ? 0 : nghttp3::err_callback_failure;
        }
        auto end_headers(std::int64_t id,bool fin,bool trailers) -> int {
            auto* s=find(id);if(!s || trailers)return nghttp3::err_callback_failure;
            if(auto ip=parse_connect_ip_request(s->headers.fields())) {
                auto result=begin_ip(*s,*ip,fin);s->headers.clear();return result;
            }
            if(fin) {s->headers.clear();s->closed=true;return response(id,false);}
            auto pending=owner_.begin(id,s->headers.fields());s->headers.clear();
            if(!pending) {s->closed=true;return response(id,false);}
            if (!accounting_.opened(id,pending->port)) {
                owner_.close(pending->handle);s->closed=true;return response(id,false);
            }
            s->handle=pending->handle;s->route_pending=true;changed();return 0;
        }
        auto data(std::int64_t id,std::span<std::uint8_t const> bytes) -> int {
            auto* s=find(id);if(!s)return nghttp3::err_callback_failure;
            if (s->ip) {
                auto valid=s->ip->feed(bytes);
                accounting_.delivered(s->id,true,s->ip->take_uploaded());
                if (!valid) revoke(*s,0x10e);
                return 0;
            }
            auto result=s->capsules.feed(bytes,[&](auto payload){if(s->ready && s->handle)if(!send_udp(*s,payload))revoke(*s,0x102);});
            if(result==UdpInput::malformed || result==UdpInput::too_large)revoke(*s,0x10e);
            return 0;
        }
        auto end_stream(std::int64_t id) -> int {
            auto* s=find(id);if(!s)return 0;
            if(s->ip || s->route_pending || !s->ready) {revoke(*s,0x10c);return 0;}
            auto result=s->capsules.finish([&](auto payload){if(s->ready && s->handle)(void)send_udp(*s,payload);});
            if(result==UdpInput::malformed || result==UdpInput::too_large) {revoke(*s,0x10e);return 0;}
            s->rx_open=false;if(s->handle)owner_.close_receive(*s->handle);
            if(!s->tx_open && s->handle) {owner_.close(*s->handle);s->ready=false;accounting_.retired(s->id);}
            return 0;
        }
        auto data_acked(std::int64_t id,std::uint64_t size) -> int {
            auto* s=find(id);if(!s || size>s->output_size-s->acked)return nghttp3::err_callback_failure;
            s->acked+=size;
            if (s->acked==s->output_size) {
                accounting_.delivered(s->id,false,std::exchange(s->output_payload,0));
                s->output_size=s->acked=0;
                s->submitted=false;
                changed();
            }
            return 0;
        }
        auto read_data(std::int64_t id,std::span<nghttp3::nghttp3_vec> output,std::uint32_t& flags) -> nghttp3::nghttp3_ssize {
            auto* s=find(id);if(!s || s->closed || !s->tx_open || s->submitted || !s->output_size || output.empty())return nghttp3::err_wouldblock;
            output[0]={s->output.data(),s->output_size};s->submitted=true;flags=nghttp3::data_flag_none;return 1;
        }
        // Pull only one bounded packet per stream until its DATA is ACKed.
        // This uses reliable DATAGRAM Capsules as a valid fallback even when
        // the peer has not enabled QUIC DATAGRAM. Oversize UDP packets drop.
        // One readiness event carries the exact generation and fd captured at
        // registration. Recheck both before touching the current socket.
        auto socket_failed(UdpHandle handle,int fd) -> bool {
            if(stopping_)return false;
            auto current=owner_.native_handle(handle);if(!current || *current!=fd)return true;
            for(auto& state:states_)if(state && state->handle==handle) {revoke(*state,0x102);break;}
            return application_.flush_pending()==0;
        }
        auto ready_socket(UdpHandle handle,int fd) -> bool {
            if(stopping_)return false;
            auto current=owner_.native_handle(handle);
            if(!current || *current!=fd)return true; // stale readiness
            for(auto& state:states_)if(state && state->handle==handle && state->ready && !state->closed && state->tx_open && !state->output_size) {
                std::array<std::uint8_t,Mtu> packet{};auto result=owner_.receive(*state->handle,packet);
                if(!result){revoke(*state,0x102);continue;}
                if(!*result)continue;
                auto prefix=write_capsule_prefix(state->output,datagram_capsule_type,**result+1);
                if(!prefix || *prefix+1+**result>state->output.size()){revoke(*state,0x102);continue;}
                state->output[*prefix]=0;std::ranges::copy(std::span(packet).first(**result),state->output.begin()+*prefix+1);
                state->output_size=*prefix+1+**result;state->output_payload=**result;state->acked=0;state->submitted=false;
                if(application_.h3().resume(state->id))revoke(*state,0x102);
            }
            return application_.flush_pending()==0;
        }
        auto socket_watch_state(UdpHandle handle,int fd) noexcept -> SocketWatchState {
            if(stopping_)return SocketWatchState::inactive;
            auto current=owner_.native_handle(handle);
            if(!current || *current!=fd)return SocketWatchState::inactive;
            for(auto const& state:states_)if(state && state->handle==handle && state->ready && !state->closed && state->tx_open)
                return state->output_size ? SocketWatchState::paused : SocketWatchState::ready;
            return SocketWatchState::inactive;
        }
        // Registration snapshots own no descriptors. Callers discard these
        // after use and never treat fd numbers as stable association IDs.
        auto sockets() noexcept -> std::array<std::optional<std::pair<UdpHandle,int>>,Streams> {
            std::array<std::optional<std::pair<UdpHandle,int>>,Streams> result{};
            for(std::size_t i=0;i<Streams;++i)if(states_[i] && states_[i]->ready && !states_[i]->closed && states_[i]->tx_open && states_[i]->handle) {
                auto fd=owner_.native_handle(*states_[i]->handle);
                if(fd)result[states_[i]->handle->slot]=std::pair{*states_[i]->handle,*fd};
            }
            return result;
        }
        auto datagram_output() noexcept -> std::optional<Packet> {return {};}
        auto datagram_accepted() noexcept -> void {}
        auto datagram_rejected() noexcept -> void {}
        auto datagram_budget() const noexcept -> std::size_t {return ip_port_ ? ip_server_mtu+1 : Mtu;}
        auto withdraw_ip() noexcept -> void {
            ip_withdrawing_=true;
            for(auto& state:states_)if(state && state->ip && state->ready)state->ip->withdraw();
        }
        auto poll_ip() -> bool {
            if(stopping_)return true;
            bool polled=false;
            for(auto& s:states_)if(s && s->ready && s->ip) {
                polled=true;
                auto ready=s->ip->poll();
                accounting_.delivered(s->id,true,s->ip->take_uploaded());
                if(!ready) {revoke(*s,0x102);continue;}
                if(!s->output_size) {
                    s->output_size=s->ip->output(s->output,&s->output_payload);
                    if(s->ip->failed() || (s->output_size && application_.h3().resume(s->id)))revoke(*s,0x102);
                    else if(s->output_size)changed();
                }
            }
            return !polled || application_.flush_pending()==0;
        }
        auto closed(std::int64_t id,std::uint64_t,std::uint64_t) noexcept -> void {
            for(auto& s:states_)if(s && s->id==id){if(s->handle)owner_.close(*s->handle);accounting_.retired(id);s.reset();changed();return;}
        }
        auto receive_closed(std::int64_t id,std::uint64_t) noexcept -> void {
            auto* s=find(id);if(!s)return;
            s->rx_open=false;
            if(s->ip || s->route_pending || !s->ready){revoke(*s,0x10c);return;}
            if(s->handle)owner_.close_receive(*s->handle);
            if(!s->tx_open && s->handle){owner_.close(*s->handle);s->ready=false;accounting_.retired(id);}
            changed();
        }
        auto send_closed(std::int64_t id,std::uint64_t) noexcept -> void {
            auto* s=find(id);if(!s)return;
            s->tx_open=false;
            if(s->ip || s->route_pending || !s->ready){revoke(*s,0x10c);return;}
            if(s->handle)owner_.close_send(*s->handle);
            if(!s->rx_open && s->handle){owner_.close(*s->handle);s->ready=false;accounting_.retired(id);}
            changed();
        }
        auto shutdown(std::int64_t) noexcept -> int {return 0;}
    };
}
