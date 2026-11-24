export module test.hy2_port_link;
import std;
import crypto;
import hysteria2.application;
import hysteria2.auth;
import hysteria2.wire;
import hysteria2.tcp_channel;
import hysteria2.stream_state;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.tls_server;
import net.datagram_driver;
import net.stream_relay;
import tls.server_credential;
import ngtcp2;
import capy;
import corosio;
import test.quic_tls_link;
import test.hy2_native_memory;

export namespace test::hy2_port {
namespace n = ::ngtcp2;namespace q=quic;namespace h=hysteria2;namespace io = ::corosio;namespace capy = ::capy;namespace support=test::quic_tls;
using Clock=std::chrono::steady_clock;using namespace std::chrono_literals;
using Registry=q::CidRegistry<4,8>;
struct Hooks {
    Registry& registry;q::SessionHandle owner;capy::async_event& work;
    auto changed() noexcept -> void {work.set();}
    auto authenticate(h::ClientAuthView auth) noexcept -> bool {return ::crypto::constant_time_equal(support::bytes(auth.credential),support::bytes("test-password"));}
    auto datagram(std::span<std::uint8_t const>) noexcept -> int {return 0;}
    auto add_connection_id(n::ngtcp2_cid const& id,n::ngtcp2_stateless_reset_token const&) noexcept -> int {return registry.insert(owner,{id.data,id.datalen})?0:n::err_callback_failure;}
    auto remove_connection_id(n::ngtcp2_cid const& id) noexcept -> int {(void)registry.remove(owner,{id.data,id.datalen});return 0;}
};
using App=h::Application<q::TlsServer,Hooks,4,16384>;
using Session=q::DatagramSession<q::TlsServer,App>;
struct Bundle {
    q::TlsServer tls;Hooks hooks;hy2_native_memory::Memory memory,h3memory{hy2_native_memory::Kind::http3};App app;Session session;
    q::SessionHandle owner;bool launched=false,drained=false,passed=false;
    Bundle(tls::ServerCredential const& credential,Registry& registry,q::SessionHandle owner,capy::async_event& work,io::endpoint const& local)
        :tls(credential,"h3"),hooks{registry,owner,work},app(tls,hooks,true,h3memory.http3()),session(tls,app,local),owner(owner){}
};
struct Factory {
    using Session=test::hy2_port::Session;
    tls::ServerCredential const& credential;io::endpoint const& local;capy::async_event work;
    std::array<std::optional<Bundle>,4> bundles;
    unsigned created=0,destroyed=0,completed=0,failures=0;bool valid=true;
    Factory(tls::ServerCredential const& credential,io::endpoint const& local) noexcept:credential(credential),local(local){}
    auto admit(n::ngtcp2_pkt_hd const& initial,io::endpoint const&,Clock::time_point) const noexcept -> bool {return initial.tokenlen==0;}
    auto create(q::SessionHandle owner,Registry& registry,std::span<std::uint8_t const> source,n::ngtcp2_pkt_hd const& initial,io::endpoint const& peer,Clock::time_point now) noexcept -> std::expected<Session*,int> {
        try {
            auto& bundle=bundles[owner.slot];if(bundle)return std::unexpected(n::err_callback_failure);
            bundle.emplace(credential,registry,owner,work,local);auto parameters=support::parameters(true);parameters.original_dcid=initial.dcid;
            parameters.initial_max_stream_data_bidi_local=parameters.initial_max_stream_data_bidi_remote=16384;parameters.initial_max_streams_bidi=4;parameters.active_connection_id_limit=4;
            n::ngtcp2_cid cid{};n::ngtcp2_cid_init(&cid,source.data(),source.size());
            auto error=bundle->session.start(true,initial.scid,cid,peer,support::settings(),parameters,bundle->memory.transport(),now);
            if(error){bundle->session.request_stop();bundle->session.stop();bundle->session.drain();valid&=bundle->app.clean() && !bundle->memory.used && !bundle->h3memory.used && !bundle->session.transport().key_slots();bundle.reset();return std::unexpected(error);}
            ++created;work.set();return &bundle->session;
        }catch(...){bundles[owner.slot].reset();return std::unexpected(n::err_nomem);}
    }
    auto application_drained(q::SessionHandle owner,Session const&) const noexcept -> bool {return bundles[owner.slot] && (!bundles[owner.slot]->launched || bundles[owner.slot]->drained);}
    auto failed(q::SessionHandle owner,int error) noexcept -> void {++failures;std::println("native failure slot={} generation={} error={}",owner.slot,owner.generation,error);work.set();}
    auto destroy(q::SessionHandle owner,Session&) noexcept -> void {
        auto& bundle=bundles[owner.slot];valid&=bundle && (!bundle->launched || bundle->drained) && bundle->app.clean() && !bundle->memory.used && !bundle->h3memory.used && !bundle->session.transport().key_slots();
        if(bundle)valid&=!bundle->tls.pending_handshake_bytes();++destroyed;bundle.reset();work.set();
    }
};
using Port=q::DatagramPort<Factory,4,8>;using Driver=net::DatagramDriver<Port>;
struct BusinessRoot {
    Bundle* bundle;
    explicit BusinessRoot(Bundle& bundle) noexcept:bundle(&bundle){}
    BusinessRoot(BusinessRoot const&)=delete;
    BusinessRoot(BusinessRoot&& other) noexcept:bundle(std::exchange(other.bundle,nullptr)){}
    ~BusinessRoot(){if(bundle){bundle->drained=true;bundle->hooks.changed();}}
};

}
