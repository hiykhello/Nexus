import std;
import crypto;
import quic.connection;
import quic.http3;
import quic.http3_headers;
import quic.tls_client;
import quic.tls_server;
import hysteria2.auth;
import http.header;
import ngtcp2;
import nghttp3;
import tls.server_credential;
import test.quic_tls_link;
import test.http3_link;

namespace n = ::ngtcp2;
namespace h3 = ::nghttp3;
namespace q=quic;
namespace h=hysteria2;
namespace t=tls;
namespace support=test::quic_tls;
using View=std::span<std::uint8_t const>;
namespace {
    using test::http3_link::Application;
    using test::http3_link::Written;
    using test::http3_link::write;
    using test::http3_link::request;
    template<class Tls> struct Peer {
        support::Memory memory;
        support::Path path;
        Application<Tls> app;
        q::Connection<Tls,Application<Tls>> connection;
        Peer(Tls& tls,bool server):path(server),app(tls),connection(tls,app) { app.server=server; app.transport=&connection; }
        ~Peer() { stop(); }
        auto clean() const noexcept -> bool { return !connection.native() && !connection.key_slots() && !memory.used && !app.http3.native() && !app.memory.used && app.quic_closed==1 && app.http3_closed==1 && !app.broken; }
        auto stop() noexcept -> void { connection.stop(); app.drain(); }
    };
    template<class Sender,class Receiver> auto transfer(Sender& sender,Receiver& receiver,std::uint64_t& now,bool hold=false) -> std::expected<Written,int> {
        std::array<std::uint8_t,1500> output{}; auto result=write(sender,output,now,hold); sender.app.drain();
        if (!result) return std::unexpected(result.error());
        if (result->bytes && !(hold && result->stream==4 && result->accepted)) {
            receiver.app.time=now+=1000000;
            auto error=receiver.connection.read(receiver.path.value,nullptr,std::span(output).first(result->bytes),now); receiver.app.drain();
            if (error) return std::unexpected(error);
        }
        return result;
    }
    template<class Client,class Server> auto pump(Client& client,Server& server,std::uint64_t& now,unsigned rounds) -> int {
        for (unsigned i=0;i<rounds;++i) {
            auto first=transfer(client,server,now); if (!first) return first.error();
            auto second=transfer(server,client,now); if (!second) return second.error();
            for (auto* connection:{client.connection.native(),server.connection.native()}) {
                if (n::ngtcp2_conn_get_expiry2(connection)<=now) if (auto error=n::ngtcp2_conn_handle_expiry(connection,now)) return error;
            }
        }
        return 0;
    }
    auto scenario(t::ServerCredential const& credential,View anchor,unsigned mode) -> int {
        q::TlsClient tls_client(support::hello(*credential.scheme()),29,support::Pki{anchor},"h3");
        q::TlsServer tls_server(credential,"h3"); Peer client(tls_client,false); Peer server(tls_server,true);
        auto error=client.connection.start(false,support::cid(0x83),support::cid(0),client.path.value,support::settings(),support::parameters(false),client.memory.transport());
        if (!error) error=server.connection.start(true,support::cid(0),support::cid(0xf0),server.path.value,support::settings(),support::parameters(true),server.memory.transport());
        if (error) return 1;
        std::uint64_t now=2;
        for (unsigned rounds=0;rounds<100 && (!client.app.completed || !server.app.completed);++rounds) if (auto error=pump(client,server,now,1)) { std::println("handshake error {}",error); return 2; }
        if (!client.app.completed || !server.app.completed) return 3;
        if (auto error=request(client,true)) return error;
        for (unsigned rounds=0;rounds<200 && (!client.app.authenticated || !server.app.authenticated);++rounds) if (auto error=pump(client,server,now,1)) { std::println("auth error {}",error); return 4; }
        if (!client.app.authenticated || !server.app.authenticated || !client.app.refs_valid() || !server.app.refs_valid()) return 5;
        if (mode==0) {
            if (auto error=request(client,false)) return error;
            for (unsigned rounds=0;rounds<500 && (!client.app.slot(4).fin || server.app.slot(4).acked!=12000);++rounds) if (auto error=pump(client,server,now,1)) { std::println("body error {}",error); return 6; }
            if (!client.app.slot(4).fin || client.app.slot(4).received!=12000 || server.app.slot(4).acked!=12000 || client.app.input!=client.app.framing+client.app.payload || server.app.input!=server.app.framing+server.app.payload) return 7;
        } else {
            if (auto error=request(client,false)) return error;
            for (unsigned rounds=0;rounds<200 && !server.app.borrow_count;++rounds) {
                auto first=transfer(client,server,now); if (!first) return first.error();
                auto second=transfer(server,client,now,true); if (!second) return second.error();
            }
            if (!server.app.borrow_count || server.app.sent<=server.app.acked || !server.app.refs_valid()) return 8;
            if (mode==1) server.app.http3.stop();
            if (mode==2) server.connection.stop();
            if (mode==3 || mode==4) {
                server.app.action=mode; if (auto error=request(client,false)) return error;
                int last=0;
                for (unsigned rounds=0;rounds<200 && !server.app.acted;++rounds) {
                    auto written=transfer(client,server,now); if (!written) { last=written.error(); break; }
                }
                if (server.app.acted!=1 || !server.app.held_during_callback || (mode==3 ? last!=n::err_callback_failure || server.app.http3_error!=h3::err_callback_failure : last!=0)) return 9;
            }
            if (mode==5) {
                if (auto error=request(client,false)) return error;
                bool dropped_encoder=false,blocked=false;
                for (unsigned rounds=0;rounds<32 && !blocked;++rounds) {
                    std::array<std::uint8_t,1500> output{}; auto written=write(client,output,now);
                    if (!written) return written.error();
                    if (written->stream==6 && written->accepted) { dropped_encoder=true; continue; }
                    if (written->bytes) {
                        server.app.time=now+=1000000;
                        auto error=server.connection.read(server.path.value,nullptr,std::span(output).first(written->bytes),now); server.app.drain();
                        if (error) return error;
                    }
                    blocked=dropped_encoder && written->stream==8 && written->accepted && server.app.input>server.app.framing+server.app.payload && !server.app.slot(8).ended;
                }
                if (!blocked || !server.app.http3.active() || !server.app.refs_valid()) return 12;
                server.app.http3.stop();
            }
            server.app.drain();
            if (!server.clean() || server.app.reentered!=1) return 10;
        }
        client.stop(); server.stop();
        if (!client.clean() || !server.clean() || tls_client.pending_handshake_bytes() || tls_server.pending_handshake_bytes()) return 11;
        std::println("authenticated QUIC+H3 scenario={} clean; server closing={} reentry={} held={} native={} h3={} accepted={} acked={}",mode,server.app.closing_calls,server.app.reentered,server.app.held_during_callback,server.memory.peak,server.app.memory.peak,server.app.sent,server.app.acked);
        return 0;
    }
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) { std::println("usage: quic-http3-lifecycle CERT.der KEY.der"); return 1; }
    try {
        auto cert=support::read(argv[1]),key=support::read(argv[2]); auto credential=t::ServerCredential::create(cert,key); ::crypto::cleanse(key); if (!credential) return 2;
        for (unsigned mode=0;mode<6;++mode) if (auto error=scenario(*credential,cert,mode)) { std::println("H3 actual QUIC lifecycle mode={} failed {}",mode,error); return 3; }
        std::println("actual TLS-authenticated QUIC+HTTP3 auth233 and DATA credit passed; H3 callback/QUIC callback/external stops retain borrowed native frames and rcbufs until unique QUIC closed callback returns");
    } catch (std::exception const& error) { std::println("H3 actual lifecycle exception {}",error.what()); return 99; }
}
