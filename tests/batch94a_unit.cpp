import std;
import config;
import hysteria2.transport_options;
import hysteria2.receive_buffer;
import quic.native_memory;
import reality.client;
import reality.server_auth;
import tls.hello_config;
import tls.handshake;
import tls.server_keys;
import tls.server_hello;
import tls.key_share;

namespace {
    auto check(bool passes,std::string_view what) -> void {
        if (!passes) throw std::runtime_error(std::string(what));
    }

    auto config_windows(std::string_view fields) {
        return config::parse_kdl(std::format(R"kdl(schema-version 1
role "client"
inbounds {{ inbound "edge" type="socks5" {{ listen host="127.0.0.1" port=1080; authentication "none"; }} }}
outbounds {{
    outbound "direct" type="direct"
    outbound "hy" type="hysteria2" {{
        server host="127.0.0.1" port=443
        authentication {{ password-file "/private/password"; }}
        tls {{ server-name "localhost"; ca-file "/private/cert"; verify #true; }}
        quic {{ {}; }}
    }}
}}
routing {{ default-outbound "hy"; }}
)kdl",fields));
    }

    auto windows() -> void {
        using Profile=hysteria2::TransportProfile<16,16384>;
        constexpr std::string_view valid="init-stream-receive-window 65536; max-stream-receive-window 131072; "
            "init-conn-receive-window 262144; max-conn-receive-window 524288";
        auto parsed=config_windows(valid);
        check(parsed.has_value(),parsed ? "" : parsed.error());
        hysteria2::TransportOptions options;
        options.receive_windows=parsed->hysteria2_outbounds.front().config.transport.receive_windows;
        auto settings=Profile::settings(options);
        auto params=Profile::parameters(options);
        check(settings && params,"transport configuration");
        check(settings->max_stream_window==131072 && settings->max_window==524288,"autotune caps");
        check(params->initial_max_stream_data_bidi_local==65536 && params->initial_max_stream_data_bidi_remote==65536 &&
            params->initial_max_data==262144,"initial QUIC parameters");
        auto defaults=Profile::parameters(hysteria2::TransportOptions{});
        check(defaults && defaults->initial_max_stream_data_bidi_remote==16384 &&
            defaults->initial_max_data==16*16384+3*16384,"legacy transport parameters");
        for (auto invalid:{
            "init-stream-receive-window 65535",
            "max-conn-receive-window 67108865",
            "init-stream-receive-window 65536",
            "init-stream-receive-window 131072; max-stream-receive-window 65536; init-conn-receive-window 131072; max-conn-receive-window 131072",
            "init-stream-receive-window 131072; max-stream-receive-window 131072; init-conn-receive-window 65536; max-conn-receive-window 131072",
            "init-stream-receive-window 65536; max-stream-receive-window 262144; init-conn-receive-window 131072; max-conn-receive-window 131072"}) {
            check(!config_windows(invalid),invalid);
        }
        check(!config_windows(std::string(valid)+"; native-bytes 524288"),"budget headroom");
        check(!config_windows(std::string(valid)+"; max-conn-receive-window 524288"),"duplicate field");
        check(config_windows("init-stream-receive-window 67108864; max-stream-receive-window 67108864; "
            "init-conn-receive-window 67108864; max-conn-receive-window 67108864; native-bytes 134217728").has_value(),"64 MiB windows");

        quic::NativeMemory<> memory(40000);
        hysteria2::ReceiveBuffer buffer(memory.http3(),20000);
        std::vector<std::uint8_t> sent(20000),got(20000);
        for (std::size_t i=0;i<sent.size();++i) sent[i]=i%251;
        check(buffer.append(sent) && !buffer.append(std::span(sent).first(1)) && memory.used()!=0,"receive storage cap");
        check(buffer.pull(std::span(got).first(19000))==19000 &&
              buffer.pull(std::span(got).subspan(19000))==1000 && sent==got && !memory.used(),"receive storage release");
        quic::NativeMemory<> small(16384);
        hysteria2::ReceiveBuffer denied(small.http3(),65536);
        check(!denied.append(sent) && !small.used(),"native budget rejection");
        std::println("Hy2 KDL range and budget checks, ngtcp2 initial/max settings, and bounded receive storage passed");
    }

    auto tls_record(std::span<std::uint8_t const> payload) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> record{22,3,3,static_cast<std::uint8_t>(payload.size()>>8),
            static_cast<std::uint8_t>(payload.size())};
        record.append_range(payload);
        return record;
    }

    auto reality_groups() -> void {
        constexpr auto hybrid=tls::x25519_mlkem768_group;
        constexpr std::array<std::uint16_t,2> both{hybrid,29};
        constexpr std::array<std::uint16_t,1> classical{29},post_quantum{hybrid},ed25519{0x0807};
        auto server=crypto::X25519Private::generate();
        check(server.has_value(),"REALITY server key");
        auto public_key=server->public_key();
        check(public_key.has_value(),"REALITY server public key");
        reality::Identity identity{{1,8,24},1000,{1,2,3,4,5,6,7,8}};
        std::array names{std::string("localhost")};
        std::array<std::array<std::uint8_t,8>,1> ids{identity.short_id};
        reality::ServerPolicy policy{names,ids,{},{},10};
        for (auto groups:{std::span<std::uint16_t const>(both),std::span<std::uint16_t const>(classical),
                          std::span<std::uint16_t const>(post_quantum)}) {
            auto hello=tls::make_client_hello("localhost",{},groups);
            check(hello.has_value(),"REALITY hello");
            auto client=reality::create_client_session(std::move(*hello),groups,*public_key,identity);
            check(client.has_value(),"REALITY client");
            auto record=client->initial_record();
            check(record.has_value(),"REALITY initial record");
            auto wire=std::span(*record).subspan(5);
            auto open=reality::authenticate_server_hello(wire,*server,policy,1000);
            check(open && open->identity.short_id==identity.short_id,"REALITY session authentication");
            check(!reality::authenticate_server_hello(wire,*server,policy,1011),"expired timestamp");
            auto selected=tls::server_handshake_keys(wire,ed25519);
            check(selected.has_value(),"REALITY TLS key exchange");
            auto response=tls::ServerHello::parse(std::span(selected->server_hello).subspan(4));
            check(response.has_value(),"server hello");
            auto field=std::ranges::find(response->extensions,51,&tls::Extension::type);
            check(field!=response->extensions.end(),"server key share");
            auto share=tls::KeyShare::parse_server(field->data);
            check(share && share->group==groups.front(),"server negotiated expected group");
        }

        auto hello=tls::make_client_hello("localhost",{},both);
        auto client=reality::create_client_session(std::move(*hello),classical,*public_key,identity);
        auto first=client->initial_record();
        auto wire=std::span(*first).subspan(5);
        auto shape=tls::ClientHello::parse(wire.subspan(4));
        auto shares=std::ranges::find(shape->extensions,51,&tls::Extension::type);
        shares->data={0,0};
        auto retry_input=tls::HandshakeDecoder::encode(1,*shape->encode());
        auto retry=tls::server_retry_hello(*retry_input,ed25519);
        check(retry && client->sent(),"prepare one hybrid HRR");
        auto result=client->feed(tls_record(*retry));
        check(result && result->outbound,"authenticated HRR accepted");
        auto second=tls::ClientHello::parse(std::span(*result->outbound).subspan(9));
        check(second && second->session_id==shape->session_id,"HRR preserves authenticated first-Hello session ID");
        auto second_shares=tls::KeyShare::parse_client(second->extension(51)->data);
        check(second_shares && second_shares->size()==1 && second_shares->front().group==hybrid,"HRR selects fresh hybrid share");
        check(client->sent().has_value(),"confirm HRR write");
        check(!client->feed(tls_record(*retry)),"reject second HRR");
        std::println("REALITY classical, hybrid, dual authentication, TLS selection and authenticated HRR passed");
    }
}

int main() {
    windows();
    reality_groups();
}
