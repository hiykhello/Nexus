import std;
import tailscale.derp;
import tailscale.derp_messages;
import tailscale.derp_info;
import tailscale.derp_handshake;
import tailscale.box;
import crypto;
namespace d=tailscale::derp;
namespace b=tailscale::box;
namespace c = ::crypto;
using Bytes=std::vector<std::uint8_t>;
using namespace std::chrono_literals;
auto require(bool condition,std::string_view message) -> void { if (!condition) throw std::runtime_error(std::string(message)); }
auto sequence(unsigned start,std::size_t count) -> Bytes {
    Bytes value(count);for (std::size_t i=0;i<count;++i) value[i]=static_cast<std::uint8_t>(start+i);return value;
}
auto view(std::string_view text) -> std::span<std::uint8_t const> { return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()}; }
auto frame(Bytes const& wire) -> d::Frame { return {static_cast<d::Type>(wire[0]),std::span(wire).subspan(5)}; }
auto json() -> void {
    for (auto text:{R"({"version":2})",R"({"version":2,"new":{"nested":[1,2,3]}})",R"({"version":1,"version":2})"}) {
        auto parsed=d::parse_server_settings(view(text));
        require(parsed && parsed->version==2 && !parsed->bytes_per_second && !parsed->burst,"compatible server info");
    }
    auto parsed=d::parse_server_settings(view(R"({"version":2,"TokenBucketBytesPerSecond":1048576,"TokenBucketBytesBurst":2097152})"));
    require(parsed && parsed->bytes_per_second==1048576 && parsed->burst==2097152,"server integer token bucket");
    for (auto text:{R"({"version":2,"TokenBucketBytesPerSecond":-1})",R"({"version":2,"TokenBucketBytesBurst":-1})",
        R"({"version":2,"TokenBucketBytesBurst":9223372036854775808})",R"({"version":2,"TokenBucketBytesBurst":1.5})",
        R"({"version":2,"TokenBucketBytesBurst":"5"})",R"({"version":2})junk",R"([{"version":2}])",R"({"version":2)",
        R"({"version":2,"unknown":[1,,2]})",R"({"version":2,"unknown":{"key":}})",R"({"version":2,"unknown":tru})",
        R"({"version":0})",R"({"version":1})",R"({"version":3})",R"({})",R"(null)"})
        require(!d::parse_server_settings(view(text)),"invalid JSON/version/rate accepted");
    require(!d::parse_server_settings({}) && !d::parse_server_settings(sequence(' ',4097)),"JSON input bound");
    for (auto levels:{255u,256u,300u}) {
        std::string deep=R"({"version":2,"unknown":)";
        deep.append(levels,'[');deep+="0";deep.append(levels,']');deep+='}';
        // The root object already consumes one of Glaze's 256 levels.
        require(bool(d::parse_server_settings(view(deep)))==(levels==255),"unknown array JSON depth bound");
        std::string objects=R"({"version":2,"unknown":)";
        for (unsigned i=0;i<levels;++i) objects+=R"({"x":)";
        objects+="0";objects.append(levels,'}');objects+='}';
        require(bool(d::parse_server_settings(view(objects)))==(levels==255),"unknown object JSON depth bound");
    }
}
auto handshake() -> void {
    auto local=c::X25519Private::from_bytes(sequence(0,32)),server=c::X25519Private::from_bytes(sequence(32,32));
    require(local && server,"keys");
    auto ap=local->public_key(),bp=server->public_key();require(ap && bp,"public keys");
    auto shared=b::SharedKey::derive(*server,*ap);require(bool(shared),"server shared key");
    d::Nonce nonce{};std::ranges::copy(sequence(64,24),nonce.begin());
    auto key_frame=d::encode_server_key(*bp);require(bool(key_frame),"key frame");
    auto start=d::HandshakeClock::time_point{}+1s,limit=start+5s;
    auto response=[&](std::string_view text) {
        Bytes sealed(text.size()+16);
        require(bool(shared->seal_to(sealed,nonce,view(text))),"server seal");
        auto encoded=d::encode_server_info(nonce,sealed);require(bool(encoded),"server info frame");return *encoded;
    };
    auto info=response(R"({"version":2,"TokenBucketBytesPerSecond":99})");
    d::PinnedClientHandshake client(*local,*bp,start,limit);
    auto sent=client.start(frame(*key_frame),nonce,start+1ms);
    require(sent && client.state()==d::HandshakeState::server_info && !client.settings(),"client login state");
    auto envelope=d::parse_client_info(frame(*sent));require(envelope && envelope->node==*ap,"client identity envelope");
    Bytes plaintext(envelope->sealed.ciphertext.size()-16);
    auto opened=shared->open_to(plaintext,envelope->sealed.nonce,envelope->sealed.ciphertext);
    require(opened && std::ranges::equal(plaintext,view(d::regular_client_info)),"client authenticated default JSON");
    auto complete=client.finish(frame(info),start+2ms);
    require(complete && complete->bytes_per_second==99 && client.settings() && *client.settings()==*complete &&
        client.state()==d::HandshakeState::ready,"server authenticated readiness");
    require(client.start(frame(*key_frame),nonce,start+3ms).error()==d::HandshakeError::state && client.settings(),"ready state reused");
    client.cancel();require(!client.settings() && client.state()==d::HandshakeState::closed &&
        client.finish(frame(info),start+3ms).error()==d::HandshakeError::closed,"closed client reused");
    auto wrong=*bp;wrong[0]^=1;
    d::PinnedClientHandshake pinned(*local,wrong,start,limit);
    require(pinned.start(frame(*key_frame),nonce,start).error()==d::HandshakeError::server_identity &&
        pinned.state()==d::HandshakeState::failed,"untrusted server key");
    d::PinnedClientHandshake expired(*local,*bp,start,limit);
    require(expired.start(frame(*key_frame),nonce,limit).error()==d::HandshakeError::timeout,"expired start");
    d::PinnedClientHandshake late(*local,*bp,start,limit);
    require(bool(late.start(frame(*key_frame),nonce,start)),"late start");
    require(late.finish(frame(info),limit).error()==d::HandshakeError::timeout && !late.settings(),"deadline reset on server info");
    auto corrupted=info;corrupted.back()^=1;
    d::PinnedClientHandshake tampered(*local,*bp,start,limit);
    require(bool(tampered.start(frame(*key_frame),nonce,start)),"tampered start");
    require(tampered.finish(frame(corrupted),start+1ms).error()==d::HandshakeError::authentication &&
        tampered.state()==d::HandshakeState::failed && !tampered.settings(),"invalid server box authenticated");
    for (auto text:{R"({"version":1})",R"({"version":2})junk",R"({"version":2,"TokenBucketBytesPerSecond":-1})"}) {
        d::PinnedClientHandshake invalid(*local,*bp,start,limit);
        require(bool(invalid.start(frame(*key_frame),nonce,start)),"invalid settings start");
        auto invalid_info=response(text);
        require(invalid.finish(frame(invalid_info),start+1ms).error()==d::HandshakeError::info &&
            invalid.state()==d::HandshakeState::failed && !invalid.settings(),"invalid authenticated JSON accepted");
    }
    d::PinnedClientHandshake oversized(*local,*bp,start,limit);
    require(bool(oversized.start(frame(*key_frame),nonce,start)),"oversized start");
    auto too_large=response(std::string(4097,' '));
    require(oversized.finish(frame(too_large),start+1ms).error()==d::HandshakeError::protocol,"unbounded authenticated JSON");
}
auto main() -> int {
    try { json();handshake();std::println("DERP pinned server identity, NaCl directions, authenticated JSON, original deadline and terminal states passed"); }
    catch (std::exception const& error) {std::cerr<<error.what()<<'\n';return 1;}
}

