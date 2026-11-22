import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.crypto;
import wireguard.noise;
import wireguard.session;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    auto decode_key(std::string_view text) -> std::optional<Key> {
        if (text.size()!=64) return {};
        auto nibble=[](char c) { return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : -1; };
        Key key;
        for (std::size_t i=0;i<32;++i) {
            auto a=nibble(text[2*i]),b=nibble(text[2*i+1]); if (a<0 || b<0) return {};
            key[i]=static_cast<std::uint8_t>((a<<4)|b);
        }
        return key;
    }
    auto checksum(std::span<std::uint8_t const> bytes) -> std::uint16_t {
        std::uint32_t sum=0;
        for (std::size_t i=0;i<bytes.size();i+=2) sum+=(std::uint16_t(bytes[i])<<8)|(i+1<bytes.size() ? bytes[i+1] : 0);
        while (sum>>16) sum=(sum&65535)+(sum>>16);
        return static_cast<std::uint16_t>(~sum);
    }
    auto packet(unsigned index,bool core_to_go,bool reply=false) -> std::vector<std::uint8_t> {
        constexpr std::array<std::size_t,10> sizes{0,1,15,16,17,63,64,65,512,1024};
        bool ipv6=index%2;
        auto header=ipv6 ? 40u : 20u;
        auto udp_size=8+sizes[index];
        std::vector<std::uint8_t> out(header+udp_size);
        auto store=[&](std::size_t offset,std::size_t value) { out[offset]=static_cast<std::uint8_t>(value>>8); out[offset+1]=static_cast<std::uint8_t>(value); };
        out[0]=ipv6 ? 0x60 : 0x45;
        if (ipv6) {
            store(4,udp_size); out[6]=17; out[7]=64;
            out[8]=out[24]=0xfd; out[9]=out[25]=0x42; out[23]=core_to_go ? 2 : 1; out[39]=core_to_go ? 1 : 2;
        } else {
            store(2,out.size()); out[8]=64; out[9]=17;
            out[12]=out[16]=10; out[13]=out[17]=42; out[15]=core_to_go ? 2 : 1; out[19]=core_to_go ? 1 : 2;
            store(10,checksum(std::span(out).first(20)));
        }
        store(header,reply ? 20000 : 10000); store(header+2,reply ? 10000 : 20000); store(header+4,udp_size);
        for (std::size_t i=0;i<sizes[index];++i) out[header+8+i]=static_cast<std::uint8_t>(index+i);
        std::vector<std::uint8_t> pseudo;
        if (ipv6) {
            pseudo.insert(pseudo.end(),out.begin()+8,out.begin()+40);
            pseudo.insert(pseudo.end(),{0,0,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size),0,0,0,17});
        } else {
            pseudo.insert(pseudo.end(),out.begin()+12,out.begin()+20);
            pseudo.insert(pseudo.end(),{0,17,static_cast<std::uint8_t>(udp_size>>8),static_cast<std::uint8_t>(udp_size)});
        }
        pseudo.insert(pseudo.end(),out.begin()+header,out.end()); auto value=checksum(pseudo);
        store(header+6,value ? value : 65535); return out;
    }
    auto matches(std::span<std::uint8_t const> plaintext,std::span<std::uint8_t const> expected) -> bool {
        return plaintext.size()>=expected.size() && std::ranges::equal(plaintext.first(expected.size()),expected) &&
            std::ranges::all_of(plaintext.subspan(expected.size()),[](auto byte) { return byte==0; });
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=4) return 1;
    bool initiate=std::string_view(argv[1])=="initiate",ipv6=std::string_view(argv[2])=="6";
    if ((!initiate && std::string_view(argv[1])!="respond") || (std::string_view(argv[2])!="4" && !ipv6)) return 1;
    unsigned port=0; auto parsed=std::from_chars(argv[3],argv[3]+std::char_traits<char>::length(argv[3]),port);
    if (parsed.ec!=std::errc{} || *parsed.ptr || !port || port>65535) return 2;
    std::string private_text,remote_text,psk_text;
    if (!(std::cin>>private_text>>remote_text>>psk_text)) return 3;
    auto private_key=decode_key(private_text),remote=decode_key(remote_text),psk=decode_key(psk_text);
    std::fill(private_text.begin(),private_text.end(),'\0'); std::fill(psk_text.begin(),psk_text.end(),'\0');
    if (!private_key || !remote || !psk) return 4;
    auto local=::crypto::X25519Private::from_bytes(*private_key); ::crypto::cleanse(*private_key);
    if (!local) return 5;
    auto handshake=Handshake::create(*local,*remote,*psk); ::crypto::cleanse(*psk);
    if (!handshake) return 6;
    net::UdpSocket socket;
    net::UdpEndpoint peer{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},static_cast<std::uint16_t>(port)};
    if (ipv6) peer.address[15]=1; else { peer.address[0]=127; peer.address[3]=1; }
    constexpr std::array<std::uint8_t,14> ready{'N','E','X','U','S','-','W','G','-','R','E','A','D','Y'};
    if (!socket.send(peer,ready)) return 7;
    auto deadline=Clock::now()+15s;
    std::optional<Session> session;
    TimestampGuard timestamp;
    if (initiate) {
        auto ephemeral=::crypto::X25519Private::generate(); if (!ephemeral) return 8;
        auto wall=std::chrono::system_clock::now().time_since_epoch();
        auto seconds=std::chrono::duration_cast<std::chrono::seconds>(wall);
        auto nanoseconds=std::chrono::duration_cast<std::chrono::nanoseconds>(wall-seconds);
        if (seconds.count()<0) return 9;
        auto stamp=make_timestamp(seconds.count(),nanoseconds.count()); if (!stamp) return 10;
        auto wire=handshake->initiate(0x12345678,*stamp,std::move(*ephemeral));
        if (!wire || !socket.send(peer,*wire)) return 11;
    }
    unsigned count=0;
    std::array<std::uint8_t,65535> input{};
    while (Clock::now()<deadline && count<10) {
        auto received=socket.receive(input); if (!received) return 12;
        if (!*received) { std::this_thread::sleep_for(1ms); continue; }
        auto const& packet=(**received);
        if (!packet.valid || packet.source!=peer) continue;
        auto wire=std::span(input).first(packet.size);
        auto type=message_type(wire); if (!type) continue;
        if (!session) {
            if (initiate && *type==MessageType::response) {
                if (!handshake->consume_response(wire)) continue;
                auto ready_session=handshake->finish(Clock::now()); if (!ready_session) return 13;
                session.emplace(std::move(*ready_session));
                auto confirm=session->seal({},Clock::now()); if (!confirm || !socket.send(peer,*confirm)) return 14;
                auto first=session->seal(::packet(0,true),Clock::now(),1420); if (!first || !socket.send(peer,*first)) return 15;
            } else if (!initiate && *type==MessageType::initiation) {
                if (!handshake->consume_initiation(wire,timestamp,Clock::now())) continue;
                auto ephemeral=::crypto::X25519Private::generate(); if (!ephemeral) return 16;
                auto response=handshake->respond(0x9abcdef0,std::move(*ephemeral)); if (!response || !socket.send(peer,*response)) return 17;
                auto ready_session=handshake->finish(Clock::now()); if (!ready_session) return 18;
                session.emplace(std::move(*ready_session));
                if (session->confirmed() || session->seal({},Clock::now())) return 19;
            }
            continue;
        }
        if (*type!=MessageType::transport) continue;
        auto plaintext=session->open(wire,Clock::now());
        if (!plaintext) continue; // Deliberate corruptions and duplicates are drops.
        if (plaintext->empty()) continue;
        auto expected=::packet(count,false,initiate);
        if (!matches(*plaintext,expected)) {
            std::println("inner packet {} mismatch: got {} bytes, expected {} before padding",count,plaintext->size(),expected.size());
            return 20;
        }
        if (!initiate) {
            auto reply=session->seal(::packet(count,true,true),Clock::now(),1420); if (!reply || !socket.send(peer,*reply)) return 21;
        }
        ++count;
        if (initiate && count<10) {
            auto next=session->seal(::packet(count,true),Clock::now(),1420); if (!next || !socket.send(peer,*next)) return 22;
        }
    }
    if (count!=10) return 23;
    std::println("Nexus WireGuard {} UDP/{} with fixed wireguard-go, IPv4/IPv6 inner packets and authentication/replay drops passed",initiate ? "initiator" : "responder",ipv6 ? "IPv6" : "IPv4");
}
