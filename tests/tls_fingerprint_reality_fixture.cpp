import std;
import tls.fingerprint;
import tls.client_handshake_io;
import tls.application_io;
import reality.client;
import vless;

namespace t=tls;
namespace c = ::crypto;
namespace r=reality;
auto write(std::span<std::uint8_t const> data) -> bool {
    for(std::size_t offset=0;offset<data.size();) {
        auto size=data.size()-offset;
        std::cout.write(reinterpret_cast<char const*>(data.data()+offset),size);std::cout.flush();
        if(!std::cout)return false;offset+=size;
    }return true;
}
auto receive() -> std::optional<c::Bytes> {
    c::Bytes record(5);std::cin.read(reinterpret_cast<char*>(record.data()),5);if(!std::cin)return {};
    auto size=(std::size_t{record[3]}<<8)|record[4];if(size>16640)return {};
    record.resize(5+size);std::cin.read(reinterpret_cast<char*>(record.data()+5),size);if(!std::cin)return {};return record;
}
int main(int argc,char** argv) {
    if(argc!=7)return 1;
    std::string_view public_hex=argv[1],short_hex=argv[3],mode=argv[4],profile=argv[5];
    auto nib=[](char c)->int {if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;};
    auto decode=[&](std::string_view text,std::span<std::uint8_t> output) {
        if(text.size()!=2*output.size())return false;
        for(std::size_t i=0;i<output.size();++i){auto a=nib(text[2*i]),b=nib(text[2*i+1]);if(a<0||b<0)return false;output[i]=a*16+b;}return true;
    };
    std::array<std::uint8_t,32> public_key{};
    auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    r::Identity identity{{1,8,24},static_cast<std::uint32_t>(seconds),{}};
    if(!decode(public_hex,public_key)||!decode(short_hex,identity.short_id))return 2;
    t::FingerprintConfig policy;
    policy.profile=profile=="randomized" ? t::Fingerprint::tls13_randomized : profile=="native" ? t::Fingerprint::native : t::Fingerprint::tls13_grease;
    policy.shares=mode=="dual" ? t::FingerprintShares::dual : mode=="hybrid" ? t::FingerprintShares::hybrid : t::FingerprintShares::x25519;
    policy.pad_to=1600;
    auto shape=t::make_fingerprint_hello(std::string_view(argv[2]),{},policy);if(!shape)return 3;
    auto session=r::create_client_session(std::move(shape->hello),shape->initial_groups(),public_key,identity);if(!session)return 4;
    auto handshake=t::ClientHandshakeIo::create(std::move(*session),0,10000);if(!handshake)return 5;
    c::Bytes unread;
    while(!handshake->complete()) {
        auto pending=handshake->pending_output();
        if(!pending.empty()) {auto size=pending.size();if(!write(pending)||!handshake->written(size,1))return 6;continue;}
        auto record=receive();if(!record)return 7;
        std::size_t offset=0;
        while(offset<record->size()&&!handshake->complete()) {
            auto step=handshake->feed(std::span(*record).subspan(offset),1);
            if(!step||!step->consumed)return 8;offset+=step->consumed;
            if(!handshake->pending_output().empty())break;
        }
        if(offset!=record->size())unread.assign(record->begin()+offset,record->end());
    }
    auto records=handshake->take_application_records();if(!records)return 9;
    t::ApplicationIo app(std::move(*records));
    vless::TcpRequest request{};for(std::size_t i=0;i<request.user.size();++i)request.user[i]=i;
    auto port=std::strtoul(argv[6],nullptr,10);if(!port||port>65535)return 10;
    request.port=static_cast<std::uint16_t>(port);request.address={127,0,0,1};
    auto wire=vless::encode_tcp_request(request);if(!wire)return 11;
    constexpr std::string_view payload="Reality VLESS bidirectional payload";
    wire->insert(wire->end(),payload.begin(),payload.end());
    auto flush=[&]() {while(!app.pending_output().empty()){auto pending=app.pending_output();auto size=pending.size();if(!write(pending)||!app.written(size))return false;}return true;};
    if(!app.send(*wire)||!flush())return 12;
    c::Bytes response;
    while(response.size()<payload.size()+2) {
        auto record=unread.empty() ? receive() : std::optional<c::Bytes>(std::exchange(unread,{}));if(!record)return 13;
        for(std::size_t offset=0;offset<record->size();) {
            auto step=app.feed(std::span(*record).subspan(offset));if(!step||!step->consumed)return 14;offset+=step->consumed;
            if(step->event&&step->event->kind==t::ApplicationEventKind::data)response.insert(response.end(),step->event->data.begin(),step->event->data.end());
            if(!flush())return 15;
        }
    }
    auto parsed=vless::parse_response(response);
    if(parsed.status!=vless::HeaderStatus::accepted||std::string_view(reinterpret_cast<char const*>(response.data()+parsed.consumed),response.size()-parsed.consumed)!=payload)return 16;
    if(!app.close_notify()||!flush())return 17;
    std::cerr<<"shaped Reality TLS, authenticated VLESS and bidirectional payload passed\n";
}
