import std;
import hysteria2.salamander;
import hysteria2.transport_options;
import quic.datagram_port;
import net.datagram_driver;
import corosio;

namespace h=hysteria2;
namespace n=net;
struct Port {
    using Failure=quic::DatagramPortError;
    std::vector<std::uint8_t> received;
    auto request_stop() noexcept -> void {}
    auto stop() noexcept -> void {}
    auto drain() noexcept -> void {}
    auto next_expiry() const noexcept -> n::DatagramDeadline {return {};}
    auto expire(n::DatagramClock::time_point) -> std::expected<void,Failure> {return {};}
    auto transmitted(std::uint64_t,n::DatagramClock::time_point) -> std::expected<void,Failure> {return {};}
    auto receive(corosio::endpoint const&,std::span<std::uint8_t const> input,n::DatagramClock::time_point)
        -> std::expected<void,Failure> {received.assign(input.begin(),input.end());return {};}
    auto output(std::span<std::uint8_t> output,n::DatagramClock::time_point)
        -> std::expected<std::optional<n::DatagramOutput>,Failure> {
        if(output.size()<40)return std::unexpected(Failure::invalid_output);
        for(std::size_t i=0;i<40;++i)output[i]=static_cast<std::uint8_t>(i);
        return std::optional<n::DatagramOutput>{n::DatagramOutput{{},40,7}};
    }
};
int main() {
    constexpr std::array<std::uint8_t,8> salt{0,1,2,3,4,5,6,7};
    constexpr std::array<std::uint8_t,8> password{'p','a','s','s','w','o','r','d'};
    h::TransportOptions options;
    auto normal=h::TransportProfile<16,16384>::settings(options);
    options.salamander_password=std::span<std::uint8_t const>(password);
    auto obfuscated=h::TransportProfile<16,16384>::settings(options);
    if(!normal || !obfuscated || obfuscated->max_tx_udp_payload_size+8!=normal->max_tx_udp_payload_size || obfuscated->no_pmtud)return 7;
    for(std::size_t limit:{std::size_t{1208},std::size_t{1280},std::size_t{1500}}) {
        options.max_udp_payload_size=limit;options.disable_path_mtu_discovery=true;
        auto selected=h::TransportProfile<16,16384>::settings(options);
        if(!selected || selected->max_tx_udp_payload_size!=limit-8 || !selected->no_pmtud)return 8;
    }
    options.max_udp_payload_size=1207;if(options.valid() || h::TransportProfile<16,16384>::settings(options))return 9;
    options.salamander_password.reset();options.max_udp_payload_size=1200;options.disable_path_mtu_discovery=false;
    auto minimum=h::TransportProfile<16,16384>::settings(options);
    if(!minimum || minimum->max_tx_udp_payload_size!=1200 || minimum->no_pmtud)return 10;
    options.max_udp_payload_size=1501;if(options.valid())return 11;
    constexpr std::array<std::uint8_t,40> expected{
        0xb1,0x87,0x34,0x47,0x8b,0x28,0x5f,0x67,0xa3,0xc5,0xa8,0x33,0x06,0x0d,0x77,0x16,
        0x23,0xe9,0x7c,0xcd,0xa6,0xb9,0x06,0x38,0x31,0xfa,0xa8,0xca,0x6d,0xe9,0x08,0x23,
        0x91,0xa7,0x14,0x67,0xab,0x08,0x7f,0x47};
    std::array<std::uint8_t,40> payload{};
    for(std::size_t i=0;i<payload.size();++i)payload[i]=static_cast<std::uint8_t>(i);
    h::salamander_transform(payload,password,salt);
    if(payload!=expected)return 1;
    h::salamander_transform(payload,password,salt);
    for(std::size_t i=0;i<payload.size();++i)if(payload[i]!=i)return 2;
    Port port;h::SalamanderPort<Port> wire(port,std::span<std::uint8_t const>(password));
    std::array<std::uint8_t,64> datagram{};auto now=n::DatagramClock::now();
    auto packet=wire.output(datagram,now);
    if(!packet || !*packet || (**packet).size!=48 || (**packet).token!=7)return 3;
    if(!wire.receive({},std::span(datagram).first(48),now) || !std::ranges::equal(port.received,payload))return 4;
    port.received.clear();if(!wire.receive({},std::span(datagram).first(7),now) || !port.received.empty())return 5;
    h::SalamanderPort<Port> plain(port,{});packet=plain.output(datagram,now);
    if(!packet || !*packet || (**packet).size!=40 || !std::ranges::equal(std::span(datagram).first(40),payload))return 6;
    for(std::size_t len:{std::size_t{0},std::size_t{1},std::size_t{31},std::size_t{32},std::size_t{33},std::size_t{64},std::size_t{127},std::size_t{1300}}) {
        std::vector<std::uint8_t> buf(len);
        for(std::size_t i=0;i<len;++i) buf[i]=static_cast<std::uint8_t>((i*37+13)&0xff);
        auto orig=buf;
        h::salamander_transform(buf,password,salt);
        for(std::size_t i=0;i<std::min<std::size_t>(len,40);++i) {
            std::uint8_t mask_byte=expected[i]^static_cast<std::uint8_t>(i);
            if(buf[i]!=(orig[i]^mask_byte)) return 12;
        }
        h::salamander_transform(buf,password,salt);
        if(buf!=orig) return 13;
    }
    return 0;
}
