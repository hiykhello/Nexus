import std;
import packet;
namespace p = ::packet;
int main() {
    p::Bytes sample6{0x60,0,0,0,0,27,6,64,0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1,
        0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,2,0x04,0xd2,0x01,0xbb,0x12,0x34,0x56,0x78,
        0x9a,0xbc,0xde,0xf0,0x60,0x12,0x10,0,0x7f,0x55,0,0,2,4,5,0xb4,'a','b','c'};
    auto v6=p::parse_tcp6(sample6);
    if (!v6 || v6->source_port!=1234 || v6->destination_port!=443 || v6->sequence!=0x12345678 ||
        v6->acknowledgement!=0x9abcdef0 || v6->flags!=0x12 || v6->window!=4096 ||
        !std::ranges::equal(v6->payload,p::Bytes{'a','b','c'}) || !p::make_tcp6(*v6) || *p::make_tcp6(*v6)!=sample6) return 1;
    for (std::size_t i=0;i<sample6.size();++i) if (p::parse_tcp6(std::span(sample6).first(i))) return 1;
    auto bad6=sample6; bad6.back()^=1;
    if (p::parse_tcp6(bad6).error()!=p::PacketError::invalid_checksum) return 1;
    bad6=sample6; bad6[6]=44;
    if (p::parse_tcp6(bad6).error()!=p::PacketError::unsupported_fragment) return 1;
    bad6=sample6; bad6[6]=60;
    if (p::parse_tcp6(bad6)) return 1;
    // The TCP pseudo-header excludes extension bytes and their length.
    auto ext6=sample6;
    ext6.insert(ext6.begin()+40,{60,0,1,4,0,0,0,0, 6,0,0x1e,2,0xaa,0xbb,1,0});
    ext6[6]=0; ext6[5]=static_cast<std::uint8_t>(ext6.size()-40);
    auto parsed6=p::parse_tcp6(ext6);
    if (!parsed6 || parsed6->sequence!=v6->sequence || !std::ranges::equal(parsed6->payload,v6->payload)) return 1;
    auto invalid6=ext6; invalid6[50]=0x80;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::unsupported_header) return 1;
    invalid6=ext6; invalid6[43]=7;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::invalid_length) return 1;
    invalid6=ext6; invalid6[40]=0;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::unsupported_header) return 1;
    invalid6=ext6; invalid6[48]=44;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::unsupported_fragment) return 1;
    invalid6=ext6; invalid6[48]=43;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::unsupported_header) return 1;
    invalid6=ext6; invalid6[51]=7;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::invalid_length) return 1;
    invalid6=ext6; invalid6[44]=1;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::unsupported_header) return 1;
    invalid6=ext6; invalid6.back()^=1;
    if (p::parse_tcp6(invalid6).error()!=p::PacketError::invalid_checksum) return 1;
    for (std::size_t i=0;i<ext6.size();++i) if (p::parse_tcp6(std::span(ext6).first(i))) return 1;
    if (p::make_tcp6(*v6, sample6.size()-1).error()!=p::PacketError::too_large) return 1;
    p::Bytes sample{0x45,0,0,0x2f,0,0,0x40,0,0x40,6,0x4e,0x92,0xc0,0,2,1,
        0xc6,0x33,0x64,2,0x04,0xd2,0x01,0xbb,0x12,0x34,0x56,0x78,0x9a,0xbc,0xde,0xf0,
        0x60,0x12,0x10,0,0xee,0x92,0,0,2,4,5,0xb4,'a','b','c'};
    auto v = p::parse_tcp4(sample);
    if (!v || v->source != p::Address4{192,0,2,1} || v->destination != p::Address4{198,51,100,2} ||
        v->source_port != 1234 || v->destination_port != 443 || v->sequence != 0x12345678 ||
        v->acknowledgement != 0x9abcdef0 || v->flags != 0x12 || v->window != 4096 ||
        !std::ranges::equal(v->options, p::Bytes{2,4,5,0xb4}) ||
        !std::ranges::equal(v->payload, p::Bytes{'a','b','c'})) return 1;
    auto built = p::make_tcp4(*v);
    if (!built || *built != sample) return 1;
    auto padded=sample;
    padded.insert(padded.begin()+20,{1,1,0,0}); padded[0]=0x46; padded[3]=static_cast<std::uint8_t>(padded.size());
    auto fix_header=[](p::Bytes& packet) {
        packet[10]=packet[11]=0;
        auto sum=p::internet_checksum(std::span(packet).first((packet[0]&15)*4));
        packet[10]=static_cast<std::uint8_t>(sum>>8); packet[11]=static_cast<std::uint8_t>(sum);
    };
    fix_header(padded);
    auto padded_view=p::parse_tcp4(padded);
    if (!padded_view || padded_view->sequence!=v->sequence || padded_view->source_port!=v->source_port ||
        !std::ranges::equal(padded_view->options,v->options) || !std::ranges::equal(padded_view->payload,v->payload)) return 1;
    auto bad_ip=padded; bad_ip[21]=7; fix_header(bad_ip);
    if (p::parse_tcp4(bad_ip).error()!=p::PacketError::unsupported_header) return 1;
    bad_ip=padded; bad_ip[23]=1; fix_header(bad_ip);
    if (p::parse_tcp4(bad_ip).error()!=p::PacketError::unsupported_header) return 1;
    bad_ip=padded; bad_ip[20]^=1;
    if (p::parse_tcp4(bad_ip).error()!=p::PacketError::invalid_checksum) return 1;
    bad_ip=padded; bad_ip.back()^=1;
    if (p::parse_tcp4(bad_ip).error()!=p::PacketError::invalid_checksum) return 1;
    bad_ip=padded; bad_ip[0]=0x44;
    if (p::parse_tcp4(bad_ip).error()!=p::PacketError::invalid_length) return 1;
    auto parsed_options = p::parse_tcp_options(v->options);
    if (!parsed_options || parsed_options->count != 1 || parsed_options->items[0].kind != 2 ||
        !std::ranges::equal(parsed_options->items[0].data, p::Bytes{5,0xb4})) return 1;
    p::Bytes syn{2,4,5,0xb4, 1,3,3,20, 4,2, 8,10,1,2,3,4,5,6,7,8, 0,0,0,0};
    auto syn_options = p::parse_tcp_syn_options(syn);
    if (!syn_options || syn_options->mss != 1460 || syn_options->window_scale != 14 ||
        !syn_options->sack_permitted || syn_options->timestamp != std::pair{0x01020304u,0x05060708u}) return 1;
    p::Bytes duplicate{2,4,5,0xb4,2,4,5,0xb4};
    if (p::parse_tcp_syn_options(duplicate).error() != p::PacketError::unsupported_header) return 1;
    p::Bytes malformed{3,4,1,0};
    if (p::parse_tcp_syn_options(malformed).error() != p::PacketError::unsupported_header) return 1;
    for (p::Bytes invalid_syn : {p::Bytes{4,2,4,2}, p::Bytes{3,3,1,3,3,2,0,0},
                               p::Bytes{2,3,1,0}, p::Bytes{4,3,0,0}, p::Bytes{8,2,0,0}})
        if (p::parse_tcp_syn_options(invalid_syn).error() != p::PacketError::unsupported_header) return 1;
    p::Bytes unknown{99,4,1,2};
    auto ignored = p::parse_tcp_syn_options(unknown);
    if (!ignored || ignored->mss || ignored->window_scale || ignored->sack_permitted || ignored->timestamp) return 1;
    p::Bytes mixed{1, 99, 4, 8, 9, 0, 255, 255};
    auto parsed_mixed = p::parse_tcp_options(mixed);
    if (!parsed_mixed || parsed_mixed->count != 2 || parsed_mixed->items[0].kind != 1 ||
        parsed_mixed->items[1].kind != 99 || !std::ranges::equal(parsed_mixed->items[1].data, p::Bytes{8,9})) return 1;
    p::Bytes many_nops(40, 1);
    if (!p::parse_tcp_options(many_nops) || p::parse_tcp_options(many_nops)->count != 40) return 1;
    p::Bytes bad_length{2, 1, 0, 0};
    if (p::parse_tcp_options(bad_length).error() != p::PacketError::invalid_length) return 1;
    bad_length[1] = 5;
    if (p::parse_tcp_options(bad_length).error() != p::PacketError::invalid_length) return 1;
    p::Bytes missing_length{1, 1, 1, 2};
    if (p::parse_tcp_options(missing_length).error() != p::PacketError::truncated) return 1;
    if (p::parse_tcp_options(std::span(many_nops).first(3)).error() != p::PacketError::invalid_length) return 1;
    many_nops.resize(44);
    if (p::parse_tcp_options(many_nops).error() != p::PacketError::invalid_length) return 1;
    for (std::size_t n = 0; n < sample.size(); ++n)
        if (p::parse_tcp4(std::span(sample).first(n))) return 1;
    auto invalid = sample; invalid.back() ^= 1;
    if (p::parse_tcp4(invalid).error() != p::PacketError::invalid_checksum) return 1;
    invalid = sample; invalid[12] ^= 1;
    if (p::parse_tcp4(invalid).error() != p::PacketError::invalid_checksum) return 1;
    invalid[10] = invalid[11] = 0;
    auto ip_checksum = p::internet_checksum(std::span(invalid).first(20));
    invalid[10] = static_cast<std::uint8_t>(ip_checksum >> 8); invalid[11] = static_cast<std::uint8_t>(ip_checksum);
    if (p::parse_tcp4(invalid).error() != p::PacketError::invalid_checksum) return 1;
    invalid = sample; invalid[32] = 0x40;
    if (p::parse_tcp4(invalid).error() != p::PacketError::invalid_length) return 1;
    invalid = sample; invalid[32] = 0xf0;
    if (p::parse_tcp4(invalid).error() != p::PacketError::invalid_length) return 1;
    invalid = sample; invalid[32] |= 2;
    if (p::parse_tcp4(invalid).error() != p::PacketError::unsupported_header) return 1;
    if (p::make_tcp4(*v, sample.size() - 1).error() != p::PacketError::too_large) return 1;
    auto too_many = *v; p::Bytes options(44); too_many.options = options;
    if (p::make_tcp4(too_many).error() != p::PacketError::unsupported_header) return 1;
    auto odd_options = *v; odd_options.options = std::span(options).first(3);
    if (p::make_tcp4(odd_options).error() != p::PacketError::unsupported_header) return 1;
    auto ns = *v; ns.flags = 0x112;
    auto ns_packet = p::make_tcp4(ns);
    if (!ns_packet || !p::parse_tcp4(*ns_packet) || p::parse_tcp4(*ns_packet)->flags != ns.flags) return 1;
    auto maximum = *v; maximum.options = {}; p::Bytes payload(65535 - 40, 0x5a); maximum.payload = payload;
    auto large = p::make_tcp4(maximum, 65535);
    if (!large || large->size() != 65535 || !p::parse_tcp4(*large)) return 1;
    payload.push_back(0); maximum.payload = payload;
    if (p::make_tcp4(maximum, 65536).error() != p::PacketError::too_large) return 1;
    std::cout << "IPv4 TCP fixed sample, bounds and checksums passed\n";
}
