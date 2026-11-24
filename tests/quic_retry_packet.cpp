import std;
import quic.retry_packet;
import ngtcp2;
namespace q=quic;namespace n = ::ngtcp2;
auto require(bool condition,char const* label) -> void {if(!condition){std::println("Retry packet failure: {}",label);std::exit(1);}}
auto decode(std::string_view hex) -> std::vector<std::uint8_t> {
    std::vector<std::uint8_t> bytes;
    for(std::size_t i=0;i<hex.size();i+=2)bytes.push_back(static_cast<std::uint8_t>(std::stoul(std::string(hex.substr(i,2)),nullptr,16)));return bytes;
}
auto main() -> int {
    auto original=decode("8394c8f03e515708"),source=decode("f067a5502a4262b5"),token=decode("746f6b656e");
    std::array<std::uint8_t,1200> output{};q::RetryPacketWriter writer;
    require(!writer.write(output,{},source,original,token),"uninitialized slot");require(bool(writer.initialize()),"initialized");
    auto result=writer.write(output,{},source,original,token);require(result && *result==36,"RFC-sized packet");
    require(output[0]==0xf0 && output[4]==1 && output[5]==0 && output[6]==8,"native long header");
    require(std::ranges::equal(std::span(output).subspan(7,8),source) && std::ranges::equal(std::span(output).subspan(15,5),token),"native CID/token serialization");
    n::ngtcp2_version_cid parsed{};require(!n::ngtcp2_pkt_decode_version_cid(&parsed,output.data(),*result,8) && parsed.version==1 && parsed.dcidlen==0 && parsed.scidlen==8,"independent native decode");
    std::print("QUIC native Retry RFC-input output=");for(auto byte:std::span(output).first(*result))std::print("{:02x}",byte);std::println("");
    std::array<std::uint8_t,20> maximum{};std::iota(maximum.begin(),maximum.end(),17);auto other=maximum;other[0]^=1;std::array<std::uint8_t,1024> max_token{};
    auto maximum_packet=writer.write(output,maximum,maximum,other,max_token);require(maximum_packet && *maximum_packet==1087,"minimum-path bound");
    unsigned small=0;
    for(std::size_t size=0;size<1087;++size){auto failed=writer.write(std::span(output).first(size),maximum,maximum,other,max_token);require(!failed,"all undersized native outputs fail");++small;}
    require(!writer.write(output,maximum,maximum,maximum,max_token),"Retry CID must differ from original destination");
    require(!writer.write(output,source,std::span(source).first(7),original,token),"short server CID rejected");
    require(!writer.write(output,source,source,std::span(original).first(7),token),"short original CID rejected");
    require(!writer.write(output,source,source,original,{}),"empty token rejected");
    require(!writer.write(output,source,source,original,std::span(output).first(83)),"borrowed token overlap rejected");
    require(!writer.write(output,source,source,original,token,2),"unsupported version rejected");
    writer.clear();require(!writer.write(output,{},source,original,token),"cleared integrity slot rejected");
    require(bool(writer.initialize()) && bool(writer.write(output,{},source,original,token)),"fresh writer recovers");
    std::println("QUIC native Retry writer={} native_undersized={} max_packet=1087 borrow/role/version/clear/recovery=true",sizeof(writer),small);
}
