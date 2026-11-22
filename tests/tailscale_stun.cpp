import std;
import tailscale.stun;
import tailscale.stun_queries;
namespace s=tailscale::stun;
using Bytes=std::vector<std::uint8_t>;
using namespace std::chrono_literals;
auto require(bool condition,std::string_view message) -> void { if (!condition) throw std::runtime_error(std::string(message)); }
auto bytes(std::string_view text) -> Bytes {
    Bytes result;
    auto digit=[](char c)->unsigned { return c<='9' ? c-'0' : c-'a'+10; };
    for (std::size_t i=0;i<text.size();i+=2) result.push_back(static_cast<std::uint8_t>((digit(text[i])<<4)|digit(text[i+1])));
    return result;
}
auto transaction(unsigned start=0) -> s::Transaction {
    s::Transaction result{}; for (unsigned i=0;i<result.size();++i) result[i]=static_cast<std::uint8_t>(start+i); return result;
}
auto with_attribute(Bytes wire,std::span<std::uint8_t const> attribute) -> Bytes {
    wire.insert(wire.end(),attribute.begin(),attribute.end());
    auto size=wire.size()-20; wire[2]=static_cast<std::uint8_t>(size>>8); wire[3]=static_cast<std::uint8_t>(size); return wire;
}
auto rfc_vectors() -> void {
    auto v4=bytes("0101003c2112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000080001a147e112a643"
        "000800142b91f599fd9e90c38c7489f92af9ba53f06be7d780280004c07d4c96");
    auto v6=bytes("010100482112a442b7e7a701bc34d686fa87dfae8022000b7465737420766563746f7220002000140002a1470113a9fa"
        "a5d3f179bc25f4b5bed2b9d900080014a382954e4be67bf11784c97c8292c275bfe3ed4180280004c8fb0b4c");
    auto first=s::parse_response(v4),second=s::parse_response(v6);
    require(first && first->mapped==s::Endpoint{4,{192,0,2,1},32853},"RFC5769 IPv4/fingerprint");
    s::Endpoint expected{6,{0x20,0x01,0x0d,0xb8,0x12,0x34,0x56,0x78,0,0x11,0x22,0x33,0x44,0x55,0x66,0x77},32853};
    require(second && second->mapped==expected,"RFC5769 IPv6/fingerprint");
    v4.back()^=1; require(!s::parse_response(v4) && s::parse_response(v4).error()==s::Error::invalid_fingerprint,"bad fingerprint accepted");
    auto mapped=bytes("010100182112a4424fd5d202dcb37d31fc773306002000140002cd3d2112a4424fd5d202dcb382ce2dc3fcc7");
    auto normalized=s::parse_response(mapped);
    require(normalized && normalized->mapped==s::Endpoint{4,{209,180,207,193},60463},"mapped IPv6 normalization");
}
auto encoding_and_limits() -> void {
    auto tx=transaction(); auto request=s::encode_request(tx);
    require(s::parse_binding_request(request)==tx,"request round trip");
    auto expected=bytes("000100142112a442000102030405060708090a0b802200087461696c6e6f6465802800048aabad90");
    require(std::ranges::equal(request,expected),"fixed official request");
    for (std::size_t size=0;size<request.size();++size) require(!s::parse_binding_request(std::span(request).first(size)),"truncated request");
    auto altered=request; altered[24]='x'; require(!s::parse_binding_request(altered),"bad software or fingerprint");
    altered=request; altered.back()^=1; require(s::parse_binding_request(altered).error()==s::Error::invalid_fingerprint,"request checksum");
    auto response=s::encode_response(tx,s::Endpoint{4,{192,0,2,1},3478}); require(bool(response),"response encode");
    expected=bytes("0101000c2112a442000102030405060708090a0b0020000800012c84e112a643");
    require(std::ranges::equal(response->view(),expected),"fixed official response");
    auto parsed=s::parse_response(response->view(),tx);
    require(parsed && parsed->mapped==s::Endpoint{4,{192,0,2,1},3478},"response round trip");
    require(s::parse_response(response->view(),transaction(1)).error()==s::Error::wrong_transaction,"transaction mismatch");
    for (std::size_t size=0;size<response->size;++size) require(!s::parse_response(response->view().first(size)),"truncated response");
    Bytes extended(response->view().begin(),response->view().end()); extended.insert(extended.end(),{0xde,0xad});
    parsed=s::parse_response(extended); require(parsed && parsed->consumed==response->size,"response trailing bytes boundary");
    extended[3]=13; require(s::parse_response(extended).error()==s::Error::invalid_length,"unaligned length");
    extended.assign(response->view().begin(),response->view().end()); extended[22]=0xff;
    require(s::parse_response(extended).error()==s::Error::invalid_attribute,"attribute overflow");
    extended.assign(response->view().begin(),response->view().end()); extended[4]^=1;
    require(s::parse_response(extended).error()==s::Error::not_stun,"cookie mismatch");
    extended.assign(response->view().begin(),response->view().end()); extended[0]|=0x80;
    require(s::parse_response(extended).error()==s::Error::not_stun,"reserved high bits");
    extended.assign(response->view().begin(),response->view().end()); extended[1]=0x11;
    require(s::parse_response(extended).error()==s::Error::wrong_type,"wrong message class");
    auto alternate=Bytes(response->view().begin(),response->view().end()); alternate[20]=0x80;
    require(s::parse_response(alternate)->mapped==parsed->mapped,"alternate XOR tag");
    auto fallback=Bytes(response->view().begin(),response->view().end());
    fallback[21]=1; fallback[26]=0x0d; fallback[27]=0x96;
    std::copy_n(std::array<std::uint8_t,4>{192,0,2,1}.begin(),4,fallback.begin()+28);
    require(s::parse_response(fallback)->mapped==s::Endpoint{4,{192,0,2,1},3478},"MAPPED fallback");
    auto both=with_attribute(fallback,response->view().subspan(20));
    require(s::parse_response(both)->mapped==s::Endpoint{4,{192,0,2,1},3478},"XOR preferred");
    both=with_attribute(Bytes(response->view().begin(),response->view().end()),response->view().subspan(20));
    require(bool(s::parse_response(both)),"identical duplicate XOR");
    both.back()^=1;
    require(s::parse_response(both).error()==s::Error::conflicting_address,"conflicting XOR");
    auto padded=bytes("010100142112a442000102030405060708090a0b8022000161aabbcc0020000800012c84e112a643");
    require(s::parse_response(padded)->mapped==s::Endpoint{4,{192,0,2,1},3478},"nonzero attribute padding");
    require(!s::encode_response(tx,s::Endpoint{}),"invalid family");
}
auto lifecycle() -> void {
    s::Queries<2> queries;
    auto now=s::Clock::time_point{}+10s;
    s::Endpoint first{4,{192,0,2,53},3478},other{4,{192,0,2,54},3478},mapped{4,{198,51,100,3},4567};
    auto one=queries.reserve(transaction(),first,now,now+100ms);
    auto two=queries.reserve(transaction(16),other,now,now+200ms);
    require(one && two && queries.size()==2,"query reservations");
    require(queries.reserve(transaction(),first,now,now+100ms).error()==s::QueryError::duplicate,"duplicate transaction");
    require(queries.reserve(transaction(32),first,now,now+100ms).error()==s::QueryError::full,"capacity");
    auto reply=s::encode_response(transaction(),mapped); require(bool(reply),"query response");
    auto rejected=queries.accept(reply->view(),other,now+10ms);
    require(!rejected && rejected.error().error==s::QueryError::wrong_source && queries.size()==2,"spoofed source consumed query");
    auto corrupted=*reply; corrupted.bytes[25]=0xff;
    rejected=queries.accept(corrupted.view(),first,now+10ms);
    require(!rejected && rejected.error().error==s::QueryError::protocol && queries.size()==2,"bad reply consumed query");
    auto accepted=queries.accept(reply->view(),first,now+10ms);
    require(accepted && accepted->mapped==mapped && accepted->elapsed==10ms && queries.size()==1,"matched response");
    require(!queries.accept(reply->view(),first,now+11ms) && !queries.cancel(*one),"replay or old ticket");
    auto three=queries.reserve(transaction(32),first,now+20ms,now+50ms); require(bool(three),"slot reuse");
    require(!queries.cancel(*one) && queries.size()==2,"old ticket canceled replacement");
    auto response=s::encode_response(transaction(32),mapped);
    rejected=queries.accept(response->view(),first,now+50ms);
    require(!rejected && rejected.error().error==s::QueryError::timeout && queries.size()==1,"deadline accepted/reset");
    require(queries.expire(now+200ms)==1 && !queries.size(),"expiration");
    require(queries.reserve(transaction(40),first,now,now).error()==s::QueryError::invalid,"invalid deadline");
    auto four=queries.reserve(transaction(48),first,now,now+1s); require(bool(four),"final reservation");
    queries.stop();
    require(queries.closed() && !queries.size() && !queries.cancel(*four) &&
        queries.reserve(transaction(64),first,now,now+1s).error()==s::QueryError::closed,"stopped owner");
    require(!queries.accept(reply->view(),first,now) && queries.accept(reply->view(),first,now).error().error==s::QueryError::closed,"stopped receive");
}
auto main() -> int {
    try {
        rfc_vectors(); encoding_and_limits(); lifecycle();
        std::println("STUN RFC/official vectors, XOR mapping, bounded attributes, exact source/transaction, deadlines and query retirement passed");
        std::cout<<"sizeof(Queries<32>)="<<sizeof(s::Queries<32>)<<'\n';
    } catch (std::exception const& error) { std::cerr<<error.what()<<'\n'; return 1; }
}

