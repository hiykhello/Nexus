import std;
import tailscale.control;
import tailscale.control_messages;
namespace m=tailscale::control_messages;
namespace c=tailscale::control;
namespace {
    std::atomic<std::size_t> allocations=0;
    auto allocate(std::size_t size,std::size_t alignment=0) -> void* {
        ++allocations;size=std::max(std::size_t{1},size);
        if (alignment && size>std::numeric_limits<std::size_t>::max()-(alignment-1)) throw std::bad_alloc();
        auto pointer=alignment ? std::aligned_alloc(alignment,((size+alignment-1)/alignment)*alignment) : std::malloc(size);
        if (!pointer) throw std::bad_alloc();return pointer;
    }
}
auto operator new(std::size_t size) -> void* {return allocate(size);}
auto operator new[](std::size_t size) -> void* {return allocate(size);}
auto operator new(std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator new[](std::size_t size,std::align_val_t alignment) -> void* {return allocate(size,static_cast<std::size_t>(alignment));}
auto operator delete(void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete(void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto operator delete[](void* pointer,std::size_t,std::align_val_t) noexcept -> void {std::free(pointer);}
auto require(bool condition,std::string_view message) -> void {if (!condition) throw std::runtime_error(std::string(message));}
auto view(std::string_view text) -> std::span<std::uint8_t const> {return {reinterpret_cast<std::uint8_t const*>(text.data()),text.size()};}
auto key(unsigned first) -> c::NodePublic {c::KeyBytes bytes{};for (unsigned i=0;i<32;++i) bytes[i]=static_cast<std::uint8_t>(first+i);return *c::NodePublic::from_bytes(bytes);}
auto hex(std::span<std::uint8_t const> bytes) -> std::string {std::string text;for (auto byte:bytes) {text+="0123456789abcdef"[byte>>4];text+="0123456789abcdef"[byte&15];}return text;}
auto node(unsigned id,unsigned first,std::string_view extra={}) -> std::string {
    return "{\"ID\":"+std::to_string(id)+",\"Name\":\"alpha\",\"Key\":\"nodekey:"+hex(key(first).view())+"\",\"Addresses\":[\"100.64.0.1/32\",\"fd7a:115c:a1e0::1/128\"]"+std::string(extra)+"}";
}
auto origin(std::uint64_t connection=7,std::uint64_t stream=9) -> m::DecodeOrigin {return {key(1),connection,stream};}
auto registration() -> void {
    for (auto [json,wanted]:std::array{
        std::pair{R"({"MachineAuthorized":true})",m::RegistrationState::authorized},
        std::pair{R"({"MachineAuthorized":false})",m::RegistrationState::pending},
        std::pair{R"({})",m::RegistrationState::pending},
        std::pair{R"({"AuthURL":"https://login.example/x","MachineAuthorized":true})",m::RegistrationState::pending},
        std::pair{R"({"NodeKeyExpired":true,"MachineAuthorized":true,"AuthURL":"https://login.example"})",m::RegistrationState::expired},
        std::pair{R"({"Error":"denied","NodeKeyExpired":true,"AuthURL":"https://login.example","MachineAuthorized":true,"NodeKeySignature":"AQ=="})",m::RegistrationState::denied},
        std::pair{R"({"Error":"\u0064enied"})",m::RegistrationState::denied},
        std::pair{R"({"AuthURL":null,"Error":null,"NodeKeyExpired":null,"MachineAuthorized":true})",m::RegistrationState::authorized}}) {
        auto parsed=m::parse_register(200,view(json));require(parsed && parsed->state==wanted,"register state/precedence");
    }
    auto signature=m::parse_register(200,view(R"({"NodeKeySignature":"AQ==","NodeKeyExpired":true})"));
    require(!signature && signature.error().error==m::Error::unsupported_security,"signature precedes expiry");
    for (auto json:{R"({"FutureSecurity":true})",R"({"MachineAuthorized":"true"})",R"({"AuthURL":[]})",R"({"Error":false})",R"({"MachineAuthorized":false,"MachineAuthorized":true})",R"({"Machine\u0041uthorized":true})",R"([])",R"(null)","{}junk"})
        require(!m::parse_register(200,view(json)),"register invalid schema/trailing");
    auto status=m::parse_register(429,view("not JSON"));require(!status && status.error()==m::Failure{m::Error::http_status,429},"HTTP status mixed with denied");
    require(!m::parse_register(200,{}) && !m::parse_register(200,view(std::string(m::max_json_bytes+1,' '))),"register byte cap");
    auto exact=std::string("{}");exact.append(m::max_json_bytes-exact.size(),' ');require(bool(m::parse_register(200,view(exact))),"exact register JSON byte cap");
    auto document=std::string(R"({"AuthURL":"https://login.example","Error":""})");auto borrowed=m::parse_register(200,view(document));
    require(borrowed && borrowed->auth_url.json.data()>=document.data() && borrowed->auth_url.json.data()<document.data()+document.size(),"reply raw JSON not borrowed");
    document[document.find("login")]='L';require(borrowed->auth_url.json.contains("Login"),"reply lifetime is owning copy");
}
auto request_lifetime() -> void {
    std::array<std::uint8_t,2048> output{};m::RegisterRequest request{key(1),"test-auth-key-\\\"example","nexus-test","linux","Nexus-test",true};
    std::size_t size=0;
    {
        auto encoded=m::encode_register(output,request);require(bool(encoded),"register encode");size=encoded->bytes().size();
        auto json=std::string_view(reinterpret_cast<char const*>(encoded->bytes().data()),size);
        require(json.contains("\"Version\":148") && json.contains("\"Auth\":{\"AuthKey\":") && json.contains("\"Ephemeral\":true") && json.contains("\"Hostname\":\"nexus-test\""),"minimal request fields");
        m::RegisterWire moved(std::move(*encoded));require(encoded->bytes().empty() && moved.bytes().size()==size,"wire move cleared wrong owner");
        moved.clear();require(moved.bytes().empty() && std::ranges::all_of(std::span(output).first(size),[](auto x){return x==0;}),"explicit secret clear");
    }
    output.fill(0xa5);{auto encoded=m::encode_register(output,request);require(bool(encoded),"abandoned wire");size=encoded->bytes().size();}
    require(std::ranges::all_of(std::span(output).first(size),[](auto x){return x==0;}),"wire destructor did not clear");
    for (std::size_t capacity:{0,1,17,128,256}) {
        output.fill(0xa5);auto failed=m::encode_register(std::span(output).first(capacity),request);
        if (failed) {failed->clear();require(std::ranges::all_of(std::span(output).subspan(capacity),[](auto x){return x==0xa5;}),"successful JSON crossed output span");continue;}
        require(std::ranges::all_of(std::span(output).first(capacity),[](auto x){return x==0;}),"partial JSON failure leaked AuthKey");
        require(std::ranges::all_of(std::span(output).subspan(capacity),[](auto x){return x==0xa5;}),"failed JSON crossed output span");
    }
    output.fill(0xa5);auto invalid=request;invalid.auth_key="";
    require(!m::encode_register(output,invalid) && std::ranges::all_of(output,[](auto x){return x==0;}),"invalid request output not cleared");
    output.fill('a');auto alias=request;alias.auth_key={reinterpret_cast<char const*>(output.data()),17};
    require(!m::encode_register(output,alias) && std::ranges::all_of(output,[](auto x){return x==0;}),"AuthKey output overlap");
    auto unicode=request;unicode.auth_key="test-auth-key-密钥";unicode.hostname="测试节点";
    {auto encoded=m::encode_register(output,unicode);require(bool(encoded),"valid UTF-8 request rejected");}
    std::array<char,3> invalid_utf8{'x',static_cast<char>(0xff),'y'};auto bad_utf8=request;bad_utf8.auth_key={invalid_utf8.data(),invalid_utf8.size()};output.fill(0xa5);
    require(!m::encode_register(output,bad_utf8) && std::ranges::all_of(output,[](auto x){return x==0;}),"invalid UTF-8 AuthKey leaked/accepted");
    std::array<std::uint8_t,16384> maximum{};std::string auth(4096,'\\');auto long_request=request;long_request.auth_key=auth;
    {auto encoded=m::encode_register(maximum,long_request);require(bool(encoded),"4096-byte escaped AuthKey");}
    auth+='a';long_request.auth_key=auth;maximum.fill(0xa5);require(!m::encode_register(maximum,long_request) && std::ranges::all_of(maximum,[](auto x){return x==0;}),"AuthKey max+1 erasure");
}
auto maps() -> void {
    auto scratch=std::make_unique<m::MapCandidate>();auto self=node(1,1);auto peer=node(2,41,R"(,"Endpoints":["192.0.2.3:443","[2001:db8::3]:443"],"HomeDERP":1)");
    auto document="{\"Node\":"+self+",\"Peers\":["+peer+"],\"MapSessionHandle\":\"session-1\",\"Seq\":1}";
    require(bool(m::parse_map(view(document),origin(),*scratch)),"map candidate");auto parsed=scratch->view();
    require(parsed && parsed->mode==m::MapMode::full && parsed->self && parsed->self->key==key(1) && parsed->peers.size()==1 && parsed->peers[0].key==key(41),"map identity/full mode");
    auto const& selected=parsed->peers[0];require(selected.addresses.size()==2 && selected.allowed_ips.size()==2 && selected.allowed_ips_presence==m::Presence::missing &&
        selected.endpoints.size()==2 && selected.endpoints[1].family==6 && selected.home_derp==1,"peer addresses/implicit AllowedIPs/endpoints");
    require(parsed->origin.connection_generation==7 && parsed->origin.stream_generation==9 && parsed->session_handle.json=="\"session-1\"" && parsed->sequence.json=="1","map origin/checkpoint");
    auto name=selected.name.json;auto position=document.find("alpha",document.find("\"Peers\""));document[position]='b';require(name=="\"blpha\"","candidate input borrow lifetime");
    for (auto [field,presence]:std::array{std::pair{"",m::Presence::missing},std::pair{",\"AllowedIPs\":null",m::Presence::null_value},std::pair{",\"AllowedIPs\":[]",m::Presence::value}}) {
        auto json="{\"Peers\":["+node(2,41,field)+"]}";require(bool(m::parse_map(view(json),origin(),*scratch)),"AllowedIPs presence");auto value=scratch->view();
        require(value && value->peers[0].allowed_ips_presence==presence && value->peers[0].allowed_ips.size()==(presence==m::Presence::value ? 0u : 2u),"null/missing/empty AllowedIPs conflated");
    }
    for (auto json:{R"({})",R"({"Peers":null,"Seq":null,"MapSessionHandle":null})",R"({"Peers":[],"Seq":0,"MapSessionHandle":""})"}) {
        require(bool(m::parse_map(view(json),origin(11,13),*scratch)),"map presence frame");auto value=scratch->view();require(value && value->origin.connection_generation==11 && value->origin.stream_generation==13,"origin generations merged");
        if (std::string_view(json).contains("null")) require(value->peers_presence==m::Presence::null_value && value->sequence.presence==m::Presence::null_value,"map null presence");
        else if (std::string_view(json).contains("[]")) require(value->peers_presence==m::Presence::value && value->sequence.presence==m::Presence::value,"map empty presence");
        else require(value->peers_presence==m::Presence::missing && value->sequence.presence==m::Presence::missing,"map missing presence");
    }
    auto delta="{\"PeersChanged\":["+node(2,41)+"],\"PeersRemoved\":[3],\"Seq\":2}";
    require(bool(m::parse_map(view(delta),origin(),*scratch)) && scratch->view()->mode==m::MapMode::delta && scratch->view()->changed.size()==1 && scratch->view()->removed.size()==1,"delta candidate");
    auto keep="{\"KeepAlive\":true,\"Peers\":["+node(2,41)+"],\"Seq\":0}";
    require(bool(m::parse_map(view(keep),origin(),*scratch)) && scratch->view()->keep_alive && scratch->view()->peers.empty() && scratch->view()->mode==m::MapMode::unchanged,"KeepAlive installed network fields");
    for (auto field:{R"("PacketFilter":[])",R"("PacketFilters":{})",R"("TKAInfo":{"Disabled":true})",R"("PeersChangedPatch":[{"NodeID":2}])",R"("OnlineChange":{"2":true})",R"("FutureACL":true)"}) {
        auto json="{"+std::string(field)+"}";require(!m::parse_map(view(json),origin(),*scratch) && !scratch->view(),"unsupported map security/unknown became installable");
    }
    for (auto extra:{R"(,"CapMap":{"future-secure":[]})",R"(,"Capabilities":["unknown"])",R"(,"KeySignature":"AQ==")",R"(,"Cap":149)",R"(,"UnsignedPeerAPIOnly":true)",R"(,"FutureNodeACL":true)",R"(,"AllowedIPs":["100.64.0.1/24"])",R"(,"Endpoints":["0.0.0.0:443"])",R"(,"Endpoints":["example.com:443"])",R"(,"Endpoints":["[fe80::1%2]:443"])",R"(,"AllowedIPs":["1.2.3.4/99"])",R"(,"AllowedIPs":["0.0.0.0/0","0.0.0.0/0"])",R"(,"Name":"escaped\u0061")"}) {
        auto json="{\"Peers\":["+node(2,41,extra)+"]}";require(!m::parse_map(view(json),origin(),*scratch) && !scratch->view(),"invalid/unsupported node candidate accepted");
    }
    for (auto json:{"{\"Node\":"+node(1,41)+"}","{\"Peers\":["+node(2,1)+"]}","{\"Peers\":["+node(2,41)+","+node(2,73)+"]}","{\"Peers\":["+node(2,41)+","+node(3,41)+"]}"})
        require(!m::parse_map(view(json),origin(),*scratch) && !scratch->view(),"duplicate/self peer identity");
    for (auto json:{R"({"PeersRemoved":[2,2]})",R"({"PeersRemoved":[0]})",R"({"Seq":-1})",R"({"Peers":"not-array"})",R"({"Peers":[null]})","{}junk",R"(null)"})
        require(!m::parse_map(view(json),origin(),*scratch) && !scratch->view(),"invalid map envelope");
    for (auto json:{R"({"PacketFilters":{"base":[]},"PacketFilters":null})",R"({"Seq":1,"Seq":2})",R"({"MapSessionHandle":"a","MapSessionHandle":"b"})"})
        require(!m::parse_map(view(json),origin(),*scratch) && !scratch->view(),"duplicate map field merged/lost");
    auto repeated="{\"Peers\":["+node(2,41,R"(,"CapMap":{"future":[]},"CapMap":{})")+"]}";
    require(!m::parse_map(view(repeated),origin(),*scratch) && !scratch->view(),"repeated capability object lost earlier unknown field");
    auto keep_unsupported="{\"KeepAlive\":true,\"Peers\":["+node(2,41,R"(,"CapMap":{"future":[]})")+"]}";
    require(!m::parse_map(view(keep_unsupported),origin(),*scratch) && !scratch->view(),"KeepAlive hid unknown security capability");
    auto self_id="{\"Node\":"+node(1,1)+",\"Peers\":["+node(1,41)+"]}";require(!m::parse_map(view(self_id),origin(),*scratch),"peer reused self ID");
    auto prefixes=std::string(",\"AllowedIPs\":[");for (unsigned i=0;i<33;++i) {if (i) prefixes+=',';prefixes+="\"10.0."+std::to_string(i)+".0/24\"";}prefixes+=']';
    auto prefix_overflow="{\"Peers\":["+node(2,41,prefixes)+"]}";require(!m::parse_map(view(prefix_overflow),origin(),*scratch) && !scratch->view(),"prefix capacity");
    auto endpoints=std::string(",\"Endpoints\":[");for (unsigned i=0;i<17;++i) {if (i) endpoints+=',';endpoints+="\"192.0.2.3:"+std::to_string(1000+i)+"\"";}endpoints+=']';
    auto endpoint_overflow="{\"Peers\":["+node(2,41,endpoints)+"]}";require(!m::parse_map(view(endpoint_overflow),origin(),*scratch) && !scratch->view(),"endpoint capacity");
    auto many=std::string("{\"Peers\":[");for (unsigned i=0;i<65;++i) {if (i) many+=',';many+=node(i+2,i+41);}many+="]}";
    require(!m::parse_map(view(many),origin(),*scratch) && !scratch->view(),"peer capacity");
    require(!m::parse_map(view("{}"),origin(0,9),*scratch) && !m::parse_map(view(std::string(m::max_json_bytes+1,' ')),origin(),*scratch),"generation/byte cap");
    auto exact=std::string("{}");exact.append(m::max_json_bytes-exact.size(),' ');require(bool(m::parse_map(view(exact),origin(),*scratch)),"exact map JSON byte cap");
    scratch->clear();require(!scratch->view(),"cleared staging reused");
}
auto allocation() -> void {
    auto scratch=std::make_unique<m::MapCandidate>();auto map="{\"Peers\":["+node(2,41)+"]}";
    auto bad="{\"Peers\":["+node(2,41,R"(,"CapMap":{"future":[]})")+"]}";
    std::array<std::uint8_t,2048> output{};m::RegisterRequest request{key(1),"test-auth-key","nexus-test","linux","Nexus-test",false};auto before=allocations.load();
    for (unsigned i=0;i<100;++i) {
        auto encoded=m::encode_register(output,request);require(bool(encoded),"measured request");encoded->clear();
        require(bool(m::parse_register(200,view(R"({"MachineAuthorized":true})"))),"measured response");
        require(bool(m::parse_map(view(map),origin(),*scratch)) && !m::parse_map(view(bad),origin(),*scratch),"measured map");
    }
    require(allocations.load()==before,"typed decoder C++ allocation");
}
auto state_name(m::RegistrationState value) -> std::string_view {
    switch (value) {case m::RegistrationState::authorized:return "authorized";case m::RegistrationState::pending:return "pending";case m::RegistrationState::expired:return "expired";case m::RegistrationState::denied:return "denied";}return "invalid";
}
auto error_name(m::Error value) -> std::string_view {
    switch (value) {case m::Error::state:return "state";case m::Error::http_status:return "http_status";case m::Error::size:return "size";case m::Error::json:return "json";
    case m::Error::schema:return "schema";case m::Error::limit:return "limit";case m::Error::identity:return "identity";case m::Error::address:return "address";
    case m::Error::duplicate:return "duplicate";case m::Error::unsupported_security:return "unsupported_security";case m::Error::capacity:return "capacity";case m::Error::overlap:return "overlap";}return "invalid";
}
auto read_input() -> std::string {
    std::string input;std::array<char,4096> buffer{};
    while (std::cin) {std::cin.read(buffer.data(),buffer.size());input.append(buffer.data(),std::cin.gcount());if (input.size()>m::max_json_bytes) throw std::runtime_error("input cap");}return input;
}
auto main(int argc,char** argv) -> int {
    try {
        if (argc==2 && std::string_view(argv[1])=="--parsers-only") {registration();maps();std::println("typed register/Map parsers passed");return 0;}
        if (argc==2 && std::string_view(argv[1])=="--request") {
            std::array<std::uint8_t,2048> output{};m::RegisterRequest request{key(1),"test-auth-key-\\\"example","nexus-test","linux","Nexus-test",true};auto encoded=m::encode_register(output,request);
            require(bool(encoded),"request oracle");std::cout.write(reinterpret_cast<char const*>(encoded->bytes().data()),encoded->bytes().size());return 0;
        }
        if (argc==3 && std::string_view(argv[1])=="--register") {
            unsigned status=0;auto text=std::string_view(argv[2]);auto number=std::from_chars(text.data(),text.data()+text.size(),status);if (number.ec!=std::errc{} || number.ptr!=text.data()+text.size()) return 64;
            auto input=read_input();auto reply=m::parse_register(status,view(input));if (!reply) {std::println("failure:{}:{}",error_name(reply.error().error),reply.error().status);return 0;}
            std::println("state:{}",state_name(reply->state));return 0;
        }
        if (argc==2 && std::string_view(argv[1])=="--map") {
            auto input=read_input();auto scratch=std::make_unique<m::MapCandidate>();auto parsed=m::parse_map(view(input),origin(),*scratch);
            if (!parsed) {std::println("failure:{}:{}",error_name(parsed.error().error),parsed.error().status);return 0;}
            auto value=scratch->view();require(bool(value),"map oracle view");
            std::println("map:{}:{}:{}:{}:{}:{}:{}:{}:{}",static_cast<unsigned>(value->mode),value->keep_alive,value->self!=nullptr,value->peers.size(),value->changed.size(),value->removed.size(),
                static_cast<unsigned>(value->peers_presence),static_cast<unsigned>(value->sequence.presence),static_cast<unsigned>(value->session_handle.presence));return 0;
        }
        registration();request_lifetime();maps();allocation();
        std::println("Typed v148 register states/status, erasing AuthKey wire, borrowed bounded non-installable Map candidate and zero C++ allocation passed");
        std::println("sizeof(RegisterWire)={} RegisterReply={} PeerCandidate={} MapCandidate={} MapView={}",sizeof(m::RegisterWire),sizeof(m::RegisterReply),sizeof(m::PeerCandidate),sizeof(m::MapCandidate),sizeof(m::MapView));
    } catch (std::exception const& error) {std::cerr<<error.what()<<'\n';return 1;}
}
