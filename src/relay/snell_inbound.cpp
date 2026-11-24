module relay;
import std;
import snell.record;
import crypto;
import snell.cipher;
import snell.owner;
import snell.replay;
import snell.credential_file;
import snell.http_obfs;
import snell.server_reply;
import snell.server_stream;
import snell.async_record;
import snell.async_packet;
import snell.packet;
import relay.stream_relay;
import relay.dns_state;
import net.stream_datagrams;
import rules;
import socks5;
import capy;
import corosio;

namespace relay {
    struct SnellReplayRegistry {
        struct Entry {
            std::shared_ptr<snell::ReplayCache<4096>> replay;std::uint32_t window;snell::Bytes psk;
            Entry(snell::View key,std::uint32_t seconds):replay(std::make_shared<snell::ReplayCache<4096>>()),window(seconds),psk(key.begin(),key.end()) {}
            ~Entry(){crypto::cleanse(psk);}
        };
        std::mutex mutex;std::vector<std::unique_ptr<Entry>> entries;
        auto acquire(snell::View key,std::uint32_t window) -> std::expected<std::shared_ptr<snell::ReplayCache<4096>>,std::string> {
            std::lock_guard lock(mutex);
            for(auto const& entry:entries) if(crypto::constant_time_equal(entry->psk,key)) {
                if(entry->window!=window)return std::unexpected("Snell listeners sharing a PSK require the same replay window");
                return entry->replay;
            }
            if(entries.size()>=16)return std::unexpected("too many Snell credential generations");
            auto entry=std::make_unique<Entry>(key,window);auto replay=entry->replay;entries.push_back(std::move(entry));return replay;
        }
    };
    auto create_snell_replay_registry() -> std::shared_ptr<SnellReplayRegistry> {return std::make_shared<SnellReplayRegistry>();}
    namespace {
        using namespace std::chrono_literals;
        using Socket=snell::HttpObfs<corosio::tcp_socket>;
        struct Profile {snell::ServerOwner<4096> owner;bool http_obfs;Profile(snell::Credential c,std::uint32_t window,std::shared_ptr<snell::ReplayCache<4096>> replay,bool obfs):owner(std::move(c),std::chrono::seconds(window),std::move(replay)),http_obfs(obfs){} };
        struct Stream {
            snell::ServerStream<Socket> stream;
            Stream(Socket& s,snell::Record<snell::Cipher> r,snell::Record<snell::Cipher> w,snell::Bytes early):stream(s,std::move(r),std::move(w),std::move(early)){}
            auto read(std::span<std::uint8_t> b){return stream.read(b,Clock::now()+300s);}
            auto send(std::span<std::uint8_t const> b){return stream.send(b,Clock::now()+300s);}
            auto close_output(){return stream.close_output(Clock::now()+300s);}
            auto cancel() noexcept ->void {stream.cancel();}
        };
        class PacketBridge {
            snell::AsyncRecord<Socket,snell::Cipher> records_;snell::AsyncPacket<decltype(records_)> packets_;
            capy::async_mutex send_lock_;net::DatagramDecoder input_{net::DatagramFraming{}};
            std::optional<snell::Packet> early_;snell::Bytes output_;std::size_t offset_=0;
        public:
            PacketBridge(Socket& s,snell::Record<snell::Cipher> r,snell::Record<snell::Cipher> w,std::optional<snell::Packet> early)
                :records_(s,std::move(r),std::move(w)),packets_(records_,false),early_(std::move(early)){}
            auto cancel() noexcept ->void {packets_.cancel();}
            auto read(std::span<std::uint8_t> data,Clock::time_point deadline)->capy::task<std::expected<std::size_t,std::string>> {
                if(data.empty())co_return std::unexpected("empty Snell packet buffer");
                if(offset_==output_.size()) {
                    std::optional<snell::Packet> packet;
                    if(early_){packet=std::move(early_);early_.reset();}
                    else {auto value=co_await packets_.receive(deadline);if(!value)co_return std::unexpected("Snell packet receive failed");packet=std::move(*value);}
                    if(packet->address.kind==snell::AddressKind::domain && !std::ranges::all_of(packet->address.value,[](std::uint8_t c){return c>32&&c<127&&c!='%'&&c!=':'&&c!='['&&c!=']';})){cancel();co_return std::unexpected("invalid Snell domain");}
                    net::ProxyAddress a;a.family=packet->address.kind==snell::AddressKind::ipv4?net::ProxyAddressFamily::ipv4:packet->address.kind==snell::AddressKind::ipv6?net::ProxyAddressFamily::ipv6:net::ProxyAddressFamily::domain;
                    if(packet->address.value.size()>a.bytes.size()){cancel();co_return std::unexpected("invalid Snell destination");}
                    a.length=packet->address.value.size();a.port=packet->address.port;std::ranges::copy(packet->address.value,a.bytes.begin());
                    auto frame=net::encode_datagram({},a,packet->payload);if(!frame){cancel();co_return std::unexpected("invalid Snell packet");}
                    output_=std::move(*frame);offset_=0;
                }
                auto n=std::min(data.size(),output_.size()-offset_);std::ranges::copy(std::span(output_).subspan(offset_,n),data.begin());offset_+=n;co_return n;
            }
            auto send(std::span<std::uint8_t const> wire,Clock::time_point deadline)->capy::task<bool> {
                auto [ec,lock]=co_await send_lock_.scoped_lock();if(ec)co_return false;
                auto fed=input_.feed(wire);if(fed.status!=net::DatagramStatus::accepted||fed.consumed!=wire.size()){cancel();co_return false;}
                auto p=input_.packet();if(!p){cancel();co_return false;}auto const& a=p->destination;
                if(a.family==net::ProxyAddressFamily::domain){cancel();co_return false;}
                auto kind=a.family==net::ProxyAddressFamily::ipv4?snell::AddressKind::ipv4:snell::AddressKind::ipv6;
                snell::Packet packet{{kind,snell::Bytes(a.bytes.begin(),a.bytes.begin()+a.length),a.port},snell::Bytes(p->payload.begin(),p->payload.end())};
                auto result=co_await packets_.send(packet,{},deadline);(void)input_.consume();co_return bool(result);
            }
        };
        auto target(std::string_view host,std::uint16_t port)->std::optional<socks5::Request> {
            if(host.empty()||host.size()>255||!port||!std::ranges::all_of(host,[](unsigned char c){return c>32&&c<127&&c!='%';}))return {};
            socks5::Request result;result.status=socks5::Status::accepted;result.port=port;
            auto text=host.find(':')!=host.npos ? "["+std::string(host)+"]:"+std::to_string(port) : std::string(host)+":"+std::to_string(port);
            auto [ec,endpoint]=corosio::make_endpoint(text);auto ip=endpoint.address();
            if(!ec&&ip.is_v4()){auto b=ip.to_v4().to_bytes();result.address_type=1;result.address_length=b.size();std::ranges::copy(b,result.address.begin());}
            else if(!ec){auto b=ip.to_v6().to_bytes();result.address_type=4;result.address_length=b.size();std::ranges::copy(b,result.address.begin());}
            else {if(host.find(':')!=host.npos||host.find('[')!=host.npos||host.find(']')!=host.npos)return {};result.address_type=3;result.address_length=host.size();std::ranges::copy(host,result.address.begin());}
            return result;
        }
        auto serve(Session& session,corosio::io_context& context,rules::RouteMatcher const& policy,Profile& profile)->capy::task<> {
            auto fail=[&]{session.close();session.done=true;};auto deadline=session.started+10s;
            Socket socket(session.client,profile.http_obfs,true);
            auto start=co_await profile.owner.start(socket,deadline);
            if(!start||session.closed){fail();co_return;}
            auto request=std::move(start->request);auto early=std::move(start->early);
            std::optional<snell::Record<snell::Cipher>> reader(std::move(start->reader)),writer;
            for(;;){
                if(request.command==5){
                    auto destination=target(request.host,request.port);if(!destination){fail();co_return;}
                    session.begin_traffic(TrafficProtocol::snell,destination->port);
                    auto dialed=co_await dial(session,context,policy,*destination,deadline);if(dialed||session.closed){fail();co_return;}
                    if(!writer){auto initial=co_await snell::server_reply(socket,profile.owner.psk(),deadline);if(!initial||session.closed){fail();co_return;}writer.emplace(std::move(*initial));}
                    else {snell::Bytes ack{0};if(!co_await snell::send_record(socket,*writer,ack,{},deadline)||session.closed){fail();co_return;}}
                    Stream incoming(socket,std::move(*reader),std::move(*writer),std::move(early));reader.reset();writer.reset();
                    session.relaying=true;session.touched=Clock::now();
                    try {(void)co_await capy::when_all(stream_relay::direction(session,stream_relay::upload(session,incoming)),stream_relay::direction(session,stream_relay::download(session,incoming)));}
                    catch(...){fail();throw;}
                    session.end_traffic();
                    if(session.closed){fail();co_return;}auto reusable=incoming.stream.finish();if(!reusable){fail();co_return;}
                    reader.emplace(std::move(reusable->first));writer.emplace(std::move(reusable->second));
                    session.target.close();session.tunnel={};
#ifdef NEXUS_ENABLE_FAKEIP
                    session.fakeip_target.reset();
#endif
                    session.touched=Clock::now();auto next=co_await snell::receive_record(socket,*reader,Clock::now()+300s);
                    if(!next||next->empty()||session.closed){fail();co_return;}
                    struct ErasePlain {snell::Bytes& bytes;~ErasePlain(){crypto::cleanse(bytes);}} erase_plain{*next};
                    auto parsed=snell::parse_request(*next);if(!parsed){fail();co_return;}
                    struct EraseIdentity {snell::Request& request;~EraseIdentity(){crypto::cleanse(request.client_id);}} erase_identity{parsed->request};
                    if(!profile.owner.accepts(parsed->request)){fail();co_return;}
                    early.assign(next->begin()+parsed->consumed,next->end());crypto::cleanse(parsed->request.client_id);parsed->request.client_id.clear();request=std::move(parsed->request);
                    session.started=Clock::now();session.handshake_deadline=session.started+10s;session.relaying=false;deadline=session.handshake_deadline;
                    continue;
                }
                if(request.command==6){
                    std::optional<snell::Packet> pending;if(!early.empty()){auto p=snell::parse_packet(early,true);if(!p){fail();co_return;}pending=std::move(*p);}
                    if(!writer){auto initial=co_await snell::server_reply(socket,profile.owner.psk(),deadline);if(!initial||session.closed){fail();co_return;}writer.emplace(std::move(*initial));}
                    else {snell::Bytes ack{0};if(!co_await snell::send_record(socket,*writer,ack,{},deadline)||session.closed){fail();co_return;}}
                    PacketBridge incoming(socket,std::move(*reader),std::move(*writer),std::move(pending));session.relaying=true;session.touched=Clock::now();
                    session.begin_traffic(TrafficProtocol::snell_udp,0);
                    session.select_traffic_path(ConnectPath::datagrams);
                    auto resolver=[&](std::string name,std::uint16_t port,Clock::time_point limit){return resolve_udp_domain(session,context,std::move(name),port,limit);};
                    net::stream_datagrams::Server state(session,context,incoming,policy,resolver,net::DatagramFraming{},net::ProxyAddress{},source_endpoint(session,policy));
                    try {(void)co_await capy::when_all(net::stream_datagrams::tasks(state));}
                    catch(...){fail();state.cancel();throw;}fail();co_return;
                }
                fail();co_return;
            }
        }
    }
    auto make_snell_inbound_factory(std::string_view psk,std::optional<std::string_view> user,std::uint32_t window,std::shared_ptr<SnellReplayRegistry> registry,bool http_obfs)->std::expected<InboundFactory,std::string> {
        if(!window||window>86400)return std::unexpected("invalid Snell replay window");
        auto credential=snell::load_credential(psk,user);if(!credential)return std::unexpected(credential.error());
        if(!registry)return std::unexpected("Snell replay registry is required");
        auto replay=registry->acquire(credential->psk(),window);if(!replay)return std::unexpected(replay.error());
        auto profile=std::make_unique<Profile>(std::move(*credential),window,std::move(*replay),http_obfs);
        return InboundFactory{[profile=std::move(profile)](Session& session,corosio::io_context& context,rules::RouteMatcher const& policy){return serve(session,context,policy,*profile);}};
    }
}
