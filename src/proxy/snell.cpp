module proxy;
import std;
import proxy.v4;
import snell.record;
import snell.cipher;
import snell.owner;
import snell.client_owner;
import snell.client_stream;
import snell.client_pool;
import snell.client_start;
import snell.async_record;
import snell.packet;
import snell.async_packet;
import snell.credential_file;
import snell.http_obfs;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
    namespace {
        template<int> struct SnellWorker;
        struct SnellProfile {
            std::string host;std::uint16_t port;snell::ClientOwner owner;std::optional<std::size_t> bootstrap;
            std::uint32_t timeout;TcpSocketOptions options;bool http_obfs;std::string obfs_host,obfs_uri;
            std::mutex mutex;std::array<std::unique_ptr<SnellWorker<0>>,17> physical;
            std::array<std::unique_ptr<SnellWorker<1>>,17> layered;std::array<std::unique_ptr<SnellWorker<2>>,17> fast;
            SnellProfile(std::string_view h,std::uint16_t p,snell::Credential credential,std::optional<std::size_t> b,std::uint32_t t,TcpSocketOptions o,bool obfs,std::string_view oh,std::string_view ou);
            ~SnellProfile();
        };
        struct SnellLower {
            pro::proxy<TunnelFacade>& lower;
            auto read(std::span<std::uint8_t> data){return lower->read(data);}
            auto send(std::span<std::uint8_t const> data){return lower->send(data);}
            auto close_output(){return lower->close_output();}
            auto cancel() noexcept ->void {if(lower)lower->cancel();}
        };
        template<class Socket> class SnellRelay {
            Session& session_;Socket& socket_;SnellProfile const& profile_;bool local_;std::optional<snell::ClientStream<Socket>> stream_;
            using RecordStream=snell::AsyncRecord<Socket,snell::Cipher>;
            std::optional<RecordStream> packet_stream_;std::optional<snell::AsyncPacket<RecordStream>> packets_;
            net::DatagramDecoder packet_input_{net::DatagramFraming{}};std::vector<std::uint8_t> packet_output_;std::size_t packet_offset_=0;
            bool upload_started_=false,download_started_=false;
        public:
            SnellRelay(Session& session,Socket& socket,SnellProfile const& profile,bool local):session_(session),socket_(socket),profile_(profile),local_(local){}
            auto cancel() noexcept ->void {if(stream_)stream_->cancel();else if(packets_)packets_->cancel();else socket_.cancel();}
            auto start(nex::corosio::endpoint destination,Clock::time_point deadline,std::string_view domain={})->nex::capy::task<TunnelConnectResult> {
                if((domain.empty() && !valid_destination(destination))||Clock::now()>=deadline)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                snell::Request request{5,{},domain.empty() ? destination.address().to_string() : std::string(domain),destination.port()};
                auto writer=co_await profile_.owner.start(socket_,std::move(request),{},deadline);
                if(session_.closed){socket_.cancel();co_return TunnelConnectResult::failed;}
                if(!writer)co_return writer.error()==snell::IoError::timeout?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                stream_.emplace(socket_,profile_.owner,std::move(*writer));co_return TunnelConnectResult::connected;
            }
            auto start_packets(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult> {
                auto connected=co_await profile_.owner.connect(socket_,snell::Request{6,{},"",0},{},deadline);
                if(session_.closed){socket_.cancel();co_return TunnelConnectResult::failed;}
                if(!connected){auto const& e=connected.error();co_return std::holds_alternative<snell::IoError>(e)&&std::get<snell::IoError>(e)==snell::IoError::timeout?TunnelConnectResult::timeout:TunnelConnectResult::failed;}
                if(!connected->early.empty()){socket_.cancel();co_return TunnelConnectResult::failed;}
                packet_stream_.emplace(socket_,std::move(connected->reader),std::move(connected->writer));packets_.emplace(*packet_stream_,true);co_return TunnelConnectResult::connected;
            }
            auto send(std::span<std::uint8_t const> data)->nex::capy::task<bool>{
                if(packets_){auto fed=packet_input_.feed(data);if(fed.status!=net::DatagramStatus::accepted||fed.consumed!=data.size()){cancel();co_return false;}
                    auto p=packet_input_.packet();if(!p){cancel();co_return false;}auto const& a=p->destination;
                    snell::AddressKind kind=a.family==net::ProxyAddressFamily::ipv4?snell::AddressKind::ipv4:a.family==net::ProxyAddressFamily::ipv6?snell::AddressKind::ipv6:snell::AddressKind::domain;
                    snell::Packet packet{{kind,snell::Bytes(a.bytes.begin(),a.bytes.begin()+a.length),a.port},snell::Bytes(p->payload.begin(),p->payload.end())};
                    auto sent=co_await packets_->send(packet,{},Clock::now()+std::chrono::seconds(300));(void)packet_input_.consume();if(sent)session_.touched=Clock::now();co_return bool(sent);}
                if(!stream_)co_return false;auto ok=co_await stream_->send(data,Clock::now()+std::chrono::seconds(300));if(ok)session_.touched=Clock::now();co_return ok;}
            auto read(std::span<std::uint8_t> data)->nex::capy::task<std::expected<std::size_t,std::string>> {
                if(packets_){if(data.empty())co_return std::unexpected("empty Snell packet output buffer");
                    if(packet_offset_==packet_output_.size()){auto packet=co_await packets_->receive(Clock::now()+std::chrono::seconds(300));if(!packet)co_return std::unexpected("Snell packet read failed");
                        net::ProxyAddress a;a.family=packet->address.kind==snell::AddressKind::ipv4?net::ProxyAddressFamily::ipv4:net::ProxyAddressFamily::ipv6;
                        if(packet->address.kind==snell::AddressKind::domain||packet->address.value.size()>a.bytes.size()){cancel();co_return std::unexpected("invalid Snell packet source");}
                        a.length=packet->address.value.size();a.port=packet->address.port;std::ranges::copy(packet->address.value,a.bytes.begin());
                        auto framed=net::encode_datagram({},a,packet->payload);if(!framed){cancel();co_return std::unexpected("invalid Snell packet");}packet_output_=std::move(*framed);packet_offset_=0;}
                    auto n=std::min(data.size(),packet_output_.size()-packet_offset_);std::ranges::copy(std::span(packet_output_).subspan(packet_offset_,n),data.begin());packet_offset_+=n;session_.touched=Clock::now();co_return n;}
                if(!stream_)co_return std::unexpected("Snell stream not started");auto value=co_await stream_->read(data,Clock::now()+std::chrono::seconds(300));
                if(!value){auto const& remote=stream_->reply_error();if(remote && std::holds_alternative<snell::RemoteError>(*remote)){auto const& error=std::get<snell::RemoteError>(*remote);co_return std::unexpected("Snell remote error "+std::to_string(error.code)+": "+error.message);}co_return std::unexpected("Snell stream read failed");}
                if(*value)session_.touched=Clock::now();co_return *value;
            }
            auto close_output()->nex::capy::task<bool>{if(!stream_)co_return false;co_return co_await stream_->close_output(Clock::now()+std::chrono::seconds(300));}
            auto upload()->nex::capy::task<bool>{if(upload_started_||!stream_)co_return false;upload_started_=true;co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*this,[this]{session_.touched=Clock::now();},local_,session_.traffic_delivery()});}
            auto download()->nex::capy::task<bool>{if(download_started_||!stream_)co_return false;download_started_=true;co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client,*this,[this]{session_.touched=Clock::now();},local_, session_.traffic_delivery()});}
        };
        class SnellDirect {
            Session& session_;nex::corosio::io_context& context_;SnellProfile const& profile_;DnsSlot dns_;nex::corosio::tcp_socket socket_;snell::HttpObfs<nex::corosio::tcp_socket> obfs_;SnellRelay<decltype(obfs_)> relay_;
            std::stop_source stop_;TcpSocketOptions options_;bool starting_=false,connected_=false;
        public:
            SnellDirect(Session& s,nex::corosio::io_context& c,SnellProfile const& p,bool local,TcpSocketOptions options)
              :session_(s),context_(c),profile_(p),socket_(c),obfs_(socket_,p.http_obfs,false,p.obfs_host,p.obfs_uri),relay_(s,obfs_,p,local),options_(options){}
            auto cancel() noexcept ->void {stop_.request_stop();dns_.cancel();relay_.cancel();}
            auto connect(nex::corosio::endpoint target)->nex::capy::task<TunnelConnectResult>{return connect_until(target,session_.started+std::chrono::milliseconds(profile_.timeout));}
            auto connect_until(nex::corosio::endpoint target,Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start(target,deadline,false);}
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return start(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),deadline,false,domain);
            }
            auto start(nex::corosio::endpoint target,Clock::time_point deadline,bool packets,std::string_view domain={})->nex::capy::task<TunnelConnectResult> {
                if(starting_||connected_||stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;starting_=true;
                struct Guard{SnellDirect& self;bool done=false;~Guard(){self.starting_=false;if(!done)self.cancel();}} guard{*this};
                auto resolved=profile_.bootstrap ? co_await resolve_bootstrap_owned(session_,context_,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline)
                    : co_await resolve_local_owned(session_,context_,dns_,profile_.host,profile_.port,deadline);
                if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(!resolved||resolved->empty()||resolved->size()>64)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::retryable;
                for(auto endpoint:*resolved){if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;if(!valid_destination(endpoint))continue;
                    if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;
                    if(net::prepare_tcp_socket(socket_,endpoint,options_,deadline))co_return TunnelConnectResult::failed;
                    auto [error]=co_await nex::corosio::timeout(socket_.connect(endpoint),deadline);
                    if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                    if(error){socket_.close();if(nex::capy::is_timeout(error)||Clock::now()>=deadline)co_return TunnelConnectResult::timeout;continue;}
                    TunnelConnectResult result;if(packets)result=co_await relay_.start_packets(deadline);else result=co_await relay_.start(target,deadline,domain);if(result!=TunnelConnectResult::connected)co_return result;
                    connected_=true;guard.done=true;co_return result;
                }co_return TunnelConnectResult::retryable;
            }
            auto send(std::span<std::uint8_t const> b){return relay_.send(b);}auto read(std::span<std::uint8_t> b){return relay_.read(b);}auto close_output(){return relay_.close_output();}
            auto upload(){return relay_.upload();}auto download(){return relay_.download();}
            auto packet_transport() const noexcept ->net::PacketTransport{return {net::PacketTransportKind::framed,{},false};}
            auto connect_packets(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start({},deadline,true);}
            auto has_uot() const noexcept ->bool{return false;}auto has_xudp() const noexcept ->bool{return false;}
            auto connect_uot()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_uot_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_xudp()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_xudp_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
        };
        class SnellFast {
            using Socket=net::ByteStreamAdapter<net::FastOpenStream>;
            Session& session_;nex::corosio::io_context& context_;SnellProfile const& profile_;DnsSlot dns_;TcpSocketOptions options_;
            std::unique_ptr<net::FastOpenStream> stream_;std::unique_ptr<Socket> socket_;std::unique_ptr<snell::HttpObfs<Socket>> obfs_;std::unique_ptr<SnellRelay<snell::HttpObfs<Socket>>> relay_;
            std::stop_source stop_;bool local_,starting_=false,connected_=false;
        public:
            SnellFast(Session& s,nex::corosio::io_context& c,SnellProfile const& p,bool local,TcpSocketOptions options)
                :session_(s),context_(c),profile_(p),options_(options),local_(local){}
            auto cancel() noexcept ->void {stop_.request_stop();dns_.cancel();if(relay_)relay_->cancel();if(stream_)stream_->cancel();}
            auto connect(nex::corosio::endpoint target)->nex::capy::task<TunnelConnectResult>{return connect_until(target,session_.started+std::chrono::milliseconds(profile_.timeout));}
            auto connect_until(nex::corosio::endpoint target,Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start(target,deadline,false);}
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return start(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),deadline,false,domain);
            }
            auto start(nex::corosio::endpoint target,Clock::time_point deadline,bool packets,std::string_view domain={})->nex::capy::task<TunnelConnectResult> {
                if(starting_||connected_||stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;starting_=true;
                struct Guard{SnellFast& self;bool done=false;~Guard(){self.starting_=false;if(!done)self.cancel();}} guard{*this};
                auto resolved=profile_.bootstrap ? co_await resolve_bootstrap_owned(session_,context_,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline)
                    : co_await resolve_local_owned(session_,context_,dns_,profile_.host,profile_.port,deadline);
                if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(!resolved||resolved->empty()||resolved->size()>64)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::retryable;
                stream_=std::make_unique<net::FastOpenStream>(context_,std::move(*resolved),deadline,options_);
                socket_=std::make_unique<Socket>(*stream_);obfs_=std::make_unique<snell::HttpObfs<Socket>>(*socket_,profile_.http_obfs,false,profile_.obfs_host,profile_.obfs_uri);relay_=std::make_unique<SnellRelay<snell::HttpObfs<Socket>>>(session_,*obfs_,profile_,local_);
                TunnelConnectResult result;if(packets)result=co_await relay_->start_packets(deadline);else result=co_await relay_->start(target,deadline,domain);
                if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(result!=TunnelConnectResult::connected)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:result;
                connected_=true;guard.done=true;co_return result;
            }
            auto send(std::span<std::uint8_t const> b)->nex::capy::task<bool>{if(!relay_)co_return false;co_return co_await relay_->send(b);}
            auto read(std::span<std::uint8_t> b)->nex::capy::task<std::expected<std::size_t,std::string>>{if(!relay_)co_return std::unexpected("Snell stream not started");co_return co_await relay_->read(b);}
            auto close_output()->nex::capy::task<bool>{if(!relay_)co_return false;co_return co_await relay_->close_output();}
            auto upload()->nex::capy::task<bool>{if(!relay_)co_return false;co_return co_await relay_->upload();}
            auto download()->nex::capy::task<bool>{if(!relay_)co_return false;co_return co_await relay_->download();}
            auto packet_transport() const noexcept ->net::PacketTransport{return {net::PacketTransportKind::framed,{},false};}
            auto connect_packets(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start({},deadline,true);}
            auto has_uot() const noexcept ->bool{return false;}auto has_xudp() const noexcept ->bool{return false;}
            auto connect_uot()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_uot_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_xudp()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_xudp_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
        };
        class SnellLayer {
            Session& session_;SnellProfile const& profile_;LowerConnector lower_;SnellLower stream_;net::ByteStreamAdapter<SnellLower> socket_;snell::HttpObfs<decltype(socket_)> obfs_;SnellRelay<decltype(obfs_)> relay_;
            std::stop_source stop_;bool starting_=false,connected_=false;
        public:
            SnellLayer(Session& s,nex::corosio::io_context& c,TunnelFactory const& detour,SnellProfile const& p,bool local)
              :session_(s),profile_(p),lower_{{},&c,&detour,p.host,p.port,p.bootstrap},stream_{lower_.tunnel},socket_(stream_),obfs_(socket_,p.http_obfs,false,p.obfs_host,p.obfs_uri),relay_(s,obfs_,p,local){}
            auto cancel() noexcept ->void {stop_.request_stop();relay_.cancel();lower_.cancel();}
            auto connect(nex::corosio::endpoint target)->nex::capy::task<TunnelConnectResult>{return connect_until(target,session_.started+std::chrono::milliseconds(profile_.timeout));}
            auto connect_until(nex::corosio::endpoint target,Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start(target,deadline,false);}
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return start(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),deadline,false,domain);
            }
            auto start(nex::corosio::endpoint target,Clock::time_point deadline,bool packets,std::string_view domain={})->nex::capy::task<TunnelConnectResult>{
                if(starting_||connected_||stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;starting_=true;
                struct Guard{SnellLayer& self;bool done=false;~Guard(){self.starting_=false;if(!done)self.cancel();}} guard{*this};
                LowerConnector::Candidates candidates;auto lower=co_await lower_.connect(session_,deadline,candidates);if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;if(lower!=TunnelConnectResult::connected)co_return lower;
                TunnelConnectResult result;if(packets)result=co_await relay_.start_packets(deadline);else result=co_await relay_.start(target,deadline,domain);if(result!=TunnelConnectResult::connected)co_return result;
                connected_=true;guard.done=true;co_return result;
            }
            auto send(std::span<std::uint8_t const> b){return relay_.send(b);}auto read(std::span<std::uint8_t> b){return relay_.read(b);}auto close_output(){return relay_.close_output();}
            auto upload(){return relay_.upload();}auto download(){return relay_.download();}
            auto packet_transport() const noexcept ->net::PacketTransport{return {net::PacketTransportKind::framed,{},false};}
            auto connect_packets(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult>{return start({},deadline,true);}
            auto has_uot() const noexcept ->bool{return false;}auto has_xudp() const noexcept ->bool{return false;}
            auto connect_uot()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_uot_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_xudp()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_xudp_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
        };
        // Each pooled physical connection owns its resolver, lower transport,
        // obfs adapter and protocol state independently of a business session.
        template<int Mode> class SnellNode {
            using FastSocket=net::ByteStreamAdapter<net::FastOpenStream>;
            using LayerSocket=net::ByteStreamAdapter<SnellLower>;
            using Socket=std::conditional_t<Mode==0,nex::corosio::tcp_socket,std::conditional_t<Mode==1,LayerSocket,FastSocket>>;
            using Obfs=snell::HttpObfs<Socket>;
            using Stream=snell::ClientStream<Obfs>;
            Session state_;OutboundContext env_;SnellProfile const& profile_;TcpSocketOptions options_;TunnelFactory const* detour_;
            DnsSlot dns_;std::unique_ptr<LowerConnector> lower_;std::unique_ptr<SnellLower> lower_stream_;
            std::unique_ptr<net::FastOpenStream> fast_;std::unique_ptr<Socket> socket_;std::unique_ptr<Obfs> obfs_;
            std::unique_ptr<Stream> stream_;std::optional<snell::ClientReuse<Obfs>> reusable_;
            bool stopping_=false,open_=false;
        public:
            SnellNode(OutboundContext const& env,SnellProfile const& profile,TcpSocketOptions options,TunnelFactory const* detour)
              :state_(env.context),env_(env),profile_(profile),options_(options),detour_(detour){
                state_.dns=env.dns;state_.local_dns=env.local_dns;state_.tunnel_factories=env.factories;state_.direct_tcp_options=env.direct_options;
            }
            ~SnellNode(){cancel();}
            [[nodiscard]] auto stopping() const noexcept ->bool {return stopping_;}
            [[nodiscard]] auto reusable() const noexcept ->bool {return !stopping_&&open_&&reusable_.has_value()&&!stream_;}
            auto cancel() noexcept ->void {
                if(stopping_)return;stopping_=true;dns_.cancel();
                if(stream_)stream_->cancel();reusable_.reset();
                if(obfs_)obfs_->cancel();if(lower_)lower_->cancel();if(fast_)fast_->cancel();state_.close();
            }
            auto connect(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult> {
                if(stopping_||Clock::now()>=deadline)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                if(open_)co_return TunnelConnectResult::connected;
                if constexpr(Mode==1){
                    if(!detour_)co_return TunnelConnectResult::failed;
                    lower_=std::unique_ptr<LowerConnector>(new LowerConnector{{},&env_.context,detour_,profile_.host,profile_.port,profile_.bootstrap});
                    LowerConnector::Candidates candidates;auto result=co_await lower_->connect(state_,deadline,candidates);
                    if(stopping_||state_.closed)co_return TunnelConnectResult::failed;
                    if(result!=TunnelConnectResult::connected)co_return result;
                    lower_stream_=std::make_unique<SnellLower>(SnellLower{lower_->tunnel});socket_=std::make_unique<Socket>(*lower_stream_);
                }else{
                    auto resolved=profile_.bootstrap ? co_await resolve_bootstrap_owned(state_,env_.context,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline)
                        : co_await resolve_local_owned(state_,env_.context,dns_,profile_.host,profile_.port,deadline);
                    if(stopping_||state_.closed)co_return TunnelConnectResult::failed;
                    if(!resolved||resolved->empty()||resolved->size()>64)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::retryable;
                    if constexpr(Mode==2){
                        fast_=std::make_unique<net::FastOpenStream>(env_.context,std::move(*resolved),deadline,options_);socket_=std::make_unique<Socket>(*fast_);
                    }else{
                        socket_=std::make_unique<Socket>(env_.context);bool connected=false;
                        for(auto endpoint:*resolved){if(stopping_||state_.closed)co_return TunnelConnectResult::failed;if(!valid_destination(endpoint))continue;
                            if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;
                            if(net::prepare_tcp_socket(*socket_,endpoint,options_,deadline))co_return TunnelConnectResult::failed;
                            auto [error]=co_await nex::corosio::timeout(socket_->connect(endpoint),deadline);
                            if(stopping_||state_.closed)co_return TunnelConnectResult::failed;
                            if(error){socket_->close();if(nex::capy::is_timeout(error)||Clock::now()>=deadline)co_return TunnelConnectResult::timeout;continue;}
                            connected=true;break;
                        }
                        if(!connected)co_return TunnelConnectResult::retryable;
                    }
                }
                obfs_=std::make_unique<Obfs>(*socket_,profile_.http_obfs,false,profile_.obfs_host,profile_.obfs_uri);open_=true;
                co_return TunnelConnectResult::connected;
            }
            auto start(nex::corosio::endpoint target,Clock::time_point deadline,std::string_view domain={})->nex::capy::task<TunnelConnectResult> {
                if(stopping_||stream_||(domain.empty() && !valid_destination(target)))co_return TunnelConnectResult::failed;
                auto connected=co_await connect(deadline);if(connected!=TunnelConnectResult::connected)co_return connected;
                snell::Request request{5,{},domain.empty() ? target.address().to_string() : std::string(domain),target.port()};
                if(reusable_){
                    auto resumed=co_await profile_.owner.resume_start(*obfs_,std::move(*reusable_),std::move(request),deadline);reusable_.reset();
                    if(stopping_)co_return TunnelConnectResult::failed;
                    if(!resumed)co_return resumed.error()==snell::IoError::timeout?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                    stream_=Stream::resume(*obfs_,profile_.owner,std::move(*resumed));if(!stream_)co_return TunnelConnectResult::failed;
                }else{
                    auto writer=co_await profile_.owner.start(*obfs_,std::move(request),{},deadline);
                    if(stopping_)co_return TunnelConnectResult::failed;
                    if(!writer)co_return writer.error()==snell::IoError::timeout?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                    stream_=std::make_unique<Stream>(*obfs_,profile_.owner,std::move(*writer));
                }
                co_return TunnelConnectResult::connected;
            }
            auto finish() ->bool {
                if(stopping_||!stream_)return false;auto completed=stream_->finish();if(!completed)return false;
                stream_.reset();reusable_.emplace(std::move(*completed));return true;
            }
            auto stream() noexcept ->Stream* {return stream_.get();}
        };
        template<int Mode> struct SnellWorker {
            OutboundContext env;SnellProfile const& profile;TcpSocketOptions options;TunnelFactory const* detour;
            snell::ClientPool<SnellNode<Mode>> pool;
            SnellWorker(OutboundContext const& e,SnellProfile const& p,TcpSocketOptions o,TunnelFactory const* d)
              :env(e),profile(p),options(o),detour(d),pool(e.context){}
            auto create()->std::unique_ptr<SnellNode<Mode>> {return std::make_unique<SnellNode<Mode>>(env,profile,options,detour);}
        };
        SnellProfile::SnellProfile(std::string_view h,std::uint16_t p,snell::Credential credential,std::optional<std::size_t> b,std::uint32_t t,TcpSocketOptions o,bool obfs,std::string_view oh,std::string_view ou)
            :host(h),port(p),owner(std::move(credential)),bootstrap(b),timeout(t),options(o),http_obfs(obfs),obfs_host(oh),obfs_uri(ou){}
        SnellProfile::~SnellProfile()=default;
        template<int Mode> auto snell_slots(SnellProfile& profile) noexcept ->auto& {
            if constexpr(Mode==0)return profile.physical;else if constexpr(Mode==1)return profile.layered;else return profile.fast;
        }
        template<int Mode> auto snell_find(SnellProfile& profile,nex::corosio::io_context& context) noexcept ->SnellWorker<Mode>* {
            for(auto const& worker:snell_slots<Mode>(profile))if(worker&&&worker->env.context==&context)return worker.get();return nullptr;
        }
        template<int Mode> auto snell_initialize(SnellProfile& profile,OutboundContext const& env,TunnelFactory const* detour,bool direct)->bool {
            std::lock_guard lock(profile.mutex);if(snell_find<Mode>(profile,env.context)||(direct&&!env.direct_options))return false;
            auto& slots=snell_slots<Mode>(profile);auto slot=std::ranges::find_if(slots,[](auto const& value){return !value;});if(slot==slots.end())return false;
            auto worker=std::make_unique<SnellWorker<Mode>>(env,profile,direct?*env.direct_options:profile.options,detour);worker->pool.start();*slot=std::move(worker);return true;
        }
        template<int Mode> auto snell_stop(SnellProfile& profile,nex::corosio::io_context& context) noexcept ->void {
            SnellWorker<Mode>* worker=nullptr;{std::lock_guard lock(profile.mutex);worker=snell_find<Mode>(profile,context);}if(worker)worker->pool.stop();
        }
        template<int Mode> auto snell_finish(SnellProfile& profile,nex::corosio::io_context& context) noexcept ->void {
            std::lock_guard lock(profile.mutex);for(auto& worker:snell_slots<Mode>(profile))if(worker&&&worker->env.context==&context){if(!worker->pool.drained())std::terminate();worker.reset();return;}
        }
        template<int Mode> class SnellPooledTunnel {
            using Worker=SnellWorker<Mode>;using Node=SnellNode<Mode>;using Pool=snell::ClientPool<Node>;
            Session& session_;Worker& worker_;bool local_,starting_=false,ready_=false,finished_=false,upload_started_=false,download_started_=false;
            std::stop_source stop_;std::optional<typename Pool::Lease> lease_;pro::proxy<TunnelFacade> legacy_;
        public:
            SnellPooledTunnel(Session& session,Worker& worker,bool local):session_(session),worker_(worker),local_(local){}
            ~SnellPooledTunnel(){cancel();}
            auto cancel() noexcept ->void {
                stop_.request_stop();if(legacy_)legacy_->cancel();
                if(lease_&&!finished_){auto node=lease_->hold();finished_=node->finish();if(!finished_)node->cancel();}
            }
            auto connect(nex::corosio::endpoint endpoint)->nex::capy::task<TunnelConnectResult>{return connect_until(endpoint,session_.started+std::chrono::milliseconds(worker_.profile.timeout));}
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return connect_until(nex::corosio::endpoint(nex::corosio::ipv4_address{},port),deadline,domain);
            }
            auto connect_until(nex::corosio::endpoint endpoint,Clock::time_point deadline,std::string_view domain={})
                -> nex::capy::task<TunnelConnectResult> {
                if(starting_||ready_||legacy_||stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;starting_=true;
                struct Guard{SnellPooledTunnel& self;bool done=false;~Guard(){self.starting_=false;if(!done)self.cancel();}} guard{*this};
                auto lease=worker_.pool.take([this]{return worker_.create();});if(!lease)co_return TunnelConnectResult::failed;
                lease_.emplace(std::move(*lease));auto result=co_await lease_->node().start(endpoint,deadline,domain);
                if(stop_.stop_requested()||session_.closed||lease_->node().stopping())co_return TunnelConnectResult::failed;
                if(result!=TunnelConnectResult::connected)co_return result;ready_=true;guard.done=true;co_return result;
            }
            auto connect_packets(Clock::time_point deadline)->nex::capy::task<TunnelConnectResult> {
                if(starting_||ready_||legacy_||stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                starting_=true;struct Guard{SnellPooledTunnel& self;bool done=false;~Guard(){self.starting_=false;if(!done)self.cancel();}} guard{*this};
                if constexpr(Mode==0)legacy_=pro::make_proxy<TunnelFacade,SnellDirect>(session_,worker_.env.context,worker_.profile,local_,worker_.options);
                else if constexpr(Mode==1)legacy_=pro::make_proxy<TunnelFacade,SnellLayer>(session_,worker_.env.context,*worker_.detour,worker_.profile,local_);
                else legacy_=pro::make_proxy<TunnelFacade,SnellFast>(session_,worker_.env.context,worker_.profile,local_,worker_.options);
                auto result=co_await legacy_->connect_packets(deadline);if(stop_.stop_requested()||session_.closed)co_return TunnelConnectResult::failed;
                if(result==TunnelConnectResult::connected){ready_=true;guard.done=true;}co_return result;
            }
            auto send(std::span<std::uint8_t const> data)->nex::capy::task<bool> {
                if(legacy_)co_return co_await legacy_->send(data);if(!ready_||stop_.stop_requested())co_return false;
                auto result=co_await lease_->node().stream()->send(data,Clock::now()+std::chrono::seconds(300));if(result)session_.touched=Clock::now();co_return result;
            }
            auto read(std::span<std::uint8_t> data)->nex::capy::task<std::expected<std::size_t,std::string>> {
                if(legacy_)co_return co_await legacy_->read(data);if(!ready_||stop_.stop_requested())co_return std::unexpected("Snell stream closed");
                auto* stream=lease_->node().stream();auto result=co_await stream->read(data,Clock::now()+std::chrono::seconds(300));
                if(!result){auto const& remote=stream->reply_error();if(remote&&std::holds_alternative<snell::RemoteError>(*remote)){auto const& error=std::get<snell::RemoteError>(*remote);co_return std::unexpected("Snell remote error "+std::to_string(error.code)+": "+error.message);}co_return std::unexpected("Snell stream read failed");}
                if(*result)session_.touched=Clock::now();co_return *result;
            }
            auto close_output()->nex::capy::task<bool>{if(legacy_)co_return co_await legacy_->close_output();if(!ready_||stop_.stop_requested())co_return false;co_return co_await lease_->node().stream()->close_output(Clock::now()+std::chrono::seconds(300));}
            auto upload()->nex::capy::task<bool>{if(legacy_)co_return co_await legacy_->upload();if(!ready_||upload_started_)co_return false;upload_started_=true;co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*this,[this]{session_.touched=Clock::now();},local_,session_.traffic_delivery()});}
            auto download()->nex::capy::task<bool>{if(legacy_)co_return co_await legacy_->download();if(!ready_||download_started_)co_return false;download_started_=true;co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client,*this,[this]{session_.touched=Clock::now();},local_, session_.traffic_delivery()});}
            auto packet_transport() const noexcept ->net::PacketTransport{return {net::PacketTransportKind::framed,{},false};}
            auto has_uot() const noexcept ->bool{return false;}auto has_xudp() const noexcept ->bool{return false;}
            auto connect_uot()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_uot_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_xudp()->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}auto connect_xudp_until(Clock::time_point)->nex::capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
        };
    }
    auto make_snell_factory(std::string_view host,std::uint16_t port,std::string_view psk,std::optional<std::string_view> user,
        std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,bool fast_open,bool http_obfs,std::string_view obfs_host,std::string_view obfs_uri,bool reuse)->std::expected<TunnelFactory,std::string> {
        if(host.empty()||host.size()>253||!port||!timeout||timeout>3600000||!options.valid())return std::unexpected("invalid Snell dial options");
        auto visible=[](std::string_view value){return std::ranges::all_of(value,[](unsigned char ch){return ch>32&&ch<127;});};
        if((!http_obfs&&(!obfs_host.empty()||!obfs_uri.empty()))||obfs_host.size()>253||!visible(obfs_host)||obfs_uri.size()>1024||(!obfs_uri.empty()&&obfs_uri.front()!='/')||!visible(obfs_uri))return std::unexpected("invalid Snell HTTP obfs options");
        auto credential=snell::load_credential(psk,user);if(!credential)return std::unexpected(credential.error());
        auto profile=std::make_unique<SnellProfile>(host,port,std::move(*credential),bootstrap,timeout,options,http_obfs,obfs_host,obfs_uri);auto* borrowed=profile.get();
        TunnelFactory factory{[profile=std::move(profile),fast_open,reuse](Session& s,nex::corosio::io_context& c,bool local,TcpSocketOptions const* inherited) ->pro::proxy<TunnelFacade>{
            if(reuse){std::lock_guard lock(profile->mutex);
                if(auto worker=snell_find<2>(*profile,c))return pro::make_proxy<TunnelFacade,SnellPooledTunnel<2>>(s,*worker,local);
                if(auto worker=snell_find<0>(*profile,c))return pro::make_proxy<TunnelFacade,SnellPooledTunnel<0>>(s,*worker,local);
                return {};}
            if(inherited ? inherited->tcp_fast_open.value_or(false) : fast_open)return pro::make_proxy<TunnelFacade,SnellFast>(s,c,*profile,local,inherited?*inherited:profile->options);
            return pro::make_proxy<TunnelFacade,SnellDirect>(s,c,*profile,local,inherited?*inherited:profile->options);},timeout,
            [borrowed,reuse](Session& s,nex::corosio::io_context& c,TunnelFactory const& detour,bool local)->pro::proxy<TunnelFacade>{
                if(reuse){std::lock_guard lock(borrowed->mutex);auto worker=snell_find<1>(*borrowed,c);
                    return worker?pro::make_proxy<TunnelFacade,SnellPooledTunnel<1>>(s,*worker,local):pro::proxy<TunnelFacade>{};}
                return pro::make_proxy<TunnelFacade,SnellLayer>(s,c,detour,*borrowed,local);},std::nullopt,options.configured()||fast_open};
        if(reuse){
            factory.start_context=[borrowed,fast_open](OutboundContext const& env,TunnelFactory const* detour,bool direct){
                auto fast=direct&&env.direct_options?env.direct_options->tcp_fast_open.value_or(false):fast_open;
                return detour?snell_initialize<1>(*borrowed,env,detour,direct):fast?snell_initialize<2>(*borrowed,env,nullptr,direct):snell_initialize<0>(*borrowed,env,nullptr,direct);};
            factory.stop_context=[borrowed](nex::corosio::io_context& c) noexcept {snell_stop<0>(*borrowed,c);snell_stop<1>(*borrowed,c);snell_stop<2>(*borrowed,c);};
            factory.quiesced_context=[borrowed](nex::corosio::io_context& c) noexcept {
                std::lock_guard lock(borrowed->mutex);auto a=snell_find<0>(*borrowed,c);auto b=snell_find<1>(*borrowed,c);auto d=snell_find<2>(*borrowed,c);
                return (!a||a->pool.drained())&&(!b||b->pool.drained())&&(!d||d->pool.drained());};
            factory.finish_context=[borrowed](nex::corosio::io_context& c) noexcept {snell_finish<0>(*borrowed,c);snell_finish<1>(*borrowed,c);snell_finish<2>(*borrowed,c);};
        }
        return factory;
    }
}
