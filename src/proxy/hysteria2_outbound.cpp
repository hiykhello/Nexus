module proxy;
import std;
import proxy.v4;
import hysteria2.client;
import quic.ech_config;
import hysteria2.sessions;
import hysteria2.client_profile;
import hysteria2.tcp_channel;
import hysteria2.transport_options;
import config;
import tls.fingerprint;
import net.stream_relay;
import net.datagram_frame;
import platform.socket_options;
import net.packet_stream_socket;
import http.connect;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace proxy {
#include "quic_ech.hpp"
    namespace {
        namespace h=hysteria2;
        template<bool Layered> struct Worker;
        struct Profile {
            std::string host;
            std::uint16_t port;
            std::optional<std::size_t> bootstrap;
            std::uint32_t timeout;
            std::unique_ptr<h::ClientProfile> client;
            bool udp,lazy_tcp_response;
            TcpSocketOptions options;
            quic_ech::Profile ech;
            std::mutex mutex;
            // Up to 16 stream workers plus one native UDP routing context.
            std::array<std::unique_ptr<Worker<false>>,17> physical;
            std::array<std::unique_ptr<Worker<true>>,17> layered;
            ~Profile();
        };
        struct LowerStream {
            pro::proxy<TunnelFacade> tunnel;
            auto send(std::span<std::uint8_t const> bytes) {return tunnel->send(bytes);}
            auto read(std::span<std::uint8_t> bytes) {return tunnel->read(bytes);}
            auto cancel() noexcept -> void {if(tunnel)tunnel->cancel();}
        };
        template<bool Layered> struct LowerState {
            explicit LowerState(OutboundContext const&) noexcept {}
            auto cancel() noexcept -> void {}
        };
        template<> struct LowerState<true> {
            Session session;
            LowerStream stream;
            explicit LowerState(OutboundContext const& env):session(env.context) {
                session.dns=env.dns;session.local_dns=env.local_dns;
                session.tunnel_factories=env.factories;session.direct_tcp_options=env.direct_options;
            }
            ~LowerState(){cancel();}
            auto cancel() noexcept -> void {stream.cancel();session.close();}
        };
        template<bool Layered> struct Node {
            using Socket=std::conditional_t<Layered,net::PacketStreamSocket<LowerStream>,nex::corosio::udp_socket>;
            using Client=h::BasicClient<Socket>;
            LowerState<Layered> lower;
            Client client;
            OutboundContext env;
            TunnelFactory const* detour;
            bool launched=false,done=false,released=false,shutdown_done=true,stopping=false;
            explicit Node(OutboundContext const& value,Profile const& profile,TunnelFactory const* via)
                :lower(value),client(value.context,*profile.client),env(value),detour(via) {}
            auto start(nex::corosio::endpoint peer, Clock::time_point deadline, quic::EchConfig const* ech,
                platform::SocketBinding const& binding,h::ClientProfile::Tickets* tickets) -> nex::capy::task<TunnelConnectResult> {
                if(stopping || Clock::now()>=deadline)co_return TunnelConnectResult::timeout;
                if constexpr(Layered) {
                    if(!detour)co_return TunnelConnectResult::failed;
                    lower.stream.tunnel=(*detour)(lower.session,env.context,false);
                    if(!lower.stream.tunnel)co_return TunnelConnectResult::failed;
                    auto transport=lower.stream.tunnel->packet_transport();
                    if(transport.kind==net::PacketTransportKind::none)co_return TunnelConnectResult::failed;
                    auto connected=co_await lower.stream.tunnel->connect_packets(net::packet_peer_address(peer),deadline);
                    if(stopping || lower.session.closed)co_return TunnelConnectResult::failed;
                    if(connected!=TunnelConnectResult::connected)co_return connected;
                    if(!client.socket().attach(lower.stream,transport,peer) || !co_await client.socket().prepare(deadline))
                        co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                if(stopping || Clock::now()>=deadline)co_return TunnelConnectResult::timeout;
                std::error_code socket_error;
                if (!client.start(peer,Layered ? nullptr : &binding,ech,deadline,&socket_error,tickets)) {
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    co_return platform::network::retry_interface_error(socket_error) ?
                        TunnelConnectResult::retryable : TunnelConnectResult::failed;
                }
                try {
                    nex::capy::run_async(env.context.get_executor(),[this](auto) noexcept {done=true;},
                        [this](std::exception_ptr) noexcept {client.finish();done=true;})(client.run());
                    launched=true;
                } catch (...) {abort();throw;}
                co_return TunnelConnectResult::connected;
            }
            auto shutdown() -> nex::capy::task<nex::capy::results<>> {
                auto deadline=Clock::now()+std::chrono::milliseconds(250);
                while (!client.shutdown_drained() && !client.shutdown_failed() && Clock::now()<deadline) {
                    auto [error]=co_await nex::corosio::delay(std::chrono::milliseconds(5));
                    if (error) break;
                }
                client.finish();co_return nex::capy::results<>{};
            }
            auto abort() noexcept -> void {stopping=true;client.finish();lower.cancel();}
            auto stop() noexcept -> void {
                if (std::exchange(stopping,true)) return;
                if (!launched || done) {client.finish();lower.cancel();return;}
                client.begin_shutdown();shutdown_done=false;
                try {
                    nex::capy::run_async(env.context.get_executor(),[this](auto) noexcept {shutdown_done=true;},
                        [this](std::exception_ptr) noexcept {client.finish();shutdown_done=true;})(shutdown());
                } catch (...) {client.finish();shutdown_done=true;}
            }
            auto release() noexcept -> void {
                if (std::exchange(released,true)) return;
                stop();client.joined();
            }
        };
        template<bool Layered> struct Worker {
            OutboundContext env;
            Profile const& profile;
            TcpSocketOptions options;
            TunnelFactory const* detour;
            h::ClientProfile::Tickets tickets;
            std::vector<std::unique_ptr<Node<Layered>>> nodes;
            bool stopped=false;
            Worker(OutboundContext const& value,Profile const& source,TcpSocketOptions selected,TunnelFactory const* via)
                :env(value),profile(source),options(std::move(selected)),detour(via) {}
            auto collect() -> void {
                std::erase_if(nodes,[](auto const& node) {
                    return node->released && node->shutdown_done && (!node->launched || (node->done && node->client.drained()));
                });
            }
            auto create() -> Node<Layered>* {
                collect();if(stopped || nodes.size()>=256)return nullptr;
                auto node=std::make_unique<Node<Layered>>(env,profile,detour);auto* result=node.get();
                nodes.push_back(std::move(node));return result;
            }
            auto stop() noexcept -> void {stopped=true;for(auto& node:nodes)node->stop();}
            auto quiesced() const noexcept -> bool {
                return std::ranges::all_of(nodes,[](auto const& node){return node->shutdown_done;});
            }
            auto finish() -> void {collect();if(!nodes.empty())std::terminate();}
        };
        Profile::~Profile()=default;
        template<bool Layered> auto slots(Profile& profile) noexcept -> auto& {
            if constexpr(Layered)return profile.layered;else return profile.physical;
        }
        template<bool Layered> auto find(Profile& profile,nex::corosio::io_context& context) noexcept -> Worker<Layered>* {
            for(auto const& worker:slots<Layered>(profile))if(worker && &worker->env.context==&context)return worker.get();
            return nullptr;
        }
        template<bool Layered> auto initialize(Profile& profile,OutboundContext const& env,TunnelFactory const* detour,bool direct) -> bool {
            std::lock_guard lock(profile.mutex);if(find<Layered>(profile,env.context) || (direct && !env.direct_options))return false;
            auto& entries=slots<Layered>(profile);auto slot=std::ranges::find_if(entries,[](auto const& worker){return !worker;});
            if(slot==entries.end())return false;
            *slot=std::make_unique<Worker<Layered>>(env,profile,direct ? *env.direct_options : profile.options,detour);return true;
        }
        template<bool Layered> auto stop(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            Worker<Layered>* worker=nullptr;{std::lock_guard lock(profile.mutex);worker=find<Layered>(profile,context);}if(worker)worker->stop();
        }
        template<bool Layered> auto finish(Profile& profile,nex::corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for(auto& worker:slots<Layered>(profile))if(worker && &worker->env.context==&context){worker->finish();worker.reset();return;}
        }
        template<bool Layered>
        class Tunnel {
            Session& session_;
            Worker<Layered>& worker_;
            Profile const& profile_;
            DnsSlot dns_;
            Node<Layered>* node_=nullptr;
            std::optional<typename Node<Layered>::Client::Channel> channel_;
            std::optional<h::UdpSessionHandle> udp_;
            std::uint16_t packet_id_=0;
            std::vector<std::uint8_t> reply_;
            std::size_t reply_offset_=0;
            bool relay_local_,ready_=false,canceled_=false;
            auto release() noexcept -> void {
                channel_.reset();
                if (node_ && udp_) (void)node_->client.close_udp(*udp_);
                udp_.reset();
                if (node_) {
                    // Failed candidates must release a configured UDP source
                    // port before the next candidate attempts to bind it.
                    if (!ready_) node_->abort();
                    node_->release();node_=nullptr;
                }
            }
            auto authenticate(nex::corosio::endpoint peer,Clock::time_point deadline,quic::EchConfig const* ech)
                -> nex::capy::task<TunnelConnectResult> {
                auto binding=worker_.options.binding;
                auto selecting=!Layered && binding.network;
                platform::network::InterfaceCandidates candidates;
                if (selecting) candidates=(*binding.network)(peer.is_v6());
                else candidates.indices.push_back(binding.interface_index);
                binding.network.reset();
                for (std::size_t path=0;path<candidates.indices.size();++path) {
                    auto now=Clock::now();
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (now>=deadline) co_return TunnelConnectResult::timeout;
                    auto until=path+1<candidates.indices.size() ?
                        std::min(deadline,now+candidates.fallback_delay) : deadline;
                    binding.interface_index=candidates.indices[path];
                    node_=worker_.create();
                    if (!node_) co_return TunnelConnectResult::failed;
                    auto started=co_await node_->start(peer,until,ech,binding,&worker_.tickets);
                    if (started==TunnelConnectResult::connected) {
                        auto authenticated=co_await node_->client.ready(until);
                        if (authenticated && !canceled_ && !session_.closed && Clock::now()<until)
                            co_return TunnelConnectResult::connected;
                        started=node_->client.retryable_handshake(until) ? TunnelConnectResult::retryable : TunnelConnectResult::failed;
                    }
                    release();
                    if (started==TunnelConnectResult::failed || !selecting) co_return started;
                }
                co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
            }
            static auto text(nex::corosio::endpoint endpoint) -> std::string {
                return endpoint.address().is_v6() ? "["+endpoint.address().to_v6().to_string()+"]:"+std::to_string(endpoint.port()) :
                    endpoint.address().to_v4().to_string()+":"+std::to_string(endpoint.port());
            }
        public:
            Tunnel(Session& session,Worker<Layered>& worker,Profile const& profile,bool local)
                :session_(session),worker_(worker),profile_(profile),relay_local_(local) {}
            ~Tunnel(){release();}
            auto cancel() noexcept -> void {
                if (std::exchange(canceled_,true)) return;
                dns_.cancel();if (channel_) channel_->cancel();if (node_) node_->stop();
                if (ready_ && relay_local_) session_.client.cancel();
            }
            auto connect(nex::corosio::endpoint destination) -> nex::capy::task<TunnelConnectResult> {
                return connect_until(destination,session_.started+std::chrono::milliseconds(profile_.timeout));
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline) {
                return connect_tcp(std::string(domain)+":"+std::to_string(port),deadline);
            }
            auto connect_until(nex::corosio::endpoint destination,Clock::time_point deadline) {
                return connect_tcp(text(destination),deadline);
            }
            auto connect_tcp(std::string target,Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if (ready_ || node_ || canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                auto endpoints=profile_.bootstrap ? co_await resolve_bootstrap_owned(session_,worker_.env.context,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline) :
                    co_await resolve_local_owned(session_,worker_.env.context,dns_,profile_.host,profile_.port,deadline);
                if (!endpoints || canceled_ || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                auto ech = co_await profile_.ech.resolve(session_, worker_.env.context, dns_, profile_.bootstrap, profile_.port, deadline);
                if (!ech || canceled_ || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                for (auto const& peer:*endpoints) {
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (!valid_destination(peer)) continue;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    auto started=co_await authenticate(peer,deadline,*ech ? &**ech : nullptr);
                    if (started!=TunnelConnectResult::connected) {
                        if (started==TunnelConnectResult::timeout) co_return started;
                        continue;
                    }
                    auto opened=node_->client.open_tcp(target);
                    if (!opened) {release();continue;}
                    auto response_deadline=profile_.lazy_tcp_response ? h::StreamDeadline{deadline} : h::StreamDeadline{};
                    channel_.emplace(node_->client.application(),node_->client.driver(),*opened,std::nullopt,response_deadline);
                    if (!response_deadline) {
                        auto accepted=co_await channel_->ready(deadline);
                        if (!accepted) {release();continue;}
                    }
                    if (canceled_ || session_.closed || Clock::now()>=deadline) {release();continue;}
                    ready_=true;co_return TunnelConnectResult::connected;
                }
                co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
            auto packet_transport() const noexcept -> net::PacketTransport {return profile_.udp ? net::PacketTransport{net::PacketTransportKind::framed,{},false} : net::PacketTransport{};}
            auto has_uot() const noexcept -> bool {return false;}
            auto has_xudp() const noexcept -> bool {return false;}
            auto connect_packets(Clock::time_point deadline) -> nex::capy::task<TunnelConnectResult> {
                if (!profile_.udp || ready_ || node_ || canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                auto endpoints=profile_.bootstrap ? co_await resolve_bootstrap_owned(session_,worker_.env.context,dns_,*profile_.bootstrap,profile_.host,profile_.port,deadline) :
                    co_await resolve_local_owned(session_,worker_.env.context,dns_,profile_.host,profile_.port,deadline);
                if (!endpoints || canceled_ || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                auto ech = co_await profile_.ech.resolve(session_, worker_.env.context, dns_, profile_.bootstrap, profile_.port, deadline);
                if (!ech || canceled_ || session_.closed) co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                for (auto const& peer:*endpoints) {
                    if (canceled_ || session_.closed) co_return TunnelConnectResult::failed;
                    if (!valid_destination(peer)) continue;
                    if (Clock::now()>=deadline) co_return TunnelConnectResult::timeout;
                    auto started=co_await authenticate(peer,deadline,*ech ? &**ech : nullptr);
                    if (started!=TunnelConnectResult::connected) {
                        if (started==TunnelConnectResult::timeout) co_return started;
                        continue;
                    }
                    auto opened=node_->client.open_udp(1);
                    if (!opened) {release();continue;}
                    udp_=*opened;ready_=true;co_return TunnelConnectResult::connected;
                }
                co_return Clock::now()>=deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
            }
            auto connect_uot_until(Clock::time_point deadline) {return connect_packets(deadline);}
            auto connect_uot() {return connect_packets(Clock::now()+std::chrono::milliseconds(profile_.timeout));}
            auto connect_xudp_until(Clock::time_point deadline) {return connect_packets(deadline);}
            auto connect_xudp() {return connect_packets(Clock::now()+std::chrono::milliseconds(profile_.timeout));}
            auto send(std::span<std::uint8_t const> bytes) -> nex::capy::task<bool> {
                if (!ready_ || canceled_) co_return false;
                if (udp_) {
                    auto frame=net::parse_datagram({}, {},bytes);
                    if (frame.status!=net::DatagramStatus::accepted || frame.consumed!=bytes.size()) co_return false;
                    auto const& address=frame.destination;std::string host;
                    if (address.family==net::ProxyAddressFamily::ipv4) {
                        nex::corosio::ipv4_address::bytes_type raw{};std::copy_n(address.bytes.begin(),4,raw.begin());
                        host=nex::corosio::ipv4_address(raw).to_string()+":"+std::to_string(address.port);
                    } else if (address.family==net::ProxyAddressFamily::ipv6) {
                        nex::corosio::ipv6_address::bytes_type raw{};std::copy_n(address.bytes.begin(),16,raw.begin());
                        host="["+nex::corosio::ipv6_address(raw).to_string()+"]:"+std::to_string(address.port);
                    } else host=std::string(address.bytes.begin(),address.bytes.begin()+address.length)+":"+std::to_string(address.port);
                    auto reopened=node_->client.open_udp(1);
                    if (!reopened) co_return false;
                    udp_=*reopened;
                    auto ticket=node_->client.submit_udp(*udp_,++packet_id_,host,frame.payload);
                    if (!ticket) co_return false;
                    struct Pending {typename Node<Layered>::Client& client;bool done=false;~Pending(){if (!done) client.cancel_udp_send();}} pending{node_->client};
                    auto deadline=Clock::now()+std::chrono::seconds(10);
                    while (!canceled_ && !session_.closed && Clock::now()<deadline) {
                        auto& changed=node_->client.driver().changed();changed.clear();
                        auto done=node_->client.udp_sent(*ticket);
                        if (!done) co_return false;
                        if (*done) {pending.done=true;session_.touched=Clock::now();co_return true;}
                        auto [error]=co_await nex::corosio::timeout(changed.wait(),deadline);if (error) co_return false;
                    }
                    co_return false;
                }
                auto result=co_await channel_->send(bytes);if (result) session_.touched=Clock::now();else cancel();co_return result;
            }
            auto read(std::span<std::uint8_t> bytes) -> nex::capy::task<std::expected<std::size_t,std::string>> {
                if (!ready_ || canceled_) co_return std::unexpected("Hysteria2 stream closed");
                if (udp_) {
                    while (!canceled_ && !session_.closed) {
                        auto& changed=node_->client.driver().changed();changed.clear();
                        if (reply_offset_<reply_.size()) {
                            auto count=std::min(bytes.size(),reply_.size()-reply_offset_);
                            std::copy_n(reply_.begin()+reply_offset_,count,bytes.begin());reply_offset_+=count;
                            if (reply_offset_==reply_.size()) {reply_.clear();reply_offset_=0;}
                            co_return count;
                        }
                        auto packet=node_->client.udp_packet();
                        if (packet) {
                            auto parsed=http::parse_destination_authority(packet->address);net::ProxyAddress address;
                            if (packet->owner==*udp_ && parsed.status==http::ConnectStatus::accepted && parsed.port) {
                                address.port=parsed.port;
                                if (parsed.kind==http::HostKind::domain && parsed.host.size()<=address.bytes.size()) {
                                    address.family=net::ProxyAddressFamily::domain;address.length=static_cast<std::uint8_t>(parsed.host.size());
                                    std::ranges::copy(parsed.host,address.bytes.begin());
                                } else if (parsed.kind!=http::HostKind::domain) {
                                    address.family=parsed.kind==http::HostKind::ipv4 ? net::ProxyAddressFamily::ipv4 : net::ProxyAddressFamily::ipv6;
                                    address.length=address.family==net::ProxyAddressFamily::ipv4 ? 4 : 16;std::copy_n(parsed.address.begin(),address.length,address.bytes.begin());
                                }
                                auto frame=net::encode_datagram({},address,packet->payload);
                                if (frame) reply_=std::move(*frame);
                            }
                            (void)node_->client.consume_udp();
                            if (!reply_.empty()) session_.touched=Clock::now();
                            // A discarded packet may have more packets queued behind it.
                            continue;
                        }
                        if (!node_->client.driver().running()) break;
                        node_->client.maintain_udp();
                        auto [error]=co_await changed.wait();if (error) break;
                    }
                    co_return std::unexpected("Hysteria2 datagram connection closed");
                }
                auto result=co_await channel_->read(bytes);if (!result) {cancel();co_return std::unexpected("Hysteria2 stream read failed");}
                if (*result) session_.touched=Clock::now();co_return *result;
            }
            auto close_output() -> nex::capy::task<bool> {co_return ready_ && channel_ && co_await channel_->close_output();}
            auto upload() -> nex::capy::task<bool> {
                if (!ready_ || canceled_ || !channel_) co_return false;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client,*channel_,[this] {session_.touched=Clock::now();},relay_local_, session_.traffic_delivery()});
            }
            auto download() -> nex::capy::task<bool> {
                if (!ready_ || canceled_ || !channel_) co_return false;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client,*channel_,[this] {session_.touched=Clock::now();},relay_local_, session_.traffic_delivery()});
            }
        };
    }
    auto make_hysteria2_factory(std::string_view host,std::uint16_t port,std::string_view password_file,std::string_view server_name,
        std::string_view ca_file,TlsKeyExchange exchange,std::optional<std::size_t> bootstrap,std::uint32_t timeout,TcpSocketOptions options,
        std::uint32_t handshake_ms,std::uint32_t idle_ms,std::size_t native_bytes,bool udp,
        std::optional<std::string_view> salamander_file,std::optional<std::size_t> max_udp_payload_size,bool disable_path_mtu_discovery,std::uint64_t send_bps,std::uint64_t receive_bps,bool disable_compensation,TlsFingerprint fingerprint,bool lazy_tcp_response,
        QuicEchOptions const& ech, bool dns_available,quic::ReceiveWindows windows,std::span<std::array<std::uint8_t,32> const> pins,
        std::span<config::PortRange const> port_ranges,std::uint32_t hop_interval_ms) -> std::expected<TunnelFactory,std::string> {
        if (host.empty() || !port || !timeout || timeout>3600000 || !options.valid() || options.keepalive_configured() || options.bind_address_no_port.has_value() || options.multipath_tcp.has_value())
            return std::unexpected("invalid or unsupported Hysteria2 dial options");
        auto shape=tls::parse_fingerprint(config::tls_fingerprint_name(fingerprint));
        if (!shape) return std::unexpected("invalid TLS fingerprint configuration");
        auto group=exchange==TlsKeyExchange::x25519 ? std::uint16_t{0x001d} : std::uint16_t{0x11ec};
        h::TransportOptions transport{std::chrono::milliseconds(handshake_ms),std::chrono::milliseconds(idle_ms),native_bytes,udp};
        transport.receive_windows=windows;transport.max_udp_payload_size=max_udp_payload_size;transport.disable_path_mtu_discovery=disable_path_mtu_discovery;
        transport.congestion={send_bps,receive_bps,false,disable_compensation};
        for (auto const& r : port_ranges) transport.port_ranges.push_back({r.first,r.last});
        transport.hop_interval=std::chrono::milliseconds(hop_interval_ms);
        auto ech_profile = quic_ech::Profile::load(ech, server_name, dns_available);
        if (!ech_profile) return std::unexpected(ech_profile.error());
        auto client=h::ClientProfile::load(server_name,ca_file,password_file,group,exchange==TlsKeyExchange::x25519_mlkem768_only,transport,salamander_file,*shape,pins);
        if (!client) return std::unexpected(client.error());
        auto profile=std::make_unique<Profile>(std::string(host),port,bootstrap,timeout,std::move(*client),udp,lazy_tcp_response,options,std::move(*ech_profile));auto* borrowed=profile.get();
        TunnelFactory factory{[profile=std::move(profile)](Session& session,nex::corosio::io_context& context,bool local,TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
            Worker<false>* worker=nullptr;{std::lock_guard lock(profile->mutex);worker=find<false>(*profile,context);}
            return worker ? pro::make_proxy<TunnelFacade,Tunnel<false>>(session,*worker,*profile,local) : pro::proxy<TunnelFacade>{};
        },timeout,[borrowed](Session& session,nex::corosio::io_context& context,TunnelFactory const&,bool local) -> pro::proxy<TunnelFacade> {
            Worker<true>* worker=nullptr;{std::lock_guard lock(borrowed->mutex);worker=find<true>(*borrowed,context);}
            return worker ? pro::make_proxy<TunnelFacade,Tunnel<true>>(session,*worker,*borrowed,local) : pro::proxy<TunnelFacade>{};
        },std::nullopt,options.configured()};
        factory.start_context=[borrowed](OutboundContext const& env,TunnelFactory const* detour,bool direct) {
            return detour ? initialize<true>(*borrowed,env,detour,direct) : initialize<false>(*borrowed,env,nullptr,direct);
        };
        factory.stop_context=[borrowed](nex::corosio::io_context& context) noexcept {stop<false>(*borrowed,context);stop<true>(*borrowed,context);};
        factory.quiesced_context=[borrowed](nex::corosio::io_context& context) noexcept {
            Worker<true>* worker=nullptr;{std::lock_guard lock(borrowed->mutex);worker=find<true>(*borrowed,context);}
            return !worker || worker->quiesced();
        };
        factory.finish_context=[borrowed](nex::corosio::io_context& context) noexcept {finish<false>(*borrowed,context);finish<true>(*borrowed,context);};
        return factory;
    }
}
