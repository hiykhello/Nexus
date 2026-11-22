// Private implementation: included inside proxy.
#pragma once
        struct FastResolver {
            Session& session;io::io_context& context;Profile const& profile;std::optional<std::size_t> bootstrap;DnsSlot slot;
            auto operator()(Clock::time_point deadline) -> capy::task<std::optional<std::vector<io::endpoint>>> {
                if(bootstrap)return resolve_bootstrap_owned(session,context,slot,*bootstrap,profile.host,profile.port,deadline);
                return resolve_local_owned(session,context,slot,profile.host,profile.port,deadline);
            }
            auto cancel() noexcept -> void {slot.cancel();}
        };
        class VlessFast {
            using Connector=tls::detail::FastOpenPhysicalConnector<FastResolver,Profile>;
            using Socket=Connector::Socket;
            Session& session_;Profile const& profile_;Connector connector_;std::uint32_t timeout_ms_;bool relay_local_;
            std::stop_source stop_;bool starting_=false;
            std::unique_ptr<vless::detail::TcpClient<Socket>> client_;
            std::unique_ptr<vless::detail::DuplexRelay<io::tcp_socket,Socket>> relay_;
            std::unique_ptr<vless::detail::VisionClient<Socket>> vision_client_;
            std::unique_ptr<vless::detail::VisionRelay<io::tcp_socket,Socket>> vision_relay_;
        public:
            VlessFast(Session& session,io::io_context& context,Profile const& profile,std::optional<std::size_t> bootstrap,std::uint32_t timeout_ms,bool local,TcpSocketOptions const& options)
                :session_(session),profile_(profile),connector_(context,FastResolver{session,context,profile,bootstrap},profile,options),timeout_ms_(timeout_ms),relay_local_(local){}
#ifdef NEXUS_TEST_TUNNEL_PROFILE
            ~VlessFast(){nexus_test_tunnel_profile_destroy();}
#endif
            auto cancel() noexcept -> void {stop_.request_stop();if(relay_)relay_->cancel();if(vision_relay_)vision_relay_->cancel();connector_.cancel();}
            auto connect(io::endpoint destination) -> capy::task<TunnelConnectResult> {return connect_until(destination,session_.started+std::chrono::milliseconds(timeout_ms_));}
            auto connect_until(io::endpoint destination,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start(destination,false,deadline));
            }
            auto connect_domain(std::string_view domain,std::uint16_t port,Clock::time_point deadline)
                -> capy::task<TunnelConnectResult> {
                co_return co_await capy::run(stop_.get_token())(start({},false,deadline,domain_request(profile_,domain,port)));
            }
            auto has_uot() const noexcept -> bool{return false;}
            auto has_xudp() const noexcept -> bool{return !profile_.packetaddr && !profile_.fixed_udp;}
            auto packet_transport() const noexcept -> net::PacketTransport{return packet_format(profile_);}
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (profile_.fixed_udp) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({},true,deadline));
            }
            auto connect_packets(net::ProxyAddress const& peer,Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (!profile_.fixed_udp) co_return co_await connect_packets(deadline);
                auto request=fixed_request(profile_,peer);
                if (!request) co_return TunnelConnectResult::failed;
                co_return co_await capy::run(stop_.get_token())(start({},true,deadline,std::move(request)));
            }
            auto connect_uot() -> capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult>{co_return TunnelConnectResult::failed;}
            auto connect_xudp() -> capy::task<TunnelConnectResult>{return connect_xudp_until(Clock::now()+std::chrono::milliseconds(timeout_ms_));}
            auto connect_xudp_until(Clock::time_point deadline) -> capy::task<TunnelConnectResult>{co_return has_xudp() ? co_await connect_packets(deadline) : TunnelConnectResult::failed;}
        private:
            auto start(io::endpoint destination,bool mux,Clock::time_point deadline,
                       std::optional<vless::TcpRequest> fixed={}) -> coro::quitter<TunnelConnectResult> {
                if(starting_ || relay_ || vision_relay_ || stop_.stop_requested() || session_.closed)co_return TunnelConnectResult::failed;
                if(Clock::now()>=deadline)co_return TunnelConnectResult::timeout;
                starting_=true;struct Guard{VlessFast& owner;bool done=false;~Guard(){owner.starting_=false;if(!done)owner.cancel();}} guard{*this};
                auto ready=co_await connector_.start(deadline);
                if(stop_.stop_requested() || session_.closed)co_return TunnelConnectResult::failed;
                if(ready!=tls::detail::ConnectResult::connected)co_return ready==tls::detail::ConnectResult::timeout ? TunnelConnectResult::timeout :
                    ready==tls::detail::ConnectResult::retryable ? TunnelConnectResult::retryable : TunnelConnectResult::failed;
                if(!profile_.accepts_alpn(connector_.negotiated()))co_return TunnelConnectResult::failed;
                auto* connection=connector_.application();auto* socket=connector_.socket();
                if(!connection || !socket)co_return TunnelConnectResult::failed;
                vless::TcpRequest request;request.user=profile_.user;
                if(!mux && !fixed){request.port=destination.port();auto address=destination.address();
                    if(address.is_v4()){request.kind=vless::AddressKind::ipv4;auto bytes=address.to_v4().to_bytes();request.address.assign(bytes.begin(),bytes.end());}
                    else{request.kind=vless::AddressKind::ipv6;auto bytes=address.to_v6().to_bytes();request.address.assign(bytes.begin(),bytes.end());}}
                if(profile_.vision){
                    vision_client_=std::make_unique<vless::detail::VisionClient<Socket>>(*socket,*connection,profile_.user);
                    vision_relay_=std::make_unique<vless::detail::VisionRelay<io::tcp_socket,Socket>>(session_.client,*vision_client_,[this]{session_.touched=Clock::now();},relay_local_&&!mux);
                    auto sent=mux ? co_await vision_client_->start_mux(deadline) : co_await vision_client_->start(fixed ? *fixed : request,deadline);
                    if(!sent || stop_.stop_requested() || session_.closed)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                }else{
                    client_=std::make_unique<vless::detail::TcpClient<Socket>>(*connection);
                    if(profile_.transport){auto upgraded=co_await client_->upgrade(*profile_.transport,deadline);
                        if(!upgraded || stop_.stop_requested() || session_.closed)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;}
                    auto sent=mux && !fixed ? co_await client_->start_datagrams(profile_.user,profile_.packetaddr,deadline) : co_await client_->start(fixed ? *fixed : request,deadline);
                    if(!sent || stop_.stop_requested() || session_.closed)co_return Clock::now()>=deadline?TunnelConnectResult::timeout:TunnelConnectResult::failed;
                    relay_=std::make_unique<vless::detail::DuplexRelay<io::tcp_socket,Socket>>(session_.client,*connection,*client_,[this]{session_.touched=Clock::now();},relay_local_&&!mux);
                }
                guard.done=true;co_return TunnelConnectResult::connected;
            }
        public:
            auto send(std::span<std::uint8_t const> bytes) -> capy::task<bool> {
                if((!relay_&&!vision_relay_)||stop_.stop_requested())co_return false;if(bytes.empty())co_return true;
                if(vision_relay_)co_return co_await vision_relay_->write(bytes);co_return co_await relay_->write(bytes);
            }
            auto read(std::span<std::uint8_t> bytes) -> capy::task<std::expected<std::size_t,std::string>> {
                if((!relay_&&!vision_relay_)||stop_.stop_requested())co_return std::unexpected("tunnel closed");
                auto result=vision_relay_ ? co_await vision_relay_->read(bytes) : co_await relay_->read(bytes);
                if(!result)co_return std::unexpected("tunnel read failed");co_return *result;
            }
            auto close_output() -> capy::task<bool>{if(vision_relay_)co_return co_await vision_relay_->close_output();if(!relay_)co_return false;co_return co_await relay_->close_output();}
            auto upload() -> capy::task<bool>{if(vision_relay_)co_return co_await vision_relay_->upload({},session_.traffic_delivery());if(!relay_)co_return false;co_return co_await relay_->upload({},session_.traffic_delivery());}
            auto download() -> capy::task<bool>{if(vision_relay_)co_return co_await vision_relay_->download({},session_.traffic_delivery());if(!relay_)co_return false;co_return co_await relay_->download({},session_.traffic_delivery());}
        };
