#pragma once

        class Http3Carrier {
            static constexpr std::size_t capacity=3*256;
            using Registry=quic::CidRegistry<1,8>;
            using Tls=masque::ClientProfile::Tls;
            using Application=masque::Session<Tls,Http3Streams<Registry,false,capacity>,false>;
            using Native=quic::DatagramSession<Tls,Application>;
            struct Bundle {
                std::unique_ptr<Tls> tls;
                Http3Streams<Registry,false,capacity> hooks;
                quic::NativeMemory<> memory;
                Application app;
                Native session;
                Bundle(std::unique_ptr<Tls> identity,Registry& registry,quic::SessionHandle owner,nex::capy::async_event& event,
                    nex::corosio::endpoint const& local,std::size_t memory_bytes)
                    :tls(std::move(identity)),hooks(registry,owner,event),memory(memory_bytes),app(*tls,hooks,false,memory.http3()),
                    session(*tls,app,local) {}
            };
            struct Factory {
                using Session=Native;
                auto admit(q::ngtcp2_pkt_hd const&,nex::corosio::endpoint const&,Clock::time_point) const noexcept -> bool {return false;}
                auto create(quic::SessionHandle,Registry&,std::span<std::uint8_t const>,q::ngtcp2_pkt_hd const&,
                    nex::corosio::endpoint const&,Clock::time_point) noexcept -> std::expected<Session*,int> {
                    return std::unexpected(q::err_invalid_argument);
                }
                auto application_drained(quic::SessionHandle,Session const&) const noexcept -> bool {return true;}
                auto failed(quic::SessionHandle,int) noexcept -> void {}
                auto destroy(quic::SessionHandle,Session&) noexcept -> void {}
            };
            using Port=quic::DatagramPort<Factory,1,8,8,true>;
            using Driver=net::DatagramDriver<Port>;
            CarrierDns dns_;
            Resolver resolver_;
            platform::SocketBinding binding_;
            masque::ClientProfile profile_;
            nex::corosio::io_context& context_;
            nex::corosio::udp_socket socket_;
            nex::corosio::endpoint local_;
            std::optional<nex::corosio::endpoint> peer_;
            std::optional<Bundle> bundle_;
            Factory factory_;
            Port port_{factory_};
            Driver driver_{socket_,port_};
            std::optional<Http3Channel<Bundle,Driver>> channel_;
            nex::capy::async_event ready_;
            bool connecting_=true,stopped_=false;

            static auto finish(std::shared_ptr<Http3Carrier> carrier) -> nex::capy::task<> {
                auto deadline=Clock::now()+std::chrono::milliseconds(250);
                while (carrier->driver_.running() && !carrier->port_.quiescent() && !carrier->port_.shutdown_failure()) {
                    auto& changed=carrier->driver_.changed();
                    changed.clear();
                    auto [error]=co_await nex::corosio::timeout(changed.wait(),deadline);
                    if (error) break;
                }
                carrier->driver_.finish();
            }
            static auto options() noexcept -> hysteria2::TransportOptions {
                hysteria2::TransportOptions result;
                result.udp=false;
                return result;
            }
            auto start(nex::corosio::endpoint peer,Clock::time_point deadline) -> bool {
                if (net::prepare_udp_socket(socket_,peer,&binding_,deadline)) return false;
                local_=socket_.local_endpoint();
                auto owner=port_.registry().reserve();
                if (!owner) return false;
                struct Unattached {
                    Port& port;
                    quic::SessionHandle owner;
                    bool active=true;
                    ~Unattached(){if (active) port.registry().release(owner);}
                } release{port_,*owner};
                auto tls=profile_.tls_client(peer,nullptr);
                auto settings=hysteria2::TransportProfile<16,h3_window>::settings(profile_.transport());
                auto params=hysteria2::TransportProfile<16,h3_window>::parameters(profile_.transport());
                if (!tls || !settings || !params) return false;
                std::array<std::uint8_t,8> src_bytes;
                std::array<std::uint8_t,16> dst_bytes;
                if (!crypto::random_bytes(src_bytes) || !crypto::random_bytes(dst_bytes) ||
                    !port_.registry().insert(*owner,src_bytes)) return false;
                auto now=Clock::now();
                if (now>=deadline) return false;
                auto timeout=std::chrono::duration_cast<std::chrono::nanoseconds>(deadline-now).count();
                settings->handshake_timeout=std::min(settings->handshake_timeout,static_cast<std::uint64_t>(timeout));
                bundle_.emplace(std::move(*tls),port_.registry(),*owner,driver_.changed(),local_,profile_.transport().native_bytes);
                q::ngtcp2_cid source{},destination{};
                q::ngtcp2_cid_init(&source,src_bytes.data(),src_bytes.size());
                q::ngtcp2_cid_init(&destination,dst_bytes.data(),dst_bytes.size());
                if (bundle_->session.start(false,destination,source,peer,*settings,*params,bundle_->memory.transport(),now) ||
                    !port_.attach(*owner,bundle_->session)) return false;
                release.active=false;
                channel_.emplace(*bundle_,driver_);
                peer_=peer;
                return true;
            }
        public:
            using Ticket=std::int64_t;
            Http3Carrier(Session& session,nex::corosio::io_context& context,Peer const& peer,
                std::optional<std::size_t> bootstrap,TcpSocketOptions const& options_)
                :dns_(session,context),resolver_{dns_.session,context,peer,bootstrap},binding_(options_.binding),
                profile_(masque::ClientProfile::for_http(peer.tls->profile(),peer.endpoint.authority,options(),peer.tls->fingerprint())),
                context_(context),socket_(context) {}
            auto connect(std::shared_ptr<Http3Carrier> owner,nex::corosio::io_context& context,Clock::time_point until)
                -> nex::capy::task<bool> {
                struct Signal {
                    Http3Carrier& carrier;
                    ~Signal() {carrier.connecting_=false;carrier.ready_.set();}
                } signal{*this};
                auto endpoints=co_await resolver_(until);
                if (stopped_ || !endpoints || endpoints->empty()) co_return false;
                auto peer=std::ranges::find_if(*endpoints,[](auto const& endpoint) {return valid_destination(endpoint);});
                if (peer==endpoints->end() || !start(*peer,until)) {
                    cancel();
                    co_return false;
                }
                auto run=[](std::shared_ptr<Http3Carrier> carrier) -> nex::capy::task<> {
                    (void)co_await carrier->driver_.run();
                    carrier->cancel();
                };
                nex::capy::run_async(context.get_executor(),[owner]{},[owner](std::exception_ptr){owner->cancel();})(run(owner));
                driver_.notify();
                while (!bundle_->app.can_request()) {
                    if (stopped_ || !co_await channel_->wait(until)) {cancel();co_return false;}
                }
                co_return !stopped_;
            }
            auto wait_ready(Clock::time_point until) -> nex::capy::task<bool> {
                if (connecting_ && !stopped_) {
                    auto [error]=co_await nex::corosio::timeout(ready_.wait(),until);
                    if (error) co_return false;
                }
                co_return !failed();
            }
            auto failed() const noexcept -> bool {
                return stopped_ || (!connecting_ && (!bundle_ || !bundle_->app.can_request() || bundle_->hooks.goaway));
            }
            auto record_peer(Session& session) const noexcept -> void {if (peer_) session.record_physical_peer(*peer_);}
            auto cancel() noexcept -> void {
                if (std::exchange(stopped_,true)) return;
                resolver_.cancel();
                ready_.set();
                driver_.finish();
            }
            auto retire(std::shared_ptr<Http3Carrier> owner) noexcept -> void {
                if (!driver_.running() || !bundle_ || bundle_->app.stopping()) {
                    cancel();
                    return;
                }
                port_.begin_shutdown();
                driver_.notify();
                stopped_=true;
                try {
                    nex::capy::run_async(context_.get_executor(),[owner]{},
                        [owner](std::exception_ptr) noexcept {owner->driver_.finish();})(finish(owner));
                } catch (...) {driver_.finish();}
            }
            auto open(xhttp::Request const& request,Peer const& peer,http2::BodyView body,Clock::time_point until)
                -> nex::capy::task<std::optional<Ticket>> {
                std::vector<h3::nghttp3_nv> fields{h3_field(":method",request.method),h3_field(":scheme","https"),
                    h3_field(":path",request.target),h3_field(":authority",peer.endpoint.authority)};
                for (auto const& [name,value]:request.fields) fields.push_back(h3_field(name,value));
                auto length=std::to_string(body.bytes.size());
                if (body.end_stream && request.method=="POST") fields.push_back(h3_field("content-length",length));
                std::int64_t id=-1;
                for (;;) {
                    if (failed() || bundle_->hooks.streams.size()==capacity) co_return std::nullopt;
                    auto rc=q::ngtcp2_conn_open_bidi_stream(bundle_->session.transport().native(),&id,nullptr);
                    if (!rc) break;
                    if (rc!=q::err_stream_id_blocked || !co_await channel_->wait(until)) co_return std::nullopt;
                }
                auto* stream=bundle_->hooks.open(id);
                if (!stream) co_return std::nullopt;
                stream->output.assign(body.bytes.begin(),body.bytes.end());
                stream->fin_requested=body.end_stream;
                if (bundle_->app.h3().request(id,fields,!body.bytes.empty() || !body.end_stream)) {
                    release(id);
                    co_return std::nullopt;
                }
                driver_.notify();
                co_return id;
            }
            auto read(Ticket stream,std::span<std::uint8_t> output,Deadline until) -> nex::capy::task<std::expected<std::size_t,IoError>> {
                for (;;) {
                    auto* state=channel_->state(stream);
                    if (!state || state->failed || state->retired || stopped_) co_return std::unexpected(IoError::io);
                    if (state->complete) {
                        auto status=std::ranges::find(state->headers,std::string_view(":status"),&http2::Header::name);
                        if (status==state->headers.end() || status->value!="200") co_return std::unexpected(IoError::protocol);
                        co_return co_await channel_->read(stream,output,until);
                    }
                    if (!co_await channel_->wait(until)) co_return std::unexpected(IoError::timeout);
                }
            }
            auto transmit(Ticket stream,http2::BodyView body,Deadline until) -> nex::capy::task<bool> {
                if (!channel_->body(stream,body.bytes,body.end_stream)) co_return false;
                co_return co_await channel_->wait_sent(stream,body.end_stream,until);
            }
            auto release(Ticket stream) noexcept -> void {channel_->release(stream);}
        };
