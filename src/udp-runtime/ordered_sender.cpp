module ss_udp.ordered_sender;
import std;
import rules;
import relay;
import ss_udp.listener;
import net.udp_authorization;
import net.datagram_frame;
import uot;
import xudp;
import xudp.client_sessions;
import xudp.client_io;
import capy;
import corosio;

namespace relay::udp_runtime {
    // One executor owns this object, its routing server and all dispatchers.
    // Tokens remain under dispatcher budget until the writer takes a packet.
    class OrderedUdpSender : public std::enable_shared_from_this<OrderedUdpSender> {
        using Clock=std::chrono::steady_clock;
        using Dispatch=shadowsocks::UdpDispatcher;
        using Peer=shadowsocks::UdpPeer;
        using Handle=shadowsocks::UdpSessionHandle;
        using Sink=shadowsocks::detail::UdpTunnelReplySink;
        using Error=shadowsocks::detail::UdpResolveError;
        struct Job { std::uint64_t token; Peer target; Clock::time_point deadline; Sink sink; };
        struct Stream {
            PacketTunnel* tunnel=nullptr;
            auto write(std::span<std::uint8_t const> data) -> capy::task<bool> {co_return co_await tunnel->send(data);}
            auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t,std::string>> {co_return co_await tunnel->read(data);}
            auto cancel() noexcept -> void {if(tunnel)tunnel->cancel();}
        };
        struct Slot {
            Dispatch* dispatcher; Handle session; Peer target,source; std::size_t outbound;
            std::optional<std::string> inbound;
            std::unique_ptr<Session> routing;
            std::unique_ptr<PacketTunnel> tunnel;
            std::deque<Job> queue;
            net::UdpAuthorization authorization;
            net::PacketTransport transport{};
            Stream stream;
            std::unique_ptr<xudp::ClientIo<Stream>> xudp;
            std::uint16_t xudp_id=0;
            Sink sink;
            Clock::time_point touched=Clock::now();
            std::optional<Clock::time_point> active_deadline;
            capy::async_event reader_done,auth_wake;
            bool connected=false,writer=false,reader=false,rotating=false,closed=false;
        };
        Server& server_;
        corosio::io_context& context_;
        std::vector<std::unique_ptr<Slot>> slots_;
        std::stop_source timer_stop_;
        capy::async_event timer_wake_;
        std::size_t pending_=0,active_=0;
        bool stopped_=false,timer_=false;
        static constexpr std::size_t max_slots_=64,max_pending_=64;
        static auto address(Peer const& peer) -> net::ProxyAddress {
            net::ProxyAddress result;result.family=peer.family==4 ? net::ProxyAddressFamily::ipv4 : net::ProxyAddressFamily::ipv6;
            result.length=peer.family==4 ? 4 : 16;result.port=peer.port;
            std::copy_n(peer.address.begin(),result.length,result.bytes.begin());return result;
        }
        static auto xaddress(Peer const& peer) -> xudp::Address {
            xudp::Address result;result.family=peer.family==4 ? xudp::Family::ipv4 : xudp::Family::ipv6;
            result.length=peer.family==4 ? 4 : 16;result.port=peer.port;
            std::copy_n(peer.address.begin(),result.length,result.bytes.begin());return result;
        }
        static auto peer(net::ProxyAddress const& source) -> std::optional<Peer> {
            if(source.family!=net::ProxyAddressFamily::ipv4 && source.family!=net::ProxyAddressFamily::ipv6)return {};
            auto size=source.family==net::ProxyAddressFamily::ipv4 ? 4u : 16u;
            if(source.length!=size || !source.port)return {};
            Peer result{static_cast<std::uint8_t>(size==4 ? 4 : 6),{},source.port};
            std::copy_n(source.bytes.begin(),size,result.address.begin());return result;
        }
        static auto peer(xudp::Address const& source) -> std::optional<Peer> {
            if(source.family!=xudp::Family::ipv4 && source.family!=xudp::Family::ipv6)return {};
            auto size=source.family==xudp::Family::ipv4 ? 4u : 16u;
            if(source.length!=size || !source.port)return {};
            Peer result{static_cast<std::uint8_t>(size==4 ? 4 : 6),{},source.port};
            std::copy_n(source.bytes.begin(),size,result.address.begin());return result;
        }
        static auto endpoint(Peer const& value) -> net::UdpEndpoint {return {value.family,value.address,value.port};}
        static auto same(Handle const& a,Handle const& b) noexcept -> bool {return a.owner==b.owner && a.id==b.id && a.generation==b.generation;}
        auto close(Slot& slot) noexcept -> void {
            if(slot.closed)return;slot.closed=true;slot.authorization.close();
            slot.auth_wake.set();slot.reader_done.set();timer_wake_.set();
            for(auto& job:slot.queue){(void)slot.dispatcher->cancel(job.token);--pending_;}slot.queue.clear();
            if(slot.xudp)slot.xudp->cancel();else if(slot.tunnel)slot.tunnel->cancel();
            if(slot.routing)slot.routing->close();
        }
        auto reap() -> void {
            std::erase_if(slots_,[](auto const& slot){return slot->closed && !slot->writer && !slot->reader;});
        }
        auto timer() -> capy::task<> {
            using namespace std::chrono_literals;
            while(!stopped_) {
                timer_wake_.clear();
                if(stopped_)break;
                if(slots_.empty()) {
                    auto [error]=co_await timer_wake_.wait();
                    if(error || stopped_) {stop();break;}
                    continue;
                }
                auto now=Clock::now();
                auto next=now+250ms;
                for(auto const& slot:slots_) if(!slot->closed) {
                    if(slot->active_deadline)next=std::min(next,*slot->active_deadline);
                    if(!slot->writer)next=std::min(next,slot->touched+62s);
                }
                if(now<next) {
                    auto [error]=co_await corosio::timeout(timer_wake_.wait(),next);
                    if(error && timer_stop_.stop_requested()) {stop();break;}
                }
                if(stopped_)break;
                now=Clock::now();
                for(auto& slot:slots_) if(!slot->closed &&
                    (!slot->dispatcher->current(slot->session) ||
                     (slot->active_deadline && now>=*slot->active_deadline) ||
                     (!slot->writer && now-slot->touched>=62s))) close(*slot);
                reap();
            }
        }
        auto start_timer() -> void {
            if(timer_)return;timer_=true;++active_;
            try {capy::run_async(context_.get_executor(),timer_stop_.get_token(),[this]{timer_=false;--active_;},
                [this](std::exception_ptr) noexcept {timer_=false;--active_;stop();})(timer());}
            catch (...) {timer_=false;--active_;throw;}
        }
        auto deliver(Slot& slot,Peer source,std::span<std::uint8_t const> payload) -> capy::task<bool> {
            using namespace std::chrono_literals;
            while(!stopped_ && !slot.closed) {
                auto result=slot.sink(slot.session,source,payload);
                if(result==shadowsocks::detail::UdpTunnelReplyResult::delivered || result==shadowsocks::detail::UdpTunnelReplyResult::dropped) {
                    slot.touched=Clock::now();co_return true;
                }
                if(result!=shadowsocks::detail::UdpTunnelReplyResult::busy)co_return false;
                auto [error]=co_await corosio::delay(1ms);if(error)co_return false;
            }
            co_return false;
        }
        auto read_loop(Slot& slot) -> capy::task<> {
            using namespace std::chrono_literals;
            if(slot.xudp) {
                while(!stopped_ && !slot.closed) {
                    auto result=co_await slot.xudp->read();if(!result)break;
                    if(result->action==xudp::Incoming::ended) {if(result->session==slot.xudp_id)slot.xudp_id=0;continue;}
                    if(result->action!=xudp::Incoming::datagram)continue;
                    if(!result->source)break;auto source=peer(*result->source);if(!source)break;
                    if(!co_await deliver(slot,*source,result->payload))break;
                }
            } else {
                net::DatagramDecoder decoder(slot.transport.framing,address(slot.target));
                std::array<std::uint8_t,16640> bytes{};
                while(!stopped_ && !slot.closed) {
                    auto result=co_await slot.tunnel->read(bytes);if(!result || !*result || *result>bytes.size())break;
                    std::size_t offset=0;
                    while(offset<*result && !stopped_ && !slot.closed) {
                        auto fed=decoder.feed(std::span(bytes).subspan(offset,*result-offset));offset+=fed.consumed;
                        if(fed.status==net::DatagramStatus::incomplete)break;
                        if(fed.status!=net::DatagramStatus::accepted) {close(slot);break;}
                        auto frame=decoder.packet();if(!frame){close(slot);break;}
                        auto source=peer(frame->destination);if(!source){close(slot);break;}
                        while(!stopped_ && !slot.closed && slot.authorization.classify(endpoint(*source))==net::UdpReplyAuthorization::pending) {
                            slot.auth_wake.clear();
                            if(slot.authorization.classify(endpoint(*source))!=net::UdpReplyAuthorization::pending)break;
                            auto [error]=slot.active_deadline
                                ? co_await corosio::timeout(slot.auth_wake.wait(),*slot.active_deadline)
                                : co_await slot.auth_wake.wait();
                            if(error){close(slot);break;}
                        }
                        if(!slot.closed && slot.authorization.accepts(endpoint(*source)) && !co_await deliver(slot,*source,frame->payload)) {close(slot);break;}
                        (void)decoder.consume();
                    }
                }
            }
            if(!slot.rotating)close(slot);
        }
        auto start_reader(Slot& slot) -> void {
            slot.reader=true;++active_;
            try {capy::run_async(context_.get_executor(),[this,&slot]{slot.reader=false;slot.reader_done.set();--active_;},
                [this,&slot](std::exception_ptr) noexcept {close(slot);slot.reader=false;slot.reader_done.set();--active_;})(read_loop(slot));}
            catch (...) {slot.reader=false;slot.reader_done.set();--active_;throw;}
        }
        auto connect_slot(Slot& slot,Clock::time_point deadline,Sink const& sink) -> capy::task<bool> {
            auto connected=co_await slot.tunnel->connect(address(slot.target),deadline);
            if(stopped_ || slot.closed || connected!=PacketConnectResult::connected)co_return false;
            slot.transport=slot.tunnel->transport();
            if(slot.transport.kind==net::PacketTransportKind::xudp) {
                slot.stream.tunnel=slot.tunnel.get();slot.xudp=std::make_unique<xudp::ClientIo<Stream>>(slot.stream,1);
            } else if(slot.transport.kind==net::PacketTransportKind::framed) {
                if(slot.transport.needs_uot_request) {
                    auto request=uot::encode_request({false,address(slot.target)});
                    if(!request || !co_await slot.tunnel->send(*request))co_return false;
                }
            } else co_return false;
            if(stopped_ || slot.closed || Clock::now()>=deadline)co_return false;
            slot.connected=true;slot.sink=sink;start_reader(slot);co_return true;
        }
        auto rotate_xudp(Slot& slot,Clock::time_point deadline,Sink const& sink) -> capy::task<bool> {
            using namespace std::chrono_literals;
            slot.rotating=true;slot.connected=false;slot.xudp->cancel();
            while(slot.reader && !stopped_ && !slot.closed && Clock::now()<deadline) {
                slot.reader_done.clear();
                if(!slot.reader)break;
                auto [error]=co_await corosio::timeout(slot.reader_done.wait(),deadline);if(error)co_return false;
            }
            if(stopped_ || slot.closed || slot.reader || Clock::now()>=deadline)co_return false;
            slot.xudp.reset();slot.tunnel.reset();slot.xudp_id=0;slot.stream.tunnel=nullptr;
            slot.tunnel=server_.open_packet_tunnel(*slot.routing,slot.outbound);
            if(!slot.tunnel)co_return false;
            slot.rotating=false;
            slot.active_deadline=slot.tunnel->connection_deadline(deadline);
            co_return co_await connect_slot(slot,*slot.active_deadline,sink);
        }
        auto write_loop(Slot& slot) -> capy::task<> {
            while(!stopped_ && !slot.closed && !slot.queue.empty()) {
                auto job=std::move(slot.queue.front());slot.queue.pop_front();
                struct Guard {OrderedUdpSender& owner;Dispatch& dispatcher;std::uint64_t token;~Guard(){(void)dispatcher.cancel(token);--owner.pending_;}} guard{*this,*slot.dispatcher,job.token};
                if(Clock::now()>=job.deadline)continue;
                slot.active_deadline=job.deadline;
                if(!slot.connected) {
                    slot.active_deadline=slot.tunnel->connection_deadline(job.deadline);
                    if(!co_await connect_slot(slot,*slot.active_deadline,job.sink)){close(slot);break;}
                }
                if(stopped_ || slot.closed || Clock::now()>=*slot.active_deadline){slot.active_deadline.reset();continue;}
                auto packet=slot.dispatcher->take_selected(job.token,job.target,Clock::now());
                if(!packet || !same(packet->session,slot.session)){slot.active_deadline.reset();continue;}
                auto credit=slot.dispatcher->reserve_bytes(packet->session,true,packet->payload.size(),Clock::now());
                if (!credit) {slot.active_deadline.reset();continue;}
                credit->submit();
                bool sent=false;
                if(slot.xudp) {
                    if(slot.xudp_id) {
                        auto result=co_await slot.xudp->send(slot.xudp_id,xaddress(packet->target),packet->payload);
                        sent=result.has_value();
                        if(!result && (result.error()!=xudp::ClientIoError::session || slot.xudp_id)) {close(slot);break;}
                    }
                    if(!sent) {
                        auto result=co_await slot.xudp->open(xaddress(packet->target),packet->payload);
                        if(!result && result.error()==xudp::ClientIoError::exhausted) {
                            if(!co_await rotate_xudp(slot,job.deadline,job.sink)){close(slot);break;}
                            result=co_await slot.xudp->open(xaddress(packet->target),packet->payload);
                        }
                        if(result){slot.xudp_id=*result;sent=true;}
                    }
                } else {
                    auto frame=net::encode_datagram(slot.transport.framing,address(packet->target),packet->payload);
                    auto transaction=slot.authorization.begin(endpoint(packet->target));
                    if(frame && transaction) {
                        sent=co_await slot.tunnel->send(*frame);
                        if(!slot.authorization.finish(*transaction,sent))sent=false;
                        slot.auth_wake.set();
                    }
                }
                if (sent) {
                    credit->complete(packet->payload.size());
                    slot.dispatcher->delivered(packet->session,true,packet->payload.size());
                }
                slot.active_deadline.reset();
                if(!sent || stopped_ || slot.closed){close(slot);break;}
                slot.touched=Clock::now();
            }
            slot.active_deadline.reset();
        }
        auto start_writer(Slot& slot) -> void {
            slot.writer=true;++active_;
            try {capy::run_async(context_.get_executor(),[this,&slot]{slot.writer=false;--active_;
                    if(!slot.closed && !slot.queue.empty())try {start_writer(slot);} catch(...) {close(slot);}},
                [this,&slot](std::exception_ptr) noexcept {close(slot);slot.writer=false;--active_;})(write_loop(slot));}
            catch (...) {slot.writer=false;--active_;throw;}
        }
    public:
        explicit OrderedUdpSender(Server& server) : server_(server),context_(server.executor_context()) {}
        ~OrderedUdpSender() {if(!drained())std::terminate();}
        OrderedUdpSender(OrderedUdpSender const&)=delete;
        auto operator=(OrderedUdpSender const&) -> OrderedUdpSender& = delete;
        [[nodiscard]] auto allows(std::size_t outbound) const noexcept -> bool {return outbound==0 || server_.has_packet_outbound(outbound);}
        [[nodiscard]] auto submit(corosio::io_context& context,Dispatch& dispatcher,std::uint64_t token,std::size_t outbound,
            std::span<Peer const> candidates,std::optional<std::string_view> inbound,Clock::time_point deadline,Sink sink) -> std::expected<void,Error> {
            if(stopped_ || &context!=&context_ || !allows(outbound) || deadline<=Clock::now())return std::unexpected(Error::state);
            if(outbound==0) {
                if(!dispatcher.complete_selected(token,candidates,Clock::now()))return std::unexpected(Error::dispatch);
                return {};
            }
            if(pending_>=max_pending_)return std::unexpected(Error::state);
            std::optional<shadowsocks::UdpTunnelTicket> ticket;
            for(auto const& candidate:candidates) {auto result=dispatcher.inspect_selected(token,candidate,Clock::now());if(result){ticket=*result;break;}}
            if(!ticket)return std::unexpected(Error::dispatch);
            reap();Slot* selected=nullptr;Slot* mux_candidate=nullptr;
            for(auto& slot:slots_)if(!slot->closed && slot->dispatcher==&dispatcher && same(slot->session,ticket->session) &&
                slot->source==ticket->source && slot->outbound==outbound &&
                ((!slot->inbound && !inbound) || (slot->inbound && inbound && *slot->inbound==*inbound))){
                if(slot->target==ticket->target){selected=slot.get();break;}
                if(!mux_candidate && slot->connected &&
                   (slot->xudp!=nullptr || (slot->transport.kind==net::PacketTransportKind::framed && !slot->transport.framing.connected)))
                    mux_candidate=slot.get();
            }
            if(!selected) selected=mux_candidate;
            if(!selected) {
                if(slots_.size()>=max_slots_)return std::unexpected(Error::state);
                auto lease=server_.acquire_session();if(!lease)return std::unexpected(Error::state);
                auto slot=std::make_unique<Slot>();slot->dispatcher=&dispatcher;slot->session=ticket->session;slot->target=ticket->target;
                slot->source=ticket->source;slot->outbound=outbound;if(inbound)slot->inbound.emplace(*inbound);
                slot->routing=std::make_unique<Session>(context_);server_.attach_session(*slot->routing,std::move(*lease));
                slot->routing->inbound=slot->inbound ? std::optional<std::string_view>{*slot->inbound} : std::nullopt;
                slot->routing->datagram_source=endpoint(slot->source);
                slot->tunnel=server_.open_packet_tunnel(*slot->routing,outbound);if(!slot->tunnel)return std::unexpected(Error::dispatch);
                selected=slot.get();slots_.push_back(std::move(slot));
            }
            selected->queue.push_back({token,ticket->target,deadline,std::move(sink)});++pending_;
            try {start_timer();timer_wake_.set();if(!selected->writer)start_writer(*selected);}
            catch (...) {close(*selected);throw;}
            return {};
        }
        auto stop() noexcept -> void {if(stopped_)return;stopped_=true;timer_wake_.set();timer_stop_.request_stop();for(auto& slot:slots_)close(*slot);}
        [[nodiscard]] auto drained() const noexcept -> bool {return !active_ && !pending_;}
        auto finish() noexcept -> void {if(!drained())std::terminate();slots_.clear();}
        [[nodiscard]] auto routing(std::shared_ptr<rules::RouteProgram const> program,std::size_t fallback,bool skip_unknown,std::chrono::milliseconds sniff_timeout)
            -> shadowsocks::detail::UdpOrderedRouting {
            auto self=shared_from_this();
            return {std::move(program),fallback,skip_unknown,sniff_timeout,
                [self](std::size_t outbound){return self->allows(outbound);},
                [self](auto& context,auto& dispatcher,auto token,auto outbound,auto candidates,auto inbound,auto deadline,auto sink) {
                    return self->submit(context,dispatcher,token,outbound,candidates,inbound,deadline,std::move(sink));
                },[self]{self->stop();},[self]{return self->drained();},[self]{self->finish();}};
        }
    };
    auto make_ordered_udp_sender(Server& server,std::shared_ptr<rules::RouteProgram const> program,
        std::size_t fallback,bool skip_unknown,std::chrono::milliseconds sniff_timeout) -> shadowsocks::detail::UdpOrderedRouting {
        auto sender=std::make_shared<OrderedUdpSender>(server);
        return sender->routing(std::move(program),fallback,skip_unknown,sniff_timeout);
    }
}
