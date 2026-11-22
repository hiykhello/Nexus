import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.crypto;
import wireguard.cookie;
import wireguard.endpoint;
import wireguard.registry;
import wireguard.port_types;
import wireguard.port;

namespace {
    using namespace wireguard;
    using namespace std::chrono_literals;
    struct BlockWrites {
        static inline unsigned calls=0;
        static auto before_send(std::optional<PeerHandle>,OutboundKind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> {
            ++calls; return std::make_error_code(std::errc::resource_unavailable_try_again);
        }
    };
    struct BlockCookie {
        static inline bool blocked=false,hard_error=false;
        static inline unsigned calls=0;
        static auto before_send(std::optional<PeerHandle>,OutboundKind kind,std::span<std::uint8_t const>) noexcept -> std::optional<std::error_code> {
            if(kind==OutboundKind::cookie) { ++calls; if(hard_error)return std::make_error_code(std::errc::network_unreachable); if(blocked)return std::make_error_code(std::errc::resource_unavailable_try_again); }
            return {};
        }
    };
    using Port=UdpPort<2,2,256,4,BlockWrites>;
    auto bytes(unsigned first) -> Key { Key result; for (std::size_t i=0;i<32;++i) result[i]=static_cast<std::uint8_t>(first+i); return result; }
    auto public_key(unsigned first) -> Key {
        auto local=::crypto::X25519Private::from_bytes(bytes(first)); if (!local) std::terminate();
        auto result=local->public_key(); if (!result) std::terminate(); return *result;
    }
    auto loopback(bool ipv6,std::uint16_t port=0) -> EndpointAddress {
        EndpointAddress result{ipv6 ? std::uint8_t{6} : std::uint8_t{4},{},port};
        if (ipv6) result.address[15]=1; else { result.address[0]=127; result.address[3]=1; } return result;
    }
    auto prefix(unsigned node) -> AllowedPrefix { return {4,{10,42,0,static_cast<std::uint8_t>(node)},32}; }
    auto config(unsigned node) -> EndpointConfig {
        EndpointConfig result; result.peer_public=public_key(node*32); result.peer=loopback(false,static_cast<std::uint16_t>(10000+node));
        result.allowed_ips={prefix(node)}; result.mtu=128; return result;
    }
    auto packet(unsigned node) -> std::array<std::uint8_t,24> { return {0x45,0,0,24,0,0,0,0,64,253,0,0,10,42,0,9,10,42,0,static_cast<std::uint8_t>(node),1,2,3,4}; }
    auto socket_bind_and_actual_dual_receive() -> bool {
        net::UdpSocket receiver;
        EndpointAddress bad{3,{},0};
        auto invalid=receiver.bind(bad);
        if (invalid || invalid.error()!=std::errc::invalid_argument || receiver.native_handle()!=-1) return false;
        bad=loopback(false); bad.address[4]=1; invalid=receiver.bind(bad);
        if (invalid || invalid.error()!=std::errc::invalid_argument || receiver.native_handle()!=-1) return false;
        if (!receiver.open() || receiver.native_handle()<0) return false;
        auto unbound=receiver.local_endpoint(); if (unbound || unbound.error()!=std::errc::not_connected) return false;
        EndpointAddress any{6,{},0};
        if (!receiver.bind(any)) return false;
        auto bound=receiver.local_endpoint(); if (!bound || bound->family!=6 || !bound->port || std::ranges::any_of(bound->address,[](auto c) { return c!=0; })) return false;
        auto duplicate=receiver.bind(any);
        if (duplicate || duplicate.error()!=std::errc::address_in_use || receiver.local_endpoint()!=bound) return false;
        for (bool ipv6:{false,true}) {
            net::UdpSocket sender;
            if (!sender.bind(loopback(ipv6))) return false;
            auto source=sender.local_endpoint(); if (!source || source->family!=(ipv6 ? 6 : 4) || !source->port) return false;
            std::array<std::uint8_t,5> payload{1,2,3,4,static_cast<std::uint8_t>(ipv6)};
            if (!sender.send(loopback(ipv6,bound->port),payload)) return false;
            bool got=false; std::array<std::uint8_t,64> input{};
            for (unsigned attempt=0;attempt<100 && !got;++attempt) {
                auto received=receiver.receive(input); if (!received) return false;
                if (*received) {
                    auto const& datagram=**received;
                    if (!datagram.valid || datagram.source!=*source || datagram.size!=payload.size() || !std::ranges::equal(std::span(input).first(datagram.size),payload)) return false;
                    got=true;
                } else std::this_thread::sleep_for(1ms);
            }
            if (!got) return false;
        }
        net::UdpSocket conflict;
        auto busy=conflict.bind(*bound);
        if (busy || busy.error()!=std::errc::address_in_use || conflict.local_endpoint()) return false;
        receiver.close();
        if (receiver.native_handle()!=-1 || receiver.local_endpoint() || receiver.bind(any) || receiver.receive({})) return false;
        if (!conflict.bind(*bound) || conflict.local_endpoint()!=bound) return false;
        conflict.close(); return conflict.native_handle()==-1;
    }
    auto staged_two_peers_and_stop() -> bool {
        PortOptions options; options.business_packets=2; options.business_bytes=256;
        auto port=Port::create(bytes(0),options); auto now=Clock::time_point(10s); auto wall=std::chrono::system_clock::now();
        if (!port || port->add_peer(config(1)) || !port->open(loopback(false),now) || port->open(loopback(false),now)) return false;
        auto a=port->add_peer(config(1)),b=port->add_peer(config(2));
        if (!a || !b || port->add_peer(config(3)) || !port->assign_route(*a,prefix(1)) || !port->assign_route(*b,prefix(2))) return false;
        if (!port->enqueue_ip(packet(1),now) || !port->enqueue_ip(packet(2),now)) return false;
        auto full=port->enqueue_ip(packet(1),now);
        if (full || full.error().code!=PortError::queue_full || port->status().business_packets!=2 || port->status().business_bytes!=48) return false;
        auto polled=port->poll(now,wall);
        if (!polled || !polled->write_blocked || polled->sent || polled->next_poll<=now) return false;
        auto pending=port->status();
        if (pending.registry.peers!=2 || pending.registry.indexes!=2 || pending.registry.reservations || pending.pending_sends!=2 || pending.business_packets!=2) return false;
        // A policy change discards all accepted business packets, including B.
        if (!port->erase_peer(*a) || port->valid(*a) || port->peer_status(*a) || port->status().pending_sends!=1 || port->status().business_packets || port->status().routes!=1) return false;
        auto replacement=port->add_peer(config(1));
        if (!replacement || replacement->slot!=a->slot || replacement->generation==a->generation || port->erase_peer(*a) || port->assign_route(*a,prefix(1)) || !port->assign_route(*replacement,prefix(1))) return false;
        if (!port->enqueue_ip(packet(1),now+1ms)) return false;
        polled=port->poll(now+1ms,wall+1ms);
        if (!polled || !polled->write_blocked || port->status().pending_sends!=2 || port->status().registry.indexes!=2) return false;
        auto reverse=port->poll(now,wall);
        if (reverse || reverse.error().code!=PortError::clock || port->status().pending_sends!=2) return false;
        port->stop();
        if (!port->drained() || port->native_handle()!=-1 || port->local_endpoint() || port->valid(*b) || port->enqueue_ip(packet(1),now+2ms)) return false;
        auto stopped=port->poll(now+2ms,wall+2ms);
        return !stopped && stopped.error().code==PortError::closed;
    }
    auto deadline_closes_pending_outputs() -> bool {
        auto port=Port::create(bytes(0)); auto now=Clock::time_point(10s); auto wall=std::chrono::system_clock::now();
        if (!port || !port->open(loopback(true),now,now+1s)) return false;
        auto peer=port->add_peer(config(1));
        if (!peer || !port->assign_route(*peer,prefix(1)) || !port->enqueue_ip(packet(1),now)) return false;
        auto polled=port->poll(now,wall);
        if (!polled || !polled->write_blocked || port->status().pending_sends!=1 || polled->next_poll>now+1s) return false;
        auto expired=port->poll(now+1s,wall+1s);
        return !expired && expired.error().code==PortError::timeout && port->drained() && port->native_handle()==-1 && !port->status().registry.reservations;
    }
    auto endpoint_inplace_failure_preserves_target() -> bool {
        std::optional<Endpoint> endpoint;
        auto identity=::crypto::X25519Private::from_bytes(bytes(0)); if (!identity) return false;
        auto bad=config(1); bad.mtu=67;
        if (Endpoint::emplace_into(endpoint,std::move(*identity),std::move(bad)) || endpoint) return false;
        identity=::crypto::X25519Private::from_bytes(bytes(0));
        if (!identity || !Endpoint::emplace_into(endpoint,std::move(*identity),config(1)) || !endpoint) return false;
        auto before=endpoint->status(); identity=::crypto::X25519Private::from_bytes(bytes(0));
        auto occupied=Endpoint::emplace_into(endpoint,std::move(*identity),config(2));
        return !occupied && endpoint->status().peer==before.peer && endpoint->status().latest_attempt==before.latest_attempt && !endpoint->status().indexes;
    }
    auto cookie_rate_over_real_udp(bool ipv6) -> bool {
        using LivePort=UdpPort<2,4,256,4>;
        PortOptions options;options.require_cookie=true;
        auto port=LivePort::create(bytes(0),options);auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        net::UdpSocket sender,other_sender;
        if(!port || !port->open(loopback(ipv6),now) || !sender.bind(loopback(ipv6)) || !other_sender.bind(loopback(ipv6)))return false;
        auto destination=port->local_endpoint();if(!destination)return false;
        auto generator=CookieGenerator::create(public_key(0)),other_generator=CookieGenerator::create(public_key(0));if(!generator || !other_generator)return false;
        std::array<std::uint8_t,response_size> wire{},other_wire{};wire[0]=other_wire[0]=2;wire[4]=1;other_wire[4]=2;
        auto receive_packet=[&](Clock::time_point at) -> bool {
            auto previous=port->status().metrics.received;
            for(unsigned retry=0;retry<100;++retry) {
                if(!port->poll(at,wall+(at-now)))return false;
                if(port->status().metrics.received>previous)return true;
                std::this_thread::sleep_for(1ms);
            }
            return false;
        };
        auto acquire=[&](auto& socket,auto& cookie,auto& packet) -> bool {
            if(!cookie.apply(packet,now) || !socket.send(*destination,packet) || !receive_packet(now))return false;
            std::array<std::uint8_t,256> buffer{};
            for(unsigned retry=0;retry<100;++retry) {
                auto received=socket.receive(buffer);if(!received)return false;
                if(*received) {
                    auto const& item=**received;
                    return item.valid && item.size==cookie_size && cookie.consume(std::span(buffer).first(item.size),now) && cookie.apply(packet,now);
                }
                std::this_thread::sleep_for(1ms);
            }
            return false;
        };
        if(!acquire(sender,*generator,wire) || !acquire(other_sender,*other_generator,other_wire))return false;
        for(unsigned count=0;count<6;++count) {
            auto& socket=count%2 ? other_sender : sender;auto& packet=count%2 ? other_wire : wire;
            if(!socket.send(*destination,packet) || !receive_packet(now))return false;
            if(port->status().metrics.rate_limit_rejects!=(count==5 ? 1u : 0u))return false;
        }
        if(!sender.send(*destination,wire) || !receive_packet(now+50ms))return false;
        auto status=port->status();if(status.metrics.rate_limit_rejects!=1 || status.metrics.received!=9)return false;
        port->stop();return port->drained();
    }
    auto cookie_hard_error_and_rotation() -> bool {
        using LivePort=UdpPort<2,4,256,4,BlockCookie>;
        PortOptions options;options.require_cookie=true;
        auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        auto port=LivePort::create(bytes(0),options);net::UdpSocket first;
        if(!port || !port->open(loopback(false),now) || !first.bind(loopback(false)))return false;
        auto target=port->local_endpoint();auto generator=CookieGenerator::create(public_key(0));
        if(!target || !generator)return false;
        std::array<std::uint8_t,response_size> wire{};wire[0]=2;wire[4]=1;
        if(!generator->apply(wire,now) || !first.send(*target,wire))return false;
        BlockCookie::calls=0;BlockCookie::hard_error=true;
        auto failed=port->poll(now,wall);BlockCookie::hard_error=false;
        if(!failed || failed->write_blocked || !failed->send_error || BlockCookie::calls!=1 || port->status().pending_sends || port->status().metrics.send_errors!=1)return false;
        auto near=now+cookie_refresh_time-1s;
        if(!generator->apply(wire,near) || !first.send(*target,wire))return false;
        BlockCookie::blocked=true;auto held=port->poll(near,wall+(near-now));
        if(!held || !held->write_blocked || port->status().pending_sends!=1)return false;
        auto calls=BlockCookie::calls;
        auto rotated=port->poll(now+cookie_refresh_time,wall+cookie_refresh_time);
        BlockCookie::blocked=false;
        if(!rotated || rotated->write_blocked || port->status().pending_sends || BlockCookie::calls!=calls)return false;
        port->stop();return port->drained();
    }
    auto batched_cookie_replies(bool ipv6,bool block_first,bool stop_blocked=false,bool expire=false) -> bool {
        using LivePort=UdpPort<2,4,256,4,BlockCookie>;
        PortOptions options;options.require_cookie=true;
        auto port=LivePort::create(bytes(0),options);auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        net::UdpSocket first,second;
        if(!port || !port->open(loopback(ipv6),now) || !first.bind(loopback(ipv6)) || !second.bind(loopback(ipv6)))return false;
        auto target=port->local_endpoint();if(!target)return false;
        auto a=CookieGenerator::create(public_key(0)),b=CookieGenerator::create(public_key(0));if(!a || !b)return false;
        std::array<std::uint8_t,response_size> wa{},wb{};wa[0]=wb[0]=2;wa[4]=1;wb[4]=2;
        if(!a->apply(wa,now) || !b->apply(wb,now) || !first.send(*target,wa) || !second.send(*target,wb))return false;
        BlockCookie::blocked=block_first;
        auto first_step=port->poll(now,wall);if(!first_step)return false;
        if(!block_first && first_step->received!=2)return false;
        if(block_first && (first_step->received!=2 || !first_step->write_blocked || first_step->read_paused || port->status().pending_sends!=1 || port->status().metrics.dropped!=1))return false;
        if(stop_blocked) {port->stop();BlockCookie::blocked=false;return port->drained() && port->native_handle()==-1;}
        if(expire) {
            auto before=port->poll(now+4999ms,wall+4999ms);
            if(!before || !before->write_blocked || port->status().pending_sends!=1 || before->next_poll>now+5s)return false;
            auto after=port->poll(now+5s,wall+5s);
            if(!after || port->status().pending_sends || after->write_blocked)return false;
        }
        BlockCookie::blocked=false;
        bool first_delivered=false,second_delivered=false;
        if(block_first && !expire) {
            if(!port->poll(now,wall))return false;
            std::array<std::uint8_t,256> input{};
            auto x=first.receive(input);if(!x)return false;
            if(*x) first_delivered=(**x).valid && (**x).size==cookie_size && a->consume(std::span(input).first((**x).size),now).has_value();
            auto y=second.receive(input);if(!y)return false;
            if(*y) second_delivered=(**y).valid && (**y).size==cookie_size && b->consume(std::span(input).first((**y).size),now).has_value();
            if(first_delivered==second_delivered)return false;
        }
        if(block_first) {
            auto retry=expire ? now+5s : now;
            if(first_delivered || expire) {if(!b->apply(wb,retry) || !second.send(*target,wb))return false;}
            else {if(!a->apply(wa,retry) || !first.send(*target,wa))return false;}
        }
        auto at=expire ? now+5s : now;
        auto expected_sent=expire ? 1u : 2u;
        for(unsigned i=0;i<100 && port->status().metrics.sent<expected_sent;++i) {
            if(!port->poll(at,wall+(at-now)))return false;
            std::this_thread::sleep_for(1ms);
        }
        if(port->status().metrics.received!=(block_first ? 3u : 2u) || port->status().metrics.sent!=expected_sent || port->status().pending_sends)return false;
        auto receive=[&](auto& socket,auto& generator) -> bool {
            std::array<std::uint8_t,256> buffer{};
            for(unsigned i=0;i<100;++i) {
                auto datagram=socket.receive(buffer);if(!datagram)return false;
                if(*datagram) {
                    auto const& packet=**datagram;
                    return packet.valid && packet.size==cookie_size && generator.consume(std::span(buffer).first(packet.size),at).has_value();
                }
                std::this_thread::sleep_for(1ms);
            }
            return false;
        };
        if(!expire && !first_delivered && !receive(first,*a))return false;
        if(!second_delivered && !receive(second,*b))return false;
        if(expire) { std::array<std::uint8_t,256> buffer{};auto empty=first.receive(buffer);if(!empty || *empty)return false; }
        port->stop();return port->drained();
    }
    auto handshake_pressure_boundaries() -> bool {
        port_detail::HandshakePressure pressure;auto now=Clock::time_point(10s);
        for(unsigned i=0;i<32;++i)if(pressure.observe(now))return false;
        if(!pressure.observe(now) || !pressure.active(now+999ms) || pressure.active(now+1s))return false;
        if(pressure.observe(now+1s))return false;
        // Clock rollback cannot reset or refill the bucket.
        if(pressure.observe(now+999ms))return false;
        for(unsigned i=0;i<31;++i)if(pressure.observe(now+1s))return false;
        if(!pressure.observe(now+1s))return false;
        // A fresh excess extends the hold; a burst that only consumes refilled
        // tokens cannot prematurely cancel the existing hold.
        for(unsigned i=0;i<16;++i)if(!pressure.observe(now+1500ms))return false;
        if(!pressure.observe(now+1500ms) || !pressure.active(now+2499ms) || pressure.active(now+2500ms))return false;
        port_detail::HandshakePressure saturated;
        auto near_max=Clock::time_point::max()-500ms;
        for(unsigned i=0;i<32;++i)if(saturated.observe(near_max))return false;
        if(!saturated.observe(near_max) || !saturated.active(Clock::time_point::max()-Clock::duration(1)) || saturated.active(Clock::time_point::max()))return false;
        return true;
    }
    auto permanent_cookie_with_automatic(bool ipv6,bool automatic) -> bool {
        using LivePort=UdpPort<2,4,256,4>;
        PortOptions options;options.require_cookie=true;options.auto_cookie=automatic;
        auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        auto port=LivePort::create(bytes(0),options);net::UdpSocket sender;
        if(!port || !port->open(loopback(ipv6),now) || !sender.bind(loopback(ipv6)))return false;
        auto target=port->local_endpoint();auto generator=CookieGenerator::create(public_key(0));
        if(!target || !generator)return false;
        std::array<std::uint8_t,response_size> wire{};wire[0]=2;wire[4]=1;
        if(!generator->apply(wire,now) || !sender.send(*target,wire))return false;
        auto first=port->poll(now,wall);
        if(!first || first->sent!=1 || port->status().automatic_cookie_active)return false;
        std::array<std::uint8_t,256> input{};auto reply=sender.receive(input);
        if(!reply || !*reply || (**reply).size!=cookie_size || !generator->consume(std::span(input).first((**reply).size),now))return false;
        // Protection remains required after the automatic pressure bucket is idle.
        auto later=now+2s;
        wire[4]=2;
        if(!generator->apply(wire,later))return false;
        std::fill(wire.end()-16,wire.end(),0);
        if(!sender.send(*target,wire))return false;
        auto second=port->poll(later,wall+2s);
        if(!second || second->sent!=1 || port->status().automatic_cookie_active)return false;
        port->stop();return port->drained() && !port->status().automatic_cookie_active;
    }
    auto automatic_pending_reply(bool ipv6) -> bool {
        using LivePort=UdpPort<2,4,256,4,BlockCookie>;
        PortOptions options;options.auto_cookie=true;
        auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        auto port=LivePort::create(bytes(0),options);net::UdpSocket flood,first,second;
        if(!port || !port->open(loopback(ipv6),now) || !flood.bind(loopback(ipv6)) || !first.bind(loopback(ipv6)) || !second.bind(loopback(ipv6)))return false;
        auto target=port->local_endpoint();auto a=CookieGenerator::create(public_key(0)),b=CookieGenerator::create(public_key(0));
        if(!target || !a || !b)return false;
        std::array<std::uint8_t,response_size> spoof{},wa{},wb{};spoof[0]=wa[0]=wb[0]=2;wa[4]=1;wb[4]=2;
        // Invalid MAC1, but a structurally correct spoofed packet, can activate protection.
        for(unsigned i=0;i<33;++i) {if(!flood.send(*target,spoof) || !port->poll(now,wall))return false;}
        if(!port->status().automatic_cookie_active || !a->apply(wa,now) || !b->apply(wb,now))return false;
        BlockCookie::blocked=true;
        if(!first.send(*target,wa) || !second.send(*target,wb))return false;
        auto step=port->poll(now,wall);
        if(!step || step->received!=2 || !step->write_blocked || step->read_paused || port->status().pending_sends!=1)return false;
        port->stop();BlockCookie::blocked=false;
        return port->drained() && !port->status().automatic_cookie_active;
    }
    auto automatic_valid_mac2_direction(bool ipv6,bool initiation) -> bool {
        using LivePort=UdpPort<2,4,256,4>;
        PortOptions options;options.auto_cookie=true;
        auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        auto port=LivePort::create(bytes(0),options);net::UdpSocket sender;
        if(!port || !port->open(loopback(ipv6),now) || !sender.bind(loopback(ipv6)))return false;
        auto target=port->local_endpoint();auto generator=CookieGenerator::create(public_key(0));
        if(!target || !generator)return false;
        std::array<std::uint8_t,response_size> spoof{};spoof[0]=2;
        for(unsigned i=0;i<33;++i) { if(!sender.send(*target,spoof) || !port->poll(now,wall))return false; }
        if(!port->status().automatic_cookie_active)return false;
        std::array<std::uint8_t,initiation_size> bytes{};bytes[0]=initiation ? 1 : 2;bytes[4]=7;
        auto wire=std::span(bytes).first(initiation ? initiation_size : response_size);
        if(!generator->apply(wire,now) || !sender.send(*target,wire))return false;
        auto challenge=port->poll(now,wall);
        if(!challenge || challenge->sent!=1)return false;
        std::array<std::uint8_t,256> input{};auto reply=sender.receive(input);
        if(!reply || !*reply || !(**reply).valid || (**reply).size!=cookie_size ||
           !generator->consume(std::span(input).first((**reply).size),now) || !generator->apply(wire,now))return false;
        auto sent_before=port->status().metrics.sent;
        for(unsigned i=0;i<6;++i) { if(!sender.send(*target,wire) || !port->poll(now,wall))return false; }
        auto status=port->status();
        // These synthetic packets lack a real Noise handshake. The shared
        // quota can be consumed only after MAC2 succeeds, before Noise/lookup.
        if(status.metrics.rate_limit_rejects!=1 || status.metrics.sent!=sent_before || !status.automatic_cookie_active)return false;
        port->stop();return port->drained() && !port->status().automatic_cookie_active;
    }
    auto automatic_cookie_over_real_udp(bool ipv6,bool enabled=true) -> bool {
        using LivePort=UdpPort<2,4,256,4>;
        PortOptions options;options.auto_cookie=enabled;
        auto port=LivePort::create(bytes(0),options);auto now=Clock::time_point(10s);auto wall=std::chrono::system_clock::now();
        net::UdpSocket sender;if(!port || !port->open(loopback(ipv6),now) || !sender.bind(loopback(ipv6)))return false;
        auto destination=port->local_endpoint();if(!destination)return false;
        auto send_and_poll=[&](std::span<std::uint8_t const> wire,Clock::time_point at) -> bool {
            auto previous=port->status().metrics.received;if(!sender.send(*destination,wire))return false;
            for(unsigned retry=0;retry<100;++retry) {
                if(!port->poll(at,wall+(at-now)))return false;
                if(port->status().metrics.received>previous)return true;
                std::this_thread::sleep_for(1ms);
            }
            return false;
        };
        std::array<std::uint8_t,4> malformed{};malformed[0]=2;
        for(unsigned i=0;i<40;++i)if(!send_and_poll(malformed,now) || port->status().automatic_cookie_active)return false;
        std::array<std::uint8_t,transport_overhead> data{};data[0]=4;
        for(unsigned i=0;i<80;++i)if(!send_and_poll(data,now) || port->status().automatic_cookie_active)return false;
        std::array<std::uint8_t,response_size> wire{};wire[0]=2;wire[4]=1;
        for(unsigned i=0;i<32;++i)if(!send_and_poll(wire,now) || port->status().automatic_cookie_active)return false;
        if(!enabled) {
            for(unsigned i=0;i<40;++i)if(!send_and_poll(wire,now) || port->status().automatic_cookie_active)return false;
            port->stop();return port->drained();
        }
        if(!send_and_poll(wire,now) || !port->status().automatic_cookie_active)return false;
        auto cookie=CookieGenerator::create(public_key(0));if(!cookie || !cookie->apply(wire,now) || !send_and_poll(wire,now))return false;
        std::array<std::uint8_t,256> buffer{};bool consumed=false;
        for(unsigned retry=0;retry<100 && !consumed;++retry) {
            auto received=sender.receive(buffer);if(!received)return false;
            if(*received) {
                auto const& item=**received;
                if(!item.valid || item.size!=cookie_size || !cookie->consume(std::span(buffer).first(item.size),now))return false;
                consumed=true;
            } else std::this_thread::sleep_for(1ms);
        }
        if(!consumed || !cookie->apply(wire,now))return false;
        for(unsigned i=0;i<6;++i)if(!send_and_poll(wire,now))return false;
        if(port->status().metrics.rate_limit_rejects!=1 || !port->status().automatic_cookie_active)return false;
        // At exactly one second, a single new handshake no longer encounters
        // automatic protection; there is no permanently latched load state.
        if(!send_and_poll(wire,now+1s) || port->status().automatic_cookie_active)return false;
        port->stop();return port->drained() && !port->status().automatic_cookie_active;
    }
}

auto main() -> int {
    if (!socket_bind_and_actual_dual_receive()) { std::println("WireGuard real UDP bind/fixed port/dual receive boundary failed"); return 1; }
    if (!staged_two_peers_and_stop()) { std::println("WireGuard port fixed queues/two peers/EAGAIN/delete/stop failed"); return 2; }
    if (!deadline_closes_pending_outputs()) { std::println("WireGuard port deadline pending output drain failed"); return 3; }
    if (!endpoint_inplace_failure_preserves_target()) { std::println("WireGuard Endpoint in-place factory rollback failed"); return 4; }
    if (!cookie_rate_over_real_udp(false) || !cookie_rate_over_real_udp(true)) { std::println("WireGuard real UDP cookie rate limiter failed"); return 5; }
    if (!cookie_hard_error_and_rotation()) { std::println("WireGuard cookie hard error/rotation failed"); return 7; }
    if (!batched_cookie_replies(false,false) || !batched_cookie_replies(true,false) || !batched_cookie_replies(false,true) ||
        !batched_cookie_replies(true,true) || !batched_cookie_replies(false,true,true) || !batched_cookie_replies(false,true,false,true) || !batched_cookie_replies(true,true,false,true)) { std::println("WireGuard batched cookie reply fairness failed"); return 6; }
    if (!handshake_pressure_boundaries()) { std::println("WireGuard handshake pressure boundaries failed"); return 8; }
    if (!permanent_cookie_with_automatic(false,false) || !permanent_cookie_with_automatic(true,false) || !permanent_cookie_with_automatic(false,true) || !permanent_cookie_with_automatic(true,true) || !automatic_pending_reply(false) || !automatic_pending_reply(true)) { std::println("WireGuard static/automatic cookie pending interaction failed"); return 10; }
    if (!automatic_valid_mac2_direction(false,false) || !automatic_valid_mac2_direction(false,true) || !automatic_valid_mac2_direction(true,false) || !automatic_valid_mac2_direction(true,true)) { std::println("WireGuard automatic MAC2 direction quota failed"); return 11; }
    if (!automatic_cookie_over_real_udp(false) || !automatic_cookie_over_real_udp(true) || !automatic_cookie_over_real_udp(false,false) || !automatic_cookie_over_real_udp(true,false)) { std::println("WireGuard automatic cookie load gate failed"); return 9; }
    std::println("WireGuard one UDP socket, fixed two-peer output/queue bounds, generation deletion, pending send deadline/stop and direct endpoint construction passed; sizeof default port={} two-peer test port={}",sizeof(UdpPort<>),sizeof(Port));
}
