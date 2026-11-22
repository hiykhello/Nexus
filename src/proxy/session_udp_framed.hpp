// Private framed datagram reader shared by ordinary and FakeIP UDP streams.
#pragma once
        auto uot_read_framed(Session& session,socks5::UdpIngress& ingress,
            pro::proxy<TunnelFacade>& tunnel,socks5::UdpTunnelAuthorization& authorization,net::DatagramFraming framing,
            net::ProxyAddress peer,socks5::UdpPeer const* alias=nullptr,bool const* closing=nullptr,Clock::time_point* touched=nullptr)
            -> capy::task<> {
            using namespace std::chrono_literals;
            auto active=[&] {return !session.closed && (!closing || !*closing);};
            net::DatagramDecoder decoder(framing,peer);
            std::array<std::uint8_t,16384> bytes{};
            while (active()) {
                auto result=co_await tunnel->read(bytes);
                if (!result || !*result) co_return;
                std::size_t offset=0;
                while (offset<*result && active()) {
                    auto fed=decoder.feed(std::span(bytes).subspan(offset,*result-offset));
                    offset+=fed.consumed;
                    if (fed.status==uot::Status::incomplete) break;
                    if (fed.status!=uot::Status::accepted) co_return;
                    auto packet=decoder.packet();
                    if (!packet || packet->destination.family==uot::Family::domain) co_return;
                    socks5::UdpPeer source{packet->destination.family==uot::Family::ipv4 ? std::uint8_t{1} : std::uint8_t{4},
                        {},packet->destination.port};
                    std::copy_n(packet->destination.bytes.begin(),packet->destination.length,source.address.begin());
#ifdef NEXUS_TEST_UOT_WRITE_RACE
                    bool reported_pending=false;
#endif
                    while (active() && authorization.classify(source)==socks5::UdpTunnelReply::pending) {
#ifdef NEXUS_TEST_UOT_WRITE_RACE
                        if (!reported_pending && std::getenv("NEXUS_TEST_UOT_WRITE_RACE")) {
                            std::fputs("uot reply pending\n",stderr);
                            std::fflush(stderr);
                            reported_pending=true;
                        }
#endif
                        auto [error]=co_await io::delay(1ms);
                        if (error) co_return;
                    }
                    if (active() && authorization.accepts(source)) {
                        while (active()) {
                            auto queued=ingress.queue_tunnel_reply(alias ? *alias : source,packet->payload);
                            if (!queued) co_return;
                            if (*queued!=socks5::UdpReplyStatus::busy) {
                                if (touched && *queued==socks5::UdpReplyStatus::queued) *touched=Clock::now();
                                break;
                            }
                            auto [error]=co_await io::delay(1ms);
                            if (error) co_return;
                        }
                    }
                    (void)decoder.consume();
                }
            }
        }
