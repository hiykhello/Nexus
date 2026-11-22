// Private adapter included by the SOCKS session executor.
#pragma once
#ifdef NEXUS_ENABLE_FAKEIP
        struct UdpFakeIpLease {
            std::unique_ptr<dns::FakeIpShared::Target> target;
            ~UdpFakeIpLease() {
                if (target) try { (void)target->release(); } catch (...) {}
            }
        };

        auto udp_fakeip_target(Session& session,socks5::UdpDatagram const& packet)
            -> std::expected<dns::SharedFakeIpRequest,dns::FakeIpRegistryError> {
            socks5::Request request;
            request.status=socks5::Status::accepted;
            request.address_type=packet.address_type;
            request.address_length=packet.address_length;
            request.address=packet.address;
            request.port=packet.port;
            return dns::translate_fakeip_request(*session.fakeip,request,session.fakeip_view);
        }

        auto udp_fakeip_domain(socks5::UdpDatagram packet,socks5::Request const& request) -> socks5::UdpDatagram {
            packet.address_type=request.address_type;
            packet.address_length=request.address_length;
            packet.address=request.address;
            return packet;
        }

        auto udp_send_alias(Session& session,socks5::UdpIngress& ingress,UdpResolution& resolution,
            socks5::UdpDatagram const& domain,std::span<io::endpoint const> endpoints,
            std::shared_ptr<UdpFakeIpLease> const& lease,rules::RouteMatcher const* legacy,socks5::UdpPeer const& source,
            std::optional<std::size_t> rule={},std::size_t outbound=0)
            -> capy::task<void> {
            for (auto const& endpoint : endpoints) {
                if (endpoint.address().is_v6() && endpoint.address().to_v6().scope_id()) continue;
                socks5::UdpPeer candidate{endpoint.address().is_v4() ? std::uint8_t{1} : std::uint8_t{4},{},endpoint.port()};
                if (candidate.address_type==1) {
                    auto address=endpoint.address().to_v4().to_bytes();
                    std::ranges::copy(address,candidate.address.begin());
                } else {
                    auto address=endpoint.address().to_v6().to_bytes();
                    std::ranges::copy(address,candidate.address.begin());
                }
                auto selected=socks5::UdpSelection{candidate,outbound,rule};
                if (legacy) {
                    auto indexed=socks5::udp_select(*legacy,domain,candidate,&source,session.auth_user);
                    if (!indexed) continue;
                    selected=*indexed;
                }
                while (!session.closed && !resolution.canceled && Clock::now()<resolution.deadline) {
                    auto sent=ingress.send_alias(domain,selected.target,lease,selected.rule,selected.predicate,selected.outbound);
                    if (sent) { session.touched=Clock::now(); co_return; }
                    auto error=std::get_if<std::error_code>(&sent.error());
                    if (!error || (*error!=std::errc::resource_unavailable_try_again && *error!=std::errc::interrupted)) break;
                    auto [delayed]=co_await io::delay(std::chrono::milliseconds(5));
                    if (delayed) session.close();
                }
            }
        }

        auto udp_resolve_alias(Session& session,io::io_context& context,socks5::UdpIngress& ingress,
            UdpResolution& resolution,rules::RouteMatcher const& policy) -> capy::task<void> {
            auto original=ingress.pending_route();
            auto peer=ingress.pending_route_source();
            if (!original || !peer || !session.fakeip) co_return;
            auto lease=std::make_shared<UdpFakeIpLease>();
            auto translated=udp_fakeip_target(session,*original);
            if (!translated || !translated->target) co_return;
            lease->target=std::move(translated->target);
            auto domain=udp_fakeip_domain(*original,translated->request);
            if (!socks5::udp_select_preflight(policy,domain,&*peer,session.auth_user)) co_return;
            resolution={true,false,ingress.route_metadata()->deadline};
            auto source=socks5::udp_endpoint(*peer);
            auto endpoints=co_await resolve_udp_domain(session,context,lease->target->mapping().domain,
                domain.port,resolution.deadline,&source);
            if (endpoints && !session.closed && !resolution.canceled)
                co_await udp_send_alias(session,ingress,resolution,domain,*endpoints,lease,&policy,*peer);
            resolution.active=false;
        }
#endif
