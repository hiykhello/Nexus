// Receive ownership, authentication dispatch, and staged socket binding.
#pragma once
        // A false result permits a retired policy on the same binding to
        // try authentication with its own key or accept a known old session.
        auto handle_datagram(std::size_t index,std::span<std::uint8_t const> wire,UdpPeer remote,bool allow_new,
            std::optional<UdpRequestIdentity> identity={}) -> bool {
            if (stopped_) return false;
            auto now=Clock::now();
            auto timestamp=wall();
            if (!timestamp) return true;
            auto seconds=*timestamp;
            remote.ingress=index;
            auto deadline=now+std::chrono::seconds(10);
            auto policy=policies_.empty() ? nullptr : &policies_[index];
            auto rejected=UdpSessionError::invalid_state;
            UdpListenerAdmission admission{allow_new,&rejected,identity};
            auto pending=sniff_owner_ ? state_.dispatcher_.begin_ordered(state_.key_,wire,remote,now,seconds,deadline,admission) :
                state_.dispatcher_.begin(state_.key_,wire,remote,now,seconds,deadline,policy,admission,ordered_.has_value());
            if (!pending) return rejected!=UdpSessionError::packet && rejected!=UdpSessionError::other_listener_generation;
            struct PendingGuard {
                UdpDispatcher& dispatcher; std::uint64_t token; bool transferred=false;
                ~PendingGuard() { if (!transferred) (void)dispatcher.cancel(token); }
            } guard{state_.dispatcher_,pending->token};
#ifdef NEXUS_TEST_UDP_PENDING
            nexus_test_udp_pending();
#endif
            if(sniff_owner_) {
                auto packet=state_.dispatcher_.pending_packet(pending->token);
                if(!packet)return true;
                auto decision=std::make_shared<OrderedUdpDecision>(*packet,*ordered_->program,
                    policy ? policy->inbound() : std::nullopt,ordered_->skip_unknown,ordered_->fallback,now);
                if(!sniff_owner_->submit(pending->token,std::move(decision),deadline,now))return true;
                guard.transferred=true;drain_ordered();return true;
            }
            auto const& a=pending->address;
            if(a.empty())return true;
            if(a[0]==3) {
                guard.transferred=start_resolution(std::move(*pending),remote,
                    policy ? policy->inbound() : std::nullopt,deadline);
            } else {
                if(a[0]!=1 && a[0]!=4)return true;
                UdpPeer target{};target.family=a[0]==1 ? 4 : 6;
                auto size=target.family==4 ? 4u : 16u;
                if(a.size()!=size+3)return true;
                std::copy_n(a.begin()+1,size,target.address.begin());
                target.port=static_cast<std::uint16_t>((static_cast<unsigned>(a[size+1])<<8)|a[size+2]);
                std::array candidates{target};
                if (ordered_) guard.transferred=send_legacy(pending->token,candidates,policy ? policy->inbound() : std::nullopt,deadline).has_value();
                else (void)state_.dispatcher_.complete(pending->token,candidates,now);
            }
            return true;
        }
        auto receive(std::size_t index) -> udp_capy::task<> {
            std::array<std::uint8_t,65536> buffer{};
            auto const& cancellation=receive_stops_[index];
            while (!cancellation.stop_requested() && ingress_ && ingress_->generation()<generation_) {
                auto [error]=co_await udp_io::delay(std::chrono::milliseconds(2));
                if (error && !cancellation.stop_requested()) {stop();co_return;}
            }
            while (!cancellation.stop_requested()) {
                if (ingress_) {
                    auto [error]=co_await sockets_[index]->wait(udp_io::wait_type::read);
                    if (cancellation.stop_requested()) break;
                    if (error) {stop();break;}
                    // Ready-only burst drain (up to 16 already-queued datagrams per wakeup).
                    for (unsigned burst=0;burst<16 && !cancellation.stop_requested();++burst) {
                        auto packet=UdpListenerIngress::read(sockets_[index]->native_handle(),buffer);
                        if (!packet) {stop();co_return;}
                        if (!*packet) break;
                        auto const& datagram=**packet;
                        ingress_->route(endpoints_[index],generation_,std::span(buffer).first(datagram.size),datagram.source);
                    }
                    continue;
                }
                udp_io::endpoint source;
                auto [error,n]=co_await sockets_[index]->recv_from(udp_capy::mutable_buffer(buffer.data(),buffer.size()),source);
                if (cancellation.stop_requested()) break;
                if (error) {stop();break;}
                auto remote=peer(source);
                if (remote && n<=65535) (void)handle_datagram(index,std::span(buffer).first(n),*remote,true);
            }
        }

        [[nodiscard]] auto identity_route(std::size_t index) const noexcept -> UdpIdentityRoute const* {
            return identities_.empty() || !identities_[index] ? nullptr : &*identities_[index];
        }

        auto bind_socket(udp_io::udp_socket& socket,udp_io::endpoint endpoint,bool share) -> std::expected<bool,std::error_code> {
            if (ingress_) {
                auto duplicate=ingress_->duplicate(endpoint,generation_,share);
                if (!duplicate) return std::unexpected(duplicate.error());
                if (duplicate->fd>=0) {
                    if (auto error=socket.assign(duplicate->fd)) {
                        ::close(duplicate->fd);
                        return std::unexpected(error);
                    }
                    return duplicate->receive;
                }
            }
            if (auto error=socket.open(endpoint.address().family())) return std::unexpected(error);
            if (auto error=socket.bind(endpoint)) return std::unexpected(error);
            return true;
        }

        auto register_ingress() -> void {
            if (!ingress_) return;
            for (std::size_t index=0;index<sockets_.size();++index)
                ingress_->add(endpoints_[index],generation_,sockets_[index]->native_handle(),this,index,identity_route(index),
                    [](void* owner,std::size_t slot,std::span<std::uint8_t const> wire,UdpPeer source,bool allow_new,
                       std::optional<UdpRequestIdentity> identity) {
                        return static_cast<BasicUdpListener*>(owner)->handle_datagram(slot,wire,source,allow_new,identity);
                    },
                    [](void* owner,std::size_t slot) noexcept {
                        static_cast<BasicUdpListener*>(owner)->receive_stops_[slot].request_stop();
                    });
        }

