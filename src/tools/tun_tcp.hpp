// Private TCP bridge included by the TUN owner.
#pragma once
        template<bool IsV6>
        struct TcpChannel {
            static constexpr bool accounts_download=true;
            Impl& host;
            proxy::Session& session;
            tcp::ConnectionId id;
            std::shared_ptr<TcpFlowSlot> slot;
            auto& engine() noexcept { if constexpr (IsV6) return *host.engine6; else return *host.engine4; }
            auto& table() noexcept { if constexpr (IsV6) return *host.table6; else return *host.table4; }

            auto read(std::span<std::uint8_t> out,std::optional<Clock::time_point> deadline={})
                -> nex::capy::task<std::expected<std::size_t,std::string>> {
                while (!host.stop_flag.load(std::memory_order_acquire) && !slot->closed &&
                       (!deadline || Clock::now()<*deadline)) {
                    auto res = engine().read(id, out, now_ms());
                    if (!res) co_return std::unexpected("tun tcp unknown flow");
                    if (res->connection_error) co_return std::unexpected("tun tcp reset");
                    if (res->bytes > 0 || res->eof) co_return res->bytes;
                    slot->changed.clear();
                    if (deadline) {
                        auto [error]=co_await nex::corosio::timeout(slot->changed.wait(),*deadline);
                        if (error) break;
                    } else {
                        auto [error]=co_await slot->changed.wait();
                        if (error) break;
                    }
                }
                co_return std::unexpected("tun tcp closed");
            }

            static auto sniff_client(void* client,sniff::TcpSniffer& sniffer,Clock::time_point deadline)
                -> nex::capy::task<sniff::TcpReadResult> {
                auto& channel=*static_cast<TcpChannel*>(client);
                std::array<std::uint8_t,4096> bytes;
                using Stop=sniff::TcpReadStop;
                for (;;) {
                    auto state=sniffer.limit();
                    if (state.status!=sniff::TcpStatus::need_more) co_return {Stop::classified,state,{}};
                    if (channel.slot->closed || channel.host.stop_flag.load(std::memory_order_acquire))
                        co_return {Stop::canceled,state,{}};
                    if (Clock::now()>=deadline) co_return {Stop::deadline,state,{}};
                    auto amount=std::min(bytes.size(),sniffer.remaining());
                    auto result=channel.engine().read(channel.id,std::span(bytes).first(amount),now_ms());
                    if (!result || result->connection_error) co_return {Stop::io_error,state,{}};
                    if (result->bytes) {
                        (void)sniffer.feed(std::span(bytes).first(result->bytes));
                        continue;
                    }
                    if (result->eof) co_return {Stop::eof,sniffer.finish(),{}};
                    auto& changed=channel.slot->changed;
                    changed.clear();
                    auto [error]=co_await nex::corosio::timeout(changed.wait(),deadline);
                    if (nex::capy::is_timeout(error)) co_return {Stop::deadline,state,error};
                    if (error) co_return {Stop::canceled,state,error};
                }
            }

            auto send(std::span<std::uint8_t const> data,std::optional<Clock::time_point> deadline={})
                -> nex::capy::task<bool> {
                while (!data.empty()) {
                    if (host.stop_flag.load(std::memory_order_acquire) || slot->closed ||
                        (deadline && Clock::now()>=*deadline)) co_return false;
                    auto* conn = table().get(id);
                    if (!conn || conn->state() == tcp::ConnectionState::reset || conn->state() == tcp::ConnectionState::expired)
                        co_return false;
                    auto cap = conn->send_capacity();
                    if (cap > 0) {
                        auto chunk = data.first(std::min(data.size(), cap));
                        if (!conn->enqueue(chunk)) co_return false;
                        session.count_traffic(false,chunk.size());
                        data = data.subspan(chunk.size());
                        (void)engine().transmit(id, now_ms());
                        continue;
                    }
                    slot->changed.clear();
                    if (deadline) {
                        auto [error]=co_await nex::corosio::timeout(slot->changed.wait(),*deadline);
                        if (error) co_return false;
                    } else {
                        auto [error]=co_await slot->changed.wait();
                        if (error) co_return false;
                    }
                }
                co_return true;
            }

            auto close_output() -> nex::capy::task<bool> {
                auto* connection=table().get(id);
                if (!connection || !connection->close_send()) co_return false;
                (void)engine().send_fin(id,now_ms());
                co_return true;
            }

            auto finish() -> nex::capy::task<bool> {
                auto deadline=Clock::now()+std::chrono::seconds(5);
                while (!slot->closed && !host.stop_flag.load(std::memory_order_acquire) && Clock::now()<deadline) {
                    auto* connection=table().get(id);
                    if (!connection || connection->send_closed()) co_return true;
                    if (connection->state()==tcp::ConnectionState::reset ||
                        connection->state()==tcp::ConnectionState::expired) co_return false;
                    slot->changed.clear();
                    auto [error]=co_await nex::corosio::timeout(slot->changed.wait(),deadline);
                    if (error) break;
                }
                co_return false;
            }
        };

#include "tun_tcp_dns.hpp"

        template<bool IsV6>
        auto handle_tcp(tcp::ConnectionId id, std::shared_ptr<TcpFlowSlot> slot) -> nex::capy::task<> {
            struct Guard {
                Impl& host; tcp::ConnectionId id; std::shared_ptr<TcpFlowSlot> slot;
                ~Guard() {
                    slot->closed = true;
                    if constexpr (IsV6) host.tcp6_flows.erase(id); else host.tcp4_flows.erase(id);
                }
            } guard{*this, id, slot};

            auto& tbl = [&]() -> auto& { if constexpr (IsV6) return *table6; else return *table4; }();
            auto& eng = [&]() -> auto& { if constexpr (IsV6) return *engine6; else return *engine4; }();
            auto ep = tbl.endpoints(id);
            auto* conn=tbl.get(id);
            if (!ep || !conn) co_return;
            auto lease_opt = routing.acquire_session();
            if (!lease_opt) { (void)eng.reset(id, now_ms()); co_return; }

            proxy::Session session(routing.executor_context());
            routing.attach_session(session, std::move(*lease_opt));
            socks5::Request req{};
            req.status = socks5::Status::accepted;
            req.port = ep->target.port;
            net::UdpEndpoint src_ep{};
            src_ep.port = ep->source.port;
            if constexpr (IsV6) {
                req.address_type = 4; req.address_length = 16; src_ep.family = 6;
                std::ranges::copy(ep->target.address, req.address.begin());
                src_ep.address = ep->source.address;
            } else {
                req.address_type = 1; req.address_length = 4; src_ep.family = 4;
                std::ranges::copy(ep->target.address, req.address.begin());
                std::ranges::copy(ep->source.address, src_ep.address.begin());
            }
            session.datagram_source=src_ep;
            session.ingress=routing.transparent_metadata(src_ep,conn->initial_dscp());
            session.source_interface=tun->name();
            session.begin_traffic(proxy::TrafficProtocol::tun_tcp,req.port);
            auto const& policy=session.route_snapshot ? session.route_snapshot->matcher : routing.routing_policy();
            TcpChannel<IsV6> ch{*this,session,id,slot};
            std::stop_callback cancel_channel(session.stop.get_token(),[&]() noexcept {
                slot->closed=true;
                slot->changed.set();
            });
            using Result=proxy::OrderedStreamResult;
            auto result=Result::rejected;
            if (session.ordered_tcp) {
                auto dns=cfg.dns_hijack_tcp ? &serve_tcp_dns<IsV6> : nullptr;
                result=co_await proxy::route_ordered_stream_tcp(session,routing.executor_context(),req,&ch,
                    &TcpChannel<IsV6>::sniff_client,dns);
            } else if ((co_await proxy::dial_destination(session,routing.executor_context(),
                           policy,req,src_ep,session.handshake_deadline))==0) {
                result=Result::connected;
            }
            if (result==Result::rejected_drop) {
                session.close();
                co_return;
            }
            if (result==Result::rejected || session.closed) {
                (void)eng.reset(id, now_ms());
                session.close();
                co_return;
            }
            if (result==Result::connected) {
                session.relaying=true;
                session.touched=Clock::now();
                (void)co_await nex::capy::when_all(
                    proxy::stream_relay::direction(session,proxy::stream_relay::upload(session,ch)),
                    proxy::stream_relay::direction(session,proxy::stream_relay::download(session,ch)));
            }
            bool graceful=false;
            if (!session.closed) graceful=co_await ch.finish();
            if (!graceful && tbl.get(id)) (void)eng.reset(id,now_ms());
            session.close();
        }
