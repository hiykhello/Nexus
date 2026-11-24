// TCP channel and flow handler for the routed TUN host.
export module cli.tun_tcp;
import std;
import capy;
import corosio;
import cli.tun_owner_lookup;
import cli.tun_tcp_dns;
import net.udp_dial;
import packet.tun_linux;
import relay;
import relay.stream_relay;
import rules;
import sniff.route_tcp;
import sniff.tcp;
import sniff.tcp_io;
import socks5;
import tcp.connection;
import tcp.engine;
import tcp.table;

export namespace cli::tun_enabled {
    template<class Impl, bool IsV6>
    struct TcpChannel {
        using Clock = std::chrono::steady_clock;
        static constexpr bool accounts_download = true;
        Impl& host;
        relay::Session& session;
        tcp::ConnectionId id;
        std::shared_ptr<typename Impl::TcpFlowSlot> slot;
        auto& engine() noexcept { if constexpr (IsV6) return *host.engine6; else return *host.engine4; }
        auto& table() noexcept { if constexpr (IsV6) return *host.table6; else return *host.table4; }

        auto read(std::span<std::uint8_t> out, std::optional<Clock::time_point> deadline = {})
            -> capy::task<std::expected<std::size_t, std::string>> {
            while (!host.stop_flag.load(std::memory_order_acquire) && !slot->closed &&
                   (!deadline || Clock::now() < *deadline)) {
                auto res = engine().read(id, out, now_ms());
                if (!res) co_return std::unexpected("tun tcp unknown flow");
                if (res->connection_error) co_return std::unexpected("tun tcp reset");
                if (res->bytes > 0 || res->eof) co_return res->bytes;
                slot->read_changed.clear();
                if (deadline) {
                    auto [error] = co_await corosio::timeout(slot->read_changed.wait(), *deadline);
                    if (error) break;
                } else {
                    auto [error] = co_await slot->read_changed.wait();
                    if (error) break;
                }
            }
            co_return std::unexpected("tun tcp closed");
        }

        static auto sniff_client(void* client, sniff::TcpSniffer& sniffer, Clock::time_point deadline)
            -> capy::task<sniff::TcpReadResult> {
            auto& channel = *static_cast<TcpChannel*>(client);
            std::array<std::uint8_t, 4096> bytes;
            using Stop = sniff::TcpReadStop;
            for (;;) {
                auto state = sniffer.limit();
                if (state.status != sniff::TcpStatus::need_more) co_return {Stop::classified, state, {}};
                if (channel.slot->closed || channel.host.stop_flag.load(std::memory_order_acquire))
                    co_return {Stop::canceled, state, {}};
                if (Clock::now() >= deadline) co_return {Stop::deadline, state, {}};
                auto amount = std::min(bytes.size(), sniffer.remaining());
                auto result = channel.engine().read(channel.id, std::span(bytes).first(amount), now_ms());
                if (!result || result->connection_error) co_return {Stop::io_error, state, {}};
                if (result->bytes) {
                    (void)sniffer.feed(std::span(bytes).first(result->bytes));
                    continue;
                }
                if (result->eof) co_return {Stop::eof, sniffer.finish(), {}};
                auto& changed = channel.slot->read_changed;
                changed.clear();
                auto [error] = co_await corosio::timeout(changed.wait(), deadline);
                if (capy::is_timeout(error)) co_return {Stop::deadline, state, error};
                if (error) co_return {Stop::canceled, state, error};
            }
        }

        auto send(std::span<std::uint8_t const> data, std::optional<Clock::time_point> deadline = {})
            -> capy::task<bool> {
            bool need_notify = false;
            auto flush_notify = [&]() noexcept {
                if (need_notify) { need_notify = false; host.notify_tx(); }
            };
            auto now = now_ms();
            while (!data.empty()) {
                if (host.stop_flag.load(std::memory_order_acquire) || slot->closed ||
                    (deadline && Clock::now() >= *deadline)) { flush_notify(); co_return false; }
                auto* conn = table().get(id);
                if (!conn || conn->state() == tcp::ConnectionState::reset || conn->state() == tcp::ConnectionState::expired) {
                    flush_notify();
                    co_return false;
                }
                auto cap = conn->send_capacity();
                if (cap > 0) {
                    auto chunk = data.first(std::min(data.size(), cap));
                    if (!conn->enqueue(chunk)) { flush_notify(); co_return false; }
                    session.count_traffic(false, chunk.size());
                    data = data.subspan(chunk.size());
                    if (engine().transmit(id, now)) need_notify = true;
                    continue;
                }
                flush_notify();
                slot->write_changed.clear();
                if (deadline) {
                    auto [error] = co_await corosio::timeout(slot->write_changed.wait(), *deadline);
                    if (error) co_return false;
                } else {
                    auto [error] = co_await slot->write_changed.wait();
                    if (error) co_return false;
                }
                now = now_ms();
            }
            flush_notify();
            co_return true;
        }

        auto close_output() -> capy::task<bool> {
            auto* connection = table().get(id);
            if (!connection || !connection->close_send()) co_return false;
            if (engine().send_fin(id, now_ms())) host.notify_tx();
            co_return true;
        }

        auto finish() -> capy::task<bool> {
            auto deadline = Clock::now() + std::chrono::seconds(5);
            while (!slot->closed && !host.stop_flag.load(std::memory_order_acquire) && Clock::now() < deadline) {
                auto* connection = table().get(id);
                if (!connection || connection->send_closed()) co_return true;
                if (connection->state() == tcp::ConnectionState::reset ||
                    connection->state() == tcp::ConnectionState::expired) co_return false;
                slot->write_changed.clear();
                auto [error] = co_await corosio::timeout(slot->write_changed.wait(), deadline);
                if (error) break;
            }
            co_return false;
        }
    };

    struct TunTcpOps {
        using Clock = std::chrono::steady_clock;

        template<class Impl, class Table, class Engine>
        static auto reset_or_abort(Impl& host, Table& tbl, Engine& eng, tcp::ConnectionId id) noexcept -> void {
            auto res = eng.reset(id, now_ms());
            if (res && res->notification.delivered) { host.notify_tx(); return; }
            if (res && res->notification.backpressured) {
                if (auto* conn = tbl.get(id); conn && conn->state() == tcp::ConnectionState::reset) {
                    host.notify_tx(); return;
                }
            }
            (void)tbl.abort(id);
        }

        template<class Impl, bool IsV6>
        static auto handle_tcp(Impl& host, tcp::ConnectionId id, std::shared_ptr<typename Impl::TcpFlowSlot> slot)
            -> capy::task<> {
            auto& tbl = [&]() -> auto& { if constexpr (IsV6) return *host.table6; else return *host.table4; }();
            auto& eng = [&]() -> auto& { if constexpr (IsV6) return *host.engine6; else return *host.engine4; }();
            struct Guard {
                Impl& host; tcp::ConnectionId id; std::shared_ptr<typename Impl::TcpFlowSlot> slot;
                bool finalized = false;
                ~Guard() {
                    slot->closed = true;
                    slot->wake();
                    if constexpr (IsV6) {
                        host.tcp6_flows.erase(id);
                        if (!finalized && host.table6 && host.table6->get(id)) (void)host.table6->abort(id);
                    } else {
                        host.tcp4_flows.erase(id);
                        if (!finalized && host.table4 && host.table4->get(id)) (void)host.table4->abort(id);
                    }
                }
            } guard{host, id, slot};

            auto ep = tbl.endpoints(id);
            auto* conn = tbl.get(id);
            if (!ep || !conn) { guard.finalized = true; co_return; }
            auto lease_opt = host.routing.acquire_session();
            if (!lease_opt) { reset_or_abort(host, tbl, eng, id); guard.finalized = true; co_return; }

            relay::Session session(host.routing.executor_context());
            host.routing.attach_session(session, std::move(*lease_opt));
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
            session.datagram_source = src_ep;
            session.ingress = host.routing.transparent_metadata(src_ep, conn->initial_dscp());
            session.source_interface = host.device_name();
            auto const& policy = session.route_snapshot ? session.route_snapshot->matcher : host.routing.routing_policy();
            if (auto owner = lookup_tun_owner(false, ep->source.address, ep->source.port, ep->target.address, ep->target.port,
                    policy, host.routing.ordered_routing_policy())) {
                if (owner->uid) session.source_uid = owner->uid;
                if (owner->gid) session.source_gid = owner->gid;
                if (!owner->process_path.empty()) session.process_path = std::move(owner->process_path);
                if (!owner->user.empty()) session.source_user = std::move(owner->user);
                if (!owner->package_name.empty()) session.package_name = std::move(owner->package_name);
            }
            session.begin_traffic(relay::TrafficProtocol::tun_tcp, req.port);
            TcpChannel<Impl, IsV6> ch{host, session, id, slot};
            std::stop_callback cancel_channel(session.stop.get_token(), [&]() noexcept {
                slot->closed = true;
                slot->wake();
            });
            using Result = relay::OrderedStreamResult;
            auto result = Result::rejected;
            if (session.ordered_tcp) {
                auto dns = host.cfg.dns_hijack_tcp ? &TunTcpDnsOps::template serve_tcp_dns<TcpChannel<Impl, IsV6>> : nullptr;
                result = co_await relay::route_ordered_stream_tcp(session, host.routing.executor_context(), req, &ch,
                    &TcpChannel<Impl, IsV6>::sniff_client, dns);
            } else if ((co_await relay::dial_destination(session, host.routing.executor_context(),
                           policy, req, src_ep, session.handshake_deadline)) == 0) {
                result = Result::connected;
            }
            if (result == Result::rejected_drop) {
                (void)tbl.abort(id);
                guard.finalized = true;
                session.close();
                co_return;
            }
            if (result == Result::rejected || session.closed) {
                reset_or_abort(host, tbl, eng, id);
                guard.finalized = true;
                session.close();
                co_return;
            }
            if (result == Result::connected) {
                session.relaying = true;
                session.touched = Clock::now();
                (void)co_await capy::when_all(
                    relay::stream_relay::direction(session, relay::stream_relay::upload(session, ch)),
                    relay::stream_relay::direction(session, relay::stream_relay::download(session, ch)));
            }
            bool graceful = false;
            if (!session.closed) graceful = co_await ch.finish();
            if (graceful && tbl.get(id)) (void)tbl.detach(id);
            else if (!graceful && tbl.get(id)) reset_or_abort(host, tbl, eng, id);
            guard.finalized = true;
            session.close();
        }
    };
}
