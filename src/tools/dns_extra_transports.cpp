module cli.dns_transports;
import std;
import capy;
import corosio;
import config;
import dns.corosio_query;
import dns.input_budget;
import dns.message;
import net.datagram_frame;
import platform.ip_address;
import relay;
import relay.session_quota;
import rulefile;
import uot;

namespace cli {
    namespace {
        struct HostRecordList {
            std::vector<std::array<std::uint8_t, 4>> ipv4;
            std::vector<std::array<std::uint8_t, 16>> ipv6;
            std::optional<std::string> cname{};
        };
        struct HostsTable {
            std::map<std::string, HostRecordList, std::less<>> exact;
            std::vector<std::pair<std::string, HostRecordList>> patterns;
        };

        auto normalize_host_key(std::string_view raw) -> std::string {
            while (raw.ends_with('.')) raw.remove_suffix(1);
            std::string out(raw);
            for (char& ch : out) {
                if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            }
            return out;
        }

        auto append_host_ip(HostRecordList& target, platform::IpAddress const& ip) -> void {
            if (ip.size == 4) {
                std::array<std::uint8_t, 4> addr{};
                std::copy_n(ip.bytes.begin(), 4, addr.begin());
                target.ipv4.push_back(addr);
            } else if (ip.size == 16) {
                target.ipv6.push_back(ip.bytes);
            }
        }

        auto encode_dns_labels(std::string_view domain, std::vector<std::uint8_t>& out) -> bool {
            while (domain.size() > 1 && domain.ends_with('.')) domain.remove_suffix(1);
            if (domain.empty() || domain.size() > 253) return false;
            std::size_t pos = 0;
            while (pos < domain.size()) {
                auto dot = domain.find('.', pos);
                auto len = (dot == std::string_view::npos ? domain.size() : dot) - pos;
                if (!len || len > 63) return false;
                out.push_back(static_cast<std::uint8_t>(len));
                out.insert(out.end(), domain.begin() + static_cast<std::ptrdiff_t>(pos),
                    domain.begin() + static_cast<std::ptrdiff_t>(pos + len));
                if (dot == std::string_view::npos) break;
                pos = dot + 1;
            }
            out.push_back(0);
            return true;
        }

        auto lookup_host_record(HostsTable const& hosts, std::string_view key) -> HostRecordList const* {
            if (auto it = hosts.exact.find(key); it != hosts.exact.end()) return &it->second;
            for (auto const& [pattern, rec] : hosts.patterns) {
                if (pattern.starts_with("*.")) {
                    auto suffix = std::string_view(pattern).substr(1);
                    if (key.size() > suffix.size() && key.ends_with(suffix)) return &rec;
                } else if (pattern.starts_with('.')) {
                    auto base = std::string_view(pattern).substr(1);
                    if (key == base || (key.size() > pattern.size() && key.ends_with(pattern))) return &rec;
                }
            }
            return nullptr;
        }

        auto parse_hosts_text(std::string_view text, HostsTable& out) -> void {
            std::size_t pos = 0;
            while (pos < text.size()) {
                auto nl = text.find('\n', pos);
                auto line = nl == std::string_view::npos ? text.substr(pos) : text.substr(pos, nl - pos);
                pos = nl == std::string_view::npos ? text.size() : nl + 1;
                if (auto hash = line.find('#'); hash != std::string_view::npos) line = line.substr(0, hash);
                std::vector<std::string_view> tokens;
                std::size_t off = 0;
                while (off < line.size()) {
                    while (off < line.size() && (line[off] == ' ' || line[off] == '\t' || line[off] == '\r')) ++off;
                    if (off >= line.size()) break;
                    auto start = off;
                    while (off < line.size() && line[off] != ' ' && line[off] != '\t' && line[off] != '\r') ++off;
                    tokens.push_back(line.substr(start, off - start));
                }
                if (tokens.size() < 2) continue;
                auto ip_token = tokens[0];
                if (auto pct = ip_token.find('%'); pct != std::string_view::npos) ip_token = ip_token.substr(0, pct);
                auto ip = platform::parse_ip_address(ip_token);
                if (!ip) continue;
                for (std::size_t i = 1; i < tokens.size(); ++i) {
                    auto host = normalize_host_key(tokens[i]);
                    if (!host.empty()) append_host_ip(out.exact[host], *ip);
                }
            }
        }

        auto build_hosts_response(HostsTable const& hosts, dns::QueryMessage const& query, std::uint16_t id)
            -> std::expected<dns::Response, dns::detail::UdpError> {
            auto wire = dns::make_query(id, query.question);
            if (!wire) return std::unexpected(dns::detail::UdpError::invalid_query);
            auto key = normalize_host_key(query.question.name);
            auto const* first = lookup_host_record(hosts, key);
            if (!first) {
                (*wire)[2] = 0x81;
                (*wire)[3] = 0x83; // NXDOMAIN
            } else {
                (*wire)[2] = 0x81;
                (*wire)[3] = 0x80; // NOERROR
                std::uint16_t answer_count = 0;
                std::uint16_t owner_off = 12;
                auto const* current = first;
                std::string cur_name = key;
                for (unsigned hop = 0; hop < 8 && current && current->cname; ++hop) {
                    std::vector<std::uint8_t> target_wire;
                    if (!encode_dns_labels(*current->cname, target_wire)) break;
                    wire->push_back(static_cast<std::uint8_t>(0xc0 | (owner_off >> 8)));
                    wire->push_back(static_cast<std::uint8_t>(owner_off & 0xff));
                    wire->insert(wire->end(), {0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 60});
                    wire->push_back(static_cast<std::uint8_t>(target_wire.size() >> 8));
                    wire->push_back(static_cast<std::uint8_t>(target_wire.size() & 0xff));
                    auto next_off = static_cast<std::uint16_t>(wire->size());
                    wire->insert(wire->end(), target_wire.begin(), target_wire.end());
                    ++answer_count;
                    if (query.question.type == 5) { current = nullptr; break; }
                    cur_name = normalize_host_key(*current->cname);
                    if (next_off >= 16384) { current = nullptr; break; }
                    owner_off = next_off;
                    current = lookup_host_record(hosts, cur_name);
                }
                if (current) {
                    if (query.question.type == 1) {
                        auto count = std::min<std::size_t>(current->ipv4.size(), 32);
                        for (std::size_t i = 0; i < count; ++i) {
                            wire->push_back(static_cast<std::uint8_t>(0xc0 | (owner_off >> 8)));
                            wire->push_back(static_cast<std::uint8_t>(owner_off & 0xff));
                            wire->insert(wire->end(), {0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 60, 0x00, 0x04});
                            wire->insert(wire->end(), current->ipv4[i].begin(), current->ipv4[i].end());
                            ++answer_count;
                        }
                    } else if (query.question.type == 28) {
                        auto count = std::min<std::size_t>(current->ipv6.size(), 32);
                        for (std::size_t i = 0; i < count; ++i) {
                            wire->push_back(static_cast<std::uint8_t>(0xc0 | (owner_off >> 8)));
                            wire->push_back(static_cast<std::uint8_t>(owner_off & 0xff));
                            wire->insert(wire->end(), {0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 60, 0x00, 0x10});
                            wire->insert(wire->end(), current->ipv6[i].begin(), current->ipv6[i].end());
                            ++answer_count;
                        }
                    }
                }
                (*wire)[6] = static_cast<std::uint8_t>(answer_count >> 8);
                (*wire)[7] = static_cast<std::uint8_t>(answer_count & 0xff);
            }
            auto parsed = dns::parse_owned_response(std::move(*wire), id, query.question);
            if (!parsed) return std::unexpected(dns::detail::UdpError::protocol);
            return std::move(*parsed);
        }

        auto endpoint_to_proxy_address(corosio::endpoint const& ep) noexcept -> net::ProxyAddress {
            net::ProxyAddress target{};
            target.port = ep.port();
            if (ep.address().is_v4()) {
                target.family = net::ProxyAddressFamily::ipv4;
                target.length = 4;
                auto bytes = ep.address().to_v4().to_bytes();
                std::ranges::copy(bytes, target.bytes.begin());
            } else {
                target.family = net::ProxyAddressFamily::ipv6;
                target.length = 16;
                auto bytes = ep.address().to_v6().to_bytes();
                std::ranges::copy(bytes, target.bytes.begin());
            }
            return target;
        }

        auto prepare_hosts_transport(config::DnsServer const& server)
            -> std::expected<dns::detail::ProtectedQuery, std::string> {
            auto map = std::make_shared<HostsTable>();
            if (!server.hosts_file.empty()) {
                auto content = rulefile::read_regular_file(server.hosts_file);
                if (!content) return std::unexpected("failed reading DNS hosts file: " + content.error());
                parse_hosts_text(*content, *map);
            }
            for (auto const& entry : server.hosts_entries) {
                auto key = normalize_host_key(entry.domain);
                HostRecordList* dst = nullptr;
                if (key.starts_with("*.") || key.starts_with('.')) {
                    auto it = std::ranges::find(map->patterns, key, &std::pair<std::string, HostRecordList>::first);
                    if (it == map->patterns.end()) {
                        map->patterns.push_back({key, {}});
                        dst = &map->patterns.back().second;
                    } else dst = &it->second;
                } else dst = &map->exact[key];
                for (auto const& addr : entry.addresses) append_host_ip(*dst, addr);
                if (entry.cname) dst->cname = normalize_host_key(*entry.cname);
            }
            std::ranges::sort(map->patterns, [](auto const& a, auto const& b) {
                return a.first.size() > b.first.size();
            });
            auto shared = std::shared_ptr<HostsTable const>(std::move(map));
            return dns::detail::ProtectedQuery{
                [shared](corosio::io_context&, corosio::endpoint, dns::QueryMessage const& query, std::uint16_t id,
                    std::chrono::steady_clock::time_point, dns::InputBudget&, std::stop_token stop)
                    -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
                    if (stop.stop_requested()) co_return std::unexpected(dns::detail::UdpError::canceled);
                    co_return build_hosts_response(*shared, query, id);
                }
            };
        }
        template<class T>
        auto run_timed_op(capy::task<T> task, std::optional<T>& out) -> capy::task<capy::results<>> {
            out.emplace(co_await std::move(task));
            co_return capy::results<>{std::error_code{}};
        }

        template<class Cancel>
        auto run_deadline_watch(std::chrono::steady_clock::time_point deadline, bool& timed_out, Cancel& cancel)
            -> capy::task<capy::results<>> {
            auto [ec] = co_await corosio::delay(deadline);
            if (!ec) { timed_out = true; cancel(); }
            co_return capy::results<>{ec};
        }

        template<class T, class Cancel>
        auto await_with_deadline(capy::task<T> task, std::chrono::steady_clock::time_point deadline, Cancel& cancel)
            -> capy::task<std::pair<bool, std::optional<T>>> {
            std::optional<T> value;
            bool timed_out = false;
            (void)co_await capy::when_any(run_timed_op(std::move(task), value),
                                          run_deadline_watch(deadline, timed_out, cancel));
            co_return std::pair{timed_out, std::move(value)};
        }
    }

    auto prepare_extra_dns_transport(config::DnsServer const& server)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        switch (server.kind) {
        case config::DnsServerKind::hosts: return prepare_hosts_transport(server);
        case config::DnsServerKind::dhcp: return prepare_dhcp_dns_transport(server);
        case config::DnsServerKind::mdns: return prepare_mdns_transport(server);
        case config::DnsServerKind::standard:
            return std::unexpected("invalid extra DNS server kind");
        }
        std::unreachable();
    }

    auto prepare_proxy_plain_dns(bool tcp, std::size_t outbound, dns::detail::TransportSnapshotRef snapshot)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        return dns::detail::ProtectedQuery{
            [tcp, outbound, snapshot = std::move(snapshot)](corosio::io_context& context, corosio::endpoint endpoint,
                dns::QueryMessage const& query, std::uint16_t id, std::chrono::steady_clock::time_point deadline,
                dns::InputBudget& budget, std::stop_token stop)
                -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
                using Error = dns::detail::UdpError;
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(Error::timeout);
                auto transport = snapshot ? snapshot->lock() : nullptr;
                if (snapshot && !transport) co_return std::unexpected(Error::transport);
                auto* server = relay::Server::from_context(context);
                if (!server) co_return std::unexpected(Error::transport);
                auto lease = server->acquire_session();
                if (!lease) co_return std::unexpected(Error::budget_exhausted);

                dns::QueryMessage wired_query = query;
                wired_query.id = id;
                auto encoded = dns::encode_query(wired_query);
                if (!encoded || encoded->size() > 65535) co_return std::unexpected(Error::invalid_query);

                relay::Session session(context);
                server->attach_session(session, std::move(*lease));
                session.dns_transport_override = std::move(transport);
                session.relaying = true;
                std::unique_ptr<relay::PacketTunnel> tunnel;
                struct Guard {
                    relay::Session& session;
                    std::unique_ptr<relay::PacketTunnel>& tunnel;
                    ~Guard() {
                        if (tunnel) tunnel->cancel();
                        if (session.tunnel) session.tunnel->cancel();
                        session.close();
                    }
                } guard{session, tunnel};
                std::stop_callback stop_cb(stop, [&]() noexcept {
                    if (tunnel) tunnel->cancel();
                    if (session.tunnel) session.tunnel->cancel();
                    session.close();
                });

                auto cancel_all = [&]() noexcept {
                    if (tunnel) tunnel->cancel();
                    if (session.tunnel) session.tunnel->cancel();
                    session.close();
                };

                if (tcp) {
                    auto conn = co_await server->open_stream(session, outbound, endpoint, deadline);
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (conn != relay::PacketConnectResult::connected || !session.tunnel)
                        co_return std::unexpected(conn == relay::PacketConnectResult::timeout ? Error::timeout : Error::transport);
                    std::vector<std::uint8_t> frame;
                    frame.reserve(2 + encoded->size());
                    frame.push_back(static_cast<std::uint8_t>(encoded->size() >> 8));
                    frame.push_back(static_cast<std::uint8_t>(encoded->size() & 0xff));
                    frame.insert(frame.end(), encoded->begin(), encoded->end());
                    auto [send_to, sent] = co_await await_with_deadline(session.tunnel->send(frame), deadline, cancel_all);
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (send_to || !sent || !*sent) co_return std::unexpected(send_to ? Error::timeout : Error::transport);

                    std::vector<std::uint8_t> rx;
                    std::array<std::uint8_t, 4096> chunk{};
                    while (rx.size() < 2) {
                        auto [rd_to, rd_res] = co_await await_with_deadline(session.tunnel->read(chunk), deadline, cancel_all);
                        if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                        if (rd_to) co_return std::unexpected(Error::timeout);
                        if (!rd_res || !*rd_res) co_return std::unexpected(Error::transport);
                        if (**rd_res == 0) co_return std::unexpected(Error::truncated);
                        rx.insert(rx.end(), chunk.begin(), chunk.begin() + **rd_res);
                    }
                    std::size_t expected_len = (std::size_t(rx[0]) << 8) | rx[1];
                    if (expected_len < 12) co_return std::unexpected(Error::protocol);
                    while (rx.size() - 2 < expected_len) {
                        auto [rd_to, rd_res] = co_await await_with_deadline(session.tunnel->read(chunk), deadline, cancel_all);
                        if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                        if (rd_to) co_return std::unexpected(Error::timeout);
                        if (!rd_res || !*rd_res) co_return std::unexpected(Error::transport);
                        if (**rd_res == 0) co_return std::unexpected(Error::truncated);
                        rx.insert(rx.end(), chunk.begin(), chunk.begin() + **rd_res);
                    }
                    std::optional<dns::InputBudget::Lease> budget_lease;
                    if (&budget != &dns::default_upstream_receive_budget()) {
                        budget_lease = budget.acquire(expected_len);
                        if (!budget_lease) co_return std::unexpected(Error::budget_exhausted);
                    }
                    dns::Bytes wire(rx.begin() + 2, rx.begin() + 2 + expected_len);
                    auto parsed = dns::parse_owned_response(std::move(wire), id, query.question);
                    if (!parsed) co_return std::unexpected(Error::protocol);
                    co_return std::move(*parsed);
                }

                tunnel = server->open_packet_tunnel(session, outbound);
                if (!tunnel) co_return std::unexpected(Error::transport);
                auto target = endpoint_to_proxy_address(endpoint);
                auto conn = co_await tunnel->connect_until(target, deadline);
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (conn != relay::PacketConnectResult::connected)
                    co_return std::unexpected(conn == relay::PacketConnectResult::timeout ? Error::timeout : Error::transport);
                auto pt = tunnel->transport();
                if (pt.needs_uot_request) {
                    auto uot_req = uot::encode_request({false, target});
                    if (!uot_req) co_return std::unexpected(Error::transport);
                    auto [uot_to, ok] = co_await await_with_deadline(tunnel->send(*uot_req), deadline, cancel_all);
                    if (uot_to || !ok || !*ok) co_return std::unexpected(uot_to ? Error::timeout : Error::transport);
                }
                auto pkt = net::encode_datagram(pt.framing, target, *encoded);
                if (!pkt) co_return std::unexpected(Error::invalid_query);
                auto [tx_to, tx_ok] = co_await await_with_deadline(tunnel->send(*pkt), deadline, cancel_all);
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (tx_to || !tx_ok || !*tx_ok) co_return std::unexpected(tx_to ? Error::timeout : Error::transport);

                net::DatagramDecoder decoder(pt.framing, target);
                std::array<std::uint8_t, 8192> buf{};
                for (;;) {
                    auto [rd_to, rd_res] = co_await await_with_deadline(tunnel->read(buf), deadline, cancel_all);
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (rd_to) co_return std::unexpected(Error::timeout);
                    if (!rd_res || !*rd_res || **rd_res == 0) co_return std::unexpected(Error::transport);
                    auto span = std::span(buf).first(**rd_res);
                    while (!span.empty()) {
                        auto feed = decoder.feed(span);
                        span = span.subspan(feed.consumed);
                        if (feed.status == net::DatagramStatus::accepted) {
                            auto dg = decoder.packet();
                            if (dg) {
                                std::optional<dns::InputBudget::Lease> budget_lease;
                                if (&budget != &dns::default_upstream_receive_budget()) {
                                    budget_lease = budget.acquire(dg->payload.size());
                                    if (!budget_lease) co_return std::unexpected(Error::budget_exhausted);
                                }
                                dns::Bytes wire(dg->payload.begin(), dg->payload.end());
                                auto parsed = dns::parse_owned_response(std::move(wire), id, query.question);
                                (void)decoder.consume();
                                if (parsed) co_return std::move(*parsed);
                            } else (void)decoder.consume();
                        } else if (feed.status != net::DatagramStatus::incomplete) {
                            co_return std::unexpected(Error::protocol);
                        }
                    }
                }
            }
        };
    }
}
