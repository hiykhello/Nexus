module;
#if defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__)
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif
module cli.dns_transports;
import std;
import capy;
import corosio;
import config;
import dns.corosio_query;
import dns.input_budget;
import dns.mdns;
import dns.message;

namespace cli {
    namespace {
        auto make_mdns_nxdomain(dns::Question const& question, std::uint16_t id)
            -> std::expected<dns::Response, dns::detail::UdpError> {
            auto wire = dns::make_query(id, question);
            if (!wire) return std::unexpected(dns::detail::UdpError::invalid_query);
            (*wire)[2] = 0x81;
            (*wire)[3] = 0x83;
            auto parsed = dns::parse_owned_response(std::move(*wire), id, question);
            if (!parsed) return std::unexpected(dns::detail::UdpError::protocol);
            return std::move(*parsed);
        }

        auto encode_mdns_wire_name(std::string_view name, std::vector<std::uint8_t>& out) -> bool {
            if (name == ".") { out.push_back(0); return true; }
            if (name.ends_with('.')) name.remove_suffix(1);
            if (name.empty()) return false;
            std::size_t wire_size = 1;
            auto const start = out.size();
            while (!name.empty()) {
                auto dot = name.find('.');
                auto label = dot == std::string_view::npos ? name : name.substr(0, dot);
                if (label.empty() || label.size() > 63 || wire_size + label.size() + 1 > 255) {
                    out.resize(start);
                    return false;
                }
                out.push_back(static_cast<std::uint8_t>(label.size()));
                for (unsigned char c : label) {
                    if (c < 33 || c > 126 || c == '.' || c == '\\') { out.resize(start); return false; }
                    out.push_back(c >= 'A' && c <= 'Z' ? static_cast<std::uint8_t>(c + 32) : c);
                }
                wire_size += label.size() + 1;
                if (dot == std::string_view::npos) break;
                name.remove_prefix(dot + 1);
                if (name.empty()) { out.resize(start); return false; }
            }
            out.push_back(0);
            return true;
        }

        auto encode_mdns_rdata(dns::mdns::MdnsRecord const& rec, std::vector<std::uint8_t>& rdata) -> bool {
            rdata.clear();
            if (rec.type == 1) {
                if (!rec.address || rec.address->size != 4) return false;
                rdata.assign(rec.address->bytes.begin(), rec.address->bytes.begin() + 4);
                return true;
            }
            if (rec.type == 28) {
                if (!rec.address || rec.address->size != 16) return false;
                rdata.assign(rec.address->bytes.begin(), rec.address->bytes.begin() + 16);
                return true;
            }
            if (rec.type == 12) {
                if (rec.target.empty()) return false;
                return encode_mdns_wire_name(rec.target, rdata);
            }
            if (rec.type == 33) {
                if (rec.target.empty()) return false;
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_priority >> 8));
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_priority & 0xffu));
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_weight >> 8));
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_weight & 0xffu));
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_port >> 8));
                rdata.push_back(static_cast<std::uint8_t>(rec.srv_port & 0xffu));
                return encode_mdns_wire_name(rec.target, rdata);
            }
            if (rec.type == 16) {
                if (rec.txt_strings.empty()) { rdata.push_back(0); return true; }
                for (auto const& s : rec.txt_strings) {
                    if (s.empty()) { rdata.push_back(0); continue; }
                    for (std::size_t off = 0; off < s.size(); off += 255) {
                        auto chunk = std::min<std::size_t>(255, s.size() - off);
                        if (rdata.size() + 1 + chunk > 65535) return false;
                        rdata.push_back(static_cast<std::uint8_t>(chunk));
                        rdata.insert(rdata.end(),
                            reinterpret_cast<std::uint8_t const*>(s.data() + off),
                            reinterpret_cast<std::uint8_t const*>(s.data() + off + chunk));
                    }
                }
                return !rdata.empty() && rdata.size() <= 65535;
            }
            return false;
        }

        auto build_mdns_standard_response(dns::Question const& question, std::uint16_t id,
            std::span<dns::mdns::MdnsRecord const> records) -> std::expected<std::optional<dns::Response>, dns::detail::UdpError> {
            auto wire = dns::make_query(id, question);
            if (!wire) return std::unexpected(dns::detail::UdpError::invalid_query);
            (*wire)[2] = 0x81;
            (*wire)[3] = 0x80;
            std::uint16_t count = 0;
            std::vector<std::uint8_t> rdata;
            for (auto const& rec : records) {
                if ((rec.type != question.type && question.type != 255) || rec.klass != 1 || rec.ttl == 0) continue;
                if (!dns::mdns::same_name(rec.name, question.name)) continue;
                if (!encode_mdns_rdata(rec, rdata) || rdata.size() > 65535 || wire->size() + 12 + rdata.size() > 65535)
                    continue;
                auto const ttl = rec.ttl;
                auto const rdlen = static_cast<std::uint16_t>(rdata.size());
                wire->insert(wire->end(), {
                    0xc0, 0x0c,
                    static_cast<std::uint8_t>(rec.type >> 8), static_cast<std::uint8_t>(rec.type & 0xffu),
                    0x00, 0x01,
                    static_cast<std::uint8_t>(ttl >> 24), static_cast<std::uint8_t>(ttl >> 16),
                    static_cast<std::uint8_t>(ttl >> 8), static_cast<std::uint8_t>(ttl & 0xffu),
                    static_cast<std::uint8_t>(rdlen >> 8), static_cast<std::uint8_t>(rdlen & 0xffu),
                });
                wire->insert(wire->end(), rdata.begin(), rdata.end());
                ++count;
                if (count >= 32) break;
            }
            if (count == 0) return std::optional<dns::Response>{};
            (*wire)[6] = static_cast<std::uint8_t>(count >> 8);
            (*wire)[7] = static_cast<std::uint8_t>(count & 0xff);
            auto parsed = dns::parse_owned_response(std::move(*wire), id, question);
            if (!parsed) return std::unexpected(dns::detail::UdpError::protocol);
            return std::optional<dns::Response>{std::move(*parsed)};
        }
    }

    auto convert_mdns_response(dns::Question const& question, std::uint16_t id,
        std::span<std::uint8_t const> mdns_wire) -> std::expected<std::optional<dns::Response>, dns::detail::UdpError> {
        auto parsed = dns::mdns::parse_mdns_response(mdns_wire);
        if (!parsed) return std::optional<dns::Response>{};
        return build_mdns_standard_response(question, id, *parsed);
    }

    auto prepare_mdns_transport(config::DnsServer const& server)
        -> std::expected<dns::detail::ProtectedQuery, std::string> {
        auto iface = server.interface_name;
        return dns::detail::ProtectedQuery{
            [iface = std::move(iface)](corosio::io_context& context, corosio::endpoint, dns::QueryMessage const& query, std::uint16_t id,
                std::chrono::steady_clock::time_point deadline, dns::InputBudget&, std::stop_token stop)
                -> capy::task<std::expected<dns::Response, dns::detail::UdpError>> {
                using Error = dns::detail::UdpError;
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (!dns::mdns::is_mdns_name(query.question.name))
                    co_return make_mdns_nxdomain(query.question, id);
                if (std::chrono::steady_clock::now() >= deadline) co_return std::unexpected(Error::timeout);

                auto req = dns::make_query(0, query.question);
                if (!req || req->size() < 14) co_return std::unexpected(Error::invalid_query);
                (*req)[2] = 0;
                (*req)[3] = 0;
                (*req)[req->size() - 2] = 0x80; // QU unicast-response preference

                corosio::endpoint mcast(corosio::ipv4_address({224, 0, 0, 251}), 5353);
                corosio::udp_socket sock(context);
                if (sock.open(mcast.address().family())) co_return std::unexpected(Error::transport);
                if (!iface.empty()) {
#if defined(__linux__)
                    unsigned ifidx = ::if_nametoindex(iface.c_str());
                    if (ifidx == 0) { sock.close(); co_return std::unexpected(Error::transport); }
                    ip_mreqn mreq{};
                    mreq.imr_ifindex = static_cast<int>(ifidx);
                    if (::setsockopt(sock.native_handle(), IPPROTO_IP, IP_MULTICAST_IF, &mreq, sizeof(mreq)) < 0) {
                        sock.close();
                        co_return std::unexpected(Error::transport);
                    }
#elif defined(__APPLE__)
                    unsigned ifidx = ::if_nametoindex(iface.c_str());
                    if (ifidx == 0) { sock.close(); co_return std::unexpected(Error::transport); }
                    std::uint32_t bound_idx = ifidx;
                    if (::setsockopt(sock.native_handle(), IPPROTO_IP, IP_BOUND_IF, &bound_idx, sizeof(bound_idx)) < 0) {
                        sock.close();
                        co_return std::unexpected(Error::transport);
                    }
#endif
                }
                if (sock.bind(corosio::endpoint(corosio::ipv4_address::any(), 0))) {
                    sock.close();
                    co_return std::unexpected(Error::transport);
                }
                std::stop_callback stop_cb(stop, [&]() noexcept { sock.close(); });
                auto [tx_err, tx_n] = co_await corosio::timeout(
                    sock.send_to(capy::const_buffer(req->data(), req->size()), mcast), deadline);
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (tx_err || tx_n != req->size())
                    co_return std::unexpected(capy::is_timeout(tx_err) ? Error::timeout : Error::transport);

                std::array<std::uint8_t, 4096> rx{};
                for (;;) {
                    corosio::endpoint peer{};
                    auto [rx_err, rx_n] = co_await corosio::timeout(
                        sock.recv_from(capy::mutable_buffer(rx.data(), rx.size()), peer), deadline);
                    if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                    if (rx_err)
                        co_return std::unexpected(capy::is_timeout(rx_err) ? Error::timeout : Error::transport);
                    if (peer.port() != 5353) continue;
                    auto built = convert_mdns_response(query.question, id, std::span(rx).first(rx_n));
                    if (!built) co_return std::unexpected(built.error());
                    if (!*built) continue;
                    co_return std::move(**built);
                }
            }
        };
    }
}
