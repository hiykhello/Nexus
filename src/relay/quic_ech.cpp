module;
#include <proxy/proxy_macros.h>
module relay;
import std;
import config;
import dns.message;
import platform.ip_address;
import relay.dns_state;
import quic.ech_config;
import capy;
import corosio;
import :dns_internal;
import :quic_ech;

namespace relay {

    namespace quic_ech {
        namespace {
            auto same_dns_name(std::string_view a, std::string_view b) noexcept -> bool {
                if (!a.empty() && a.back() == '.') a.remove_suffix(1);
                if (!b.empty() && b.back() == '.') b.remove_suffix(1);
                auto lower = [](unsigned char c) noexcept {
                    return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c + ('a' - 'A')) : c;
                };
                return a.size() == b.size() && std::ranges::equal(a, b, [&](char x, char y) {
                    return lower(static_cast<unsigned char>(x)) == lower(static_cast<unsigned char>(y));
                });
            }
        }

        auto Profile::load(config::QuicEchOptions const& options, std::string_view name, bool dns_available)
            -> std::expected<Profile, std::string> {
            Profile profile;
            if (!options.dns && options.config_file.empty()) {
                if (!options.query_server_name.empty())
                    return std::unexpected("ECH query-server-name requires ech-dns");
                return profile;
            }
            std::string normalized(name);
            if (!dns::canonicalize_name(normalized) || normalized == "." ||
                platform::parse_ip_address(name) || platform::parse_ip_address(normalized))
                return std::unexpected("QUIC ECH requires a DNS server-name");
            profile.server_name = normalized;
            if (options.dns) {
#ifdef NEXUS_DNS_RESPONSE
                if (!dns_available || !options.config_file.empty())
                    return std::unexpected("QUIC ECH discovery requires DNS and a single configuration source");
                if (!options.query_server_name.empty()) {
                    std::string query_norm(options.query_server_name);
                    if (!dns::canonicalize_name(query_norm) || query_norm == "." ||
                        platform::parse_ip_address(options.query_server_name) || platform::parse_ip_address(query_norm))
                        return std::unexpected("ECH query-server-name must be a valid DNS hostname");
                    profile.dns_name = std::move(query_norm);
                } else {
                    profile.dns_name = std::move(normalized);
                }
#else
                (void)dns_available;
                return std::unexpected("QUIC ECH discovery requires the dns-response feature");
#endif
            } else {
                if (!options.query_server_name.empty())
                    return std::unexpected("ECH query-server-name cannot be combined with ech-config-file");
                auto loaded = quic::read_ech_config(options.config_file);
                if (!loaded) return std::unexpected(std::move(loaded.error()));
                profile.config.emplace(std::move(*loaded));
            }
            return profile;
        }

#ifdef NEXUS_DNS_RESPONSE
        namespace {
            using Bytes = std::span<const std::uint8_t>;
            constexpr std::uint16_t https = 65, svcb = 64;

            auto read16(Bytes data) noexcept -> std::uint16_t {
                return static_cast<std::uint16_t>((std::uint16_t{data[0]} << 8) | data[1]);
            }

            auto take_target(Bytes& data) -> std::optional<std::string> {
                std::string name;
                while (!data.empty()) {
                    auto length = data.front();
                    data = data.subspan(1);
                    if (!length) {
                        if (name.empty()) return ".";
                        if (!dns::canonicalize_name(name)) return {};
                        return name;
                    }
                    if (length > 63 || length > data.size() || name.size() + length + 1 > 254) return {};
                    if (!name.empty()) name.push_back('.');
                    name.append(reinterpret_cast<const char*>(data.data()), length);
                    data = data.subspan(length);
                }
                return {};
            }

            auto h3_alpn(Bytes data) -> std::optional<bool> {
                if (data.empty()) return {};
                bool found = false;
                while (!data.empty()) {
                    auto size = data.front();
                    data = data.subspan(1);
                    if (!size || size > data.size()) return {};
                    if (size == 2 && data[0] == 'h' && data[1] == '3') found = true;
                    data = data.subspan(size);
                }
                return found;
            }

            auto tcp_alpn(Bytes data) -> std::optional<bool> {
                if (data.empty()) return {};
                bool found = false;
                while (!data.empty()) {
                    auto size = data.front();
                    data = data.subspan(1);
                    if (!size || size > data.size()) return {};
                    auto token = std::string_view(reinterpret_cast<const char*>(data.data()), size);
                    if (token == "h2" || token == "http/1.1") found = true;
                    data = data.subspan(size);
                }
                return found;
            }

            struct Binding {
                std::uint16_t priority;
                std::optional<quic::EchConfig> config;
            };

            auto service_binding(Bytes data, std::string_view owner, std::string_view query_origin,
                                 std::string_view inner_origin, std::uint16_t port,
                                 Transport transport) -> std::optional<Binding> {
                if (data.size() < 3) return {};
                auto priority = read16(data);
                data = data.subspan(2);
                auto target = take_target(data);
                if (!target) return {};
                if (!priority) return Binding{0, {}};
                bool compatible = *target == "." || *target == owner || *target == query_origin || *target == inner_origin;
                bool alpn_has_tcp = false;
                std::optional<std::uint16_t> previous;
                std::bitset<7> present;
                Bytes mandatory, ech;
                while (!data.empty()) {
                    if (data.size() < 4) return {};
                    auto key = read16(data);
                    auto size = read16(data.subspan(2));
                    data = data.subspan(4);
                    if ((previous && key <= *previous) || size > data.size()) return {};
                    previous = key;
                    auto value = data.first(size);
                    data = data.subspan(size);
                    if (key < present.size()) present.set(key);
                    switch (key) {
                    case 0:
                        if (size < 2 || size % 2) return {};
                        mandatory = value;
                        break;
                    case 1: {
                        if (transport == Transport::quic) {
                            auto alpn = h3_alpn(value);
                            if (!alpn) return {};
                            compatible &= *alpn;
                        } else {
                            auto alpn = tcp_alpn(value);
                            if (!alpn) return {};
                            alpn_has_tcp = *alpn;
                        }
                        break;
                    }
                    case 2: if (size || !present[1]) return {}; break;
                    case 3:
                        if (size != 2 || !read16(value)) return {};
                        compatible &= read16(value) == port;
                        break;
                    case 4: if (!size || size % 4) return {}; break;
                    case 5: ech = value; break;
                    case 6: if (!size || size % 16) return {}; break;
                    }
                }
                if (transport == Transport::tcp && present[1] && !alpn_has_tcp && present[2]) compatible = false;
                std::uint16_t last = 0;
                while (!mandatory.empty()) {
                    auto key = read16(mandatory);
                    if (key <= last) return {};
                    last = key;
                    if (key >= present.size() || key == 4 || key == 6 || !present[key]) compatible = false;
                    mandatory = mandatory.subspan(2);
                }
                if (!present[5]) return Binding{priority, {}};
                auto config = quic::select_ech_config(ech);
                if (!config && config.error() == quic::EchConfigError::malformed) return {};
                if (!compatible || !config || same_dns_name(config->public_name, inner_origin)) return Binding{priority, {}};
                return Binding{priority, std::move(*config)};
            }

            auto select_binding(dns::Response const& response, std::string_view owner, std::string_view query_origin,
                                std::string_view inner_origin, std::uint16_t type, std::uint16_t port, Transport transport)
                -> std::optional<quic::EchConfig> {
                if (response.rcode) return {};
                std::optional<Binding> best;
                for (auto const& record : response.records) {
                    if (record.section != dns::Section::answer || record.type != type || record.klass != 1 ||
                        record.name != owner) continue;
                    auto data = Bytes(response.wire).subspan(record.data_offset, record.data_length);
                    auto candidate = service_binding(data, owner, query_origin, inner_origin, port, transport);
                    if (!candidate || !candidate->priority) return {};
                    if (candidate->config && (!best || best->priority > candidate->priority)) best = std::move(candidate);
                }
                if (!best) return {};
                return std::move(best->config);
            }
        }
#endif

        auto Profile::resolve(Session& session, corosio::io_context& context, DnsSlot& slot,
                              std::optional<std::size_t> bootstrap, std::uint16_t port, Clock::time_point deadline,
                              Transport transport) const -> capy::task<Result> {
            if (dns_name.empty()) {
                if (config && !server_name.empty() && same_dns_name(config->public_name, server_name))
                    co_return std::unexpected("ECH public_name must differ from server-name");
                co_return config;
            }
#ifdef NEXUS_DNS_RESPONSE
            auto const* routing_ptr = dns_detail::active_dns_routing(session);
            if (!session.dns || !routing_ptr) co_return std::unexpected("QUIC ECH DNS resolver is unavailable");
            auto const& routing = *routing_ptr;
            auto resolver=bootstrap.value_or(routing.final);
            if (resolver>=routing.resolver_count()) co_return std::unexpected("invalid QUIC ECH DNS resolver");
            auto snapshot = session.local_dns ? session.local_dns->source.acquire() : nullptr;
            std::string prefixed;
            std::vector<std::pair<std::string_view, std::uint16_t>> queries;
            queries.reserve(3);
            if (port && port != 443) {
                prefixed = "_" + std::to_string(port) + "._https." + dns_name;
                if (dns::canonicalize_name(prefixed)) queries.emplace_back(prefixed, https);
            }
            queries.emplace_back(dns_name, https);
            queries.emplace_back(dns_name, svcb);
            for (auto const& [query_name, type] : queries) {
                if (slot.canceled || session.closed || Clock::now() >= deadline) break;
                auto selected=resolver;
                bool disable_cache=false;
                if (resolver>=routing.servers.size()) {
                    auto decision=policy::select_dns_action(session.dns_rules(),dns_name,type,
                        routing.view_finals[resolver-routing.servers.size()],routing.disable_cache);
                    if (decision.action==policy::DnsAction::reject) continue;
                    selected=decision.server;
                    disable_cache=decision.disable_cache;
                }
                std::string name_copy(query_name);
                auto response = co_await resolve_response_owned(session, context, slot, selected, name_copy, type,
                    deadline, snapshot, disable_cache, nullptr, name_copy, {});
                if (!response) continue;
                if (auto found = select_binding(response->response, query_name, dns_name, server_name, type, port, transport))
                    co_return found;
            }
#else
            (void)session; (void)context; (void)slot; (void)bootstrap; (void)port; (void)deadline; (void)transport;
#endif
            co_return std::unexpected(transport == Transport::quic
                ? "QUIC ECH DNS did not provide a compatible ECHConfigList"
                : "TLS ECH DNS did not provide a compatible ECHConfigList");
        }
    }
}
