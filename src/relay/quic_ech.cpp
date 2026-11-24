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
import :quic_ech;

namespace relay {

    namespace quic_ech {
        auto Profile::load(config::QuicEchOptions const& options, std::string_view name, bool dns_available)
            -> std::expected<Profile, std::string> {
            Profile profile;
            if (!options.dns && options.config_file.empty()) return profile;
            std::string normalized(name);
            if (platform::parse_ip_address(name) || !dns::canonicalize_name(normalized) || normalized == ".")
                return std::unexpected("QUIC ECH requires a DNS server-name");
            if (options.dns) {
#ifdef NEXUS_DNS_RESPONSE
                if (!dns_available || !options.config_file.empty())
                    return std::unexpected("QUIC ECH discovery requires DNS and a single configuration source");
                profile.dns_name = std::move(normalized);
#else
                (void)dns_available;
                return std::unexpected("QUIC ECH discovery requires the dns-response feature");
#endif
            } else {
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

            struct Binding {
                std::uint16_t priority;
                std::optional<quic::EchConfig> config;
            };

            auto service_binding(Bytes data, std::string_view owner, std::uint16_t port) -> std::optional<Binding> {
                if (data.size() < 3) return {};
                auto priority = read16(data);
                data = data.subspan(2);
                auto target = take_target(data);
                if (!target) return {};
                if (!priority) return Binding{0, {}};
                bool compatible = *target == "." || *target == owner;
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
                        auto alpn = h3_alpn(value);
                        if (!alpn) return {};
                        compatible &= *alpn;
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
                if (!compatible || !config) return Binding{priority, {}};
                return Binding{priority, std::move(*config)};
            }

            auto select_binding(dns::Response const& response, std::string_view owner, std::uint16_t type,
                                std::uint16_t port) -> std::optional<quic::EchConfig> {
                if (response.rcode) return {};
                std::optional<Binding> best;
                for (auto const& record : response.records) {
                    if (record.section != dns::Section::answer || record.type != type || record.klass != 1 ||
                        record.name != owner) continue;
                    auto data = Bytes(response.wire).subspan(record.data_offset, record.data_length);
                    auto candidate = service_binding(data, owner, port);
                    if (!candidate || !candidate->priority) return {};
                    if (candidate->config && (!best || best->priority > candidate->priority)) best = std::move(candidate);
                }
                if (!best) return {};
                return std::move(best->config);
            }
        }
#endif

        auto Profile::resolve(Session& session, corosio::io_context& context, DnsSlot& slot,
                              std::optional<std::size_t> bootstrap, std::uint16_t port, Clock::time_point deadline) const
            -> capy::task<Result> {
            if (dns_name.empty()) co_return config;
#ifdef NEXUS_DNS_RESPONSE
            if (!session.dns) co_return std::unexpected("QUIC ECH DNS resolver is unavailable");
            auto const& routing=session.dns->routing;
            auto resolver=bootstrap.value_or(routing.final);
            if (resolver>=routing.resolver_count()) co_return std::unexpected("invalid QUIC ECH DNS resolver");
            auto snapshot = session.local_dns ? session.local_dns->source.acquire() : nullptr;
            for (auto type : {https, svcb}) {
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
                auto response = co_await resolve_response_owned(session, context, slot, selected, dns_name, type,
                    deadline, snapshot, disable_cache, nullptr, dns_name, {});
                if (!response) continue;
                if (auto found = select_binding(response->response, dns_name, type, port)) co_return found;
            }
#else
            (void)session; (void)context; (void)slot; (void)bootstrap; (void)port; (void)deadline;
#endif
            co_return std::unexpected("QUIC ECH DNS did not provide a compatible ECHConfigList");
        }
    }
}
