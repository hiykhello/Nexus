#pragma once

namespace nexus::proxy {
    // Each network worker owns its own cache and uses it on its executor only.
    struct DnsState {
        DnsRouting routing;
        dns::AddressCache cache{256};
        inline explicit DnsState(DnsRouting value) : routing(std::move(value)) {}
        inline auto select(std::string_view domain) const -> std::size_t {
            std::string normalized(domain);
            for (auto& c : normalized) if (c>='A' && c<='Z') c+=('a'-'A');
            for (auto const& rule : routing.rules) {
                if (normalized==rule.domain || (rule.suffix && normalized.size()>rule.domain.size() &&
                    normalized.ends_with(rule.domain) && normalized[normalized.size()-rule.domain.size()-1]=='.')) return rule.server;
            }
            return routing.final;
        }
        inline auto endpoint(std::size_t index) const -> io::endpoint {
            auto const& server=routing.servers[index];
            if (server.ipv6) return io::endpoint(io::ipv6_address(server.address),server.port);
            io::ipv4_address::bytes_type bytes{};
            std::copy_n(server.address.begin(),4,bytes.begin());
            return io::endpoint(io::ipv4_address(bytes),server.port);
        }
    };
}
