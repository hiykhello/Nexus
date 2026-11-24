// Per-user inbound connection, stream and bandwidth limit parser implementation.
module config;
import std;
import glaze;
import config.kdl_common;

namespace config {
    using namespace config::kdl;
    auto inbound(Node const& node, Config& result) -> std::expected<std::uint16_t, std::string>;

    auto inbound_with_limits(Node const& node, Config& parsed, Node const*& limits)
        -> std::expected<std::uint16_t, std::string> {
        auto found = std::ranges::find(node.children, std::string_view("user-limits"), &Node::name);
        if (found == node.children.end()) return inbound(node, parsed);
        limits = &*found;
        auto protocol = node;
        protocol.children.erase(protocol.children.begin() + (found - node.children.begin()));
        return inbound(protocol, parsed);
    }

    auto parse_user_limits(InboundConfig& inbound, Node const* block) -> std::expected<void, std::string> {
        auto& limits = inbound.user_limits;
        if (inbound.password_auth) limits.push_back({inbound.password_auth->username});
        if (inbound.trojan)
            for (auto const& user : inbound.trojan->users) limits.push_back({user.name});
        if (inbound.anytls)
            for (auto const& user : inbound.anytls->users) limits.push_back({user.name});
        if (inbound.shadowtls)
            for (auto const& user : inbound.shadowtls->users) limits.push_back({user.username});
        if (inbound.vless)
            for (auto const& user : inbound.vless->users) limits.push_back({user.name});
        if (inbound.shadowsocks)
            for (auto const& user : inbound.shadowsocks->users) limits.push_back({user.name});
        if (inbound.hysteria2)
            for (auto const& user : inbound.hysteria2->connection.users) limits.push_back({user.name});
        if (inbound.tuic)
            for (auto const& user : inbound.tuic->users) limits.push_back({user.name});
        if (inbound.naive)
            for (auto const& user : inbound.naive->users) limits.push_back({user.name});
        if (!block) return {};
        if (limits.empty() || block->tag || !block->arguments.empty() || !block->properties.empty() || block->children.empty())
            return error("user-limits requires an inbound with named users and one or more user entries");
        auto metered = inbound.anytls || inbound.trojan || inbound.hysteria2 || inbound.tuic ||
            inbound.vless || inbound.shadowtls || inbound.shadowsocks || inbound.naive || inbound.password_auth;
        for (auto const& row : block->children) {
            auto name = argument(row);
            if (row.name != "user" || !name || row.properties.empty() || !row.children.empty())
                return error("user-limits requires named users with connection or stream limits");
            auto target = std::ranges::find(limits, *name, &UserLimits::name);
            if (target == limits.end() || target->connections || target->streams ||
                target->byte_quota || target->bytes_per_second || target->burst_bytes)
                return error("unknown or duplicate user-limits user");
            for (auto const& [field, value] : row.properties) {
                auto count = integer(value);
                if (!count) return error("user limit must be a nonnegative integer");
                if (field == "connections" && !target->connections && *count <= 4096) target->connections = *count;
                else if (field == "streams" && !target->streams && *count <= 4096 &&
                    (inbound.anytls || inbound.vless || inbound.hysteria2 || inbound.tuic)) target->streams = *count;
                else if (field == "byte-quota" && metered && !target->byte_quota) target->byte_quota = *count;
                else if (field == "bytes-per-second" && metered && !target->bytes_per_second && *count && *count <= 1000000000)
                    target->bytes_per_second = static_cast<std::uint32_t>(*count);
                else if (field == "burst-bytes" && metered && !target->burst_bytes && *count && *count <= 16 * 1024 * 1024)
                    target->burst_bytes = static_cast<std::uint32_t>(*count);
                else return error("invalid, unsupported or duplicate user limit");
            }
            if (target->burst_bytes && !target->bytes_per_second)
                return error("burst-bytes requires bytes-per-second");
        }
        return {};
    }
}
