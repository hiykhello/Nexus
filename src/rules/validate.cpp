module;
#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

module nexus.rules;
import std;

namespace nexus::rules {
    auto Rule::operator==(Rule const& other) const -> bool {
        return type == other.type && value == other.value;
    }

    auto RuleSet::operator==(RuleSet const& other) const -> bool {
        if (rules.size() != other.rules.size()) return false;
        for (std::size_t i = 0; i < rules.size(); ++i) {
            if (!(rules[i] == other.rules[i])) return false;
        }
        return true;
    }

    auto valid_domain(std::string_view name) -> bool {
        if (name.empty() || name.size() > 253) return false;
        std::size_t label_start = 0;
        for (std::size_t i = 0; i <= name.size(); ++i) {
            if (i == name.size() || name[i] == '.') {
                auto length = i - label_start;
                if (length == 0 || length > 63 || name[label_start] == '-' || name[i - 1] == '-') return false;
                label_start = i + 1;
                continue;
            }
            unsigned char c = static_cast<unsigned char>(name[i]);
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
                return false;
        }
        return true;
    }

    namespace {
        auto invalid(std::string message) -> std::unexpected<Error> {
            return std::unexpected(Error{ErrorCode::invalid_rule, std::move(message)});
        }

        auto normalize_domain(std::string& name) -> bool {
            if (!valid_domain(name)) return false;
            for (std::size_t i = 0; i < name.size(); ++i) {
                unsigned char c = static_cast<unsigned char>(name[i]);
                if (c >= 'A' && c <= 'Z') name[i] = static_cast<char>(c + ('a' - 'A'));
            }
            return true;
        }

        auto valid_cidr(std::string const& value) -> bool {
            if (value.find('\0') != std::string::npos) return false;
            auto slash = value.find('/');
            if (slash == std::string::npos || slash == 0 || slash + 1 == value.size()) return false;
            if (value.find('/', slash + 1) != std::string::npos) return false;
            auto address = value.substr(0, slash);
            auto prefix = std::string_view(value).substr(slash + 1);
            unsigned bits = 0;
            auto [end, error] = std::from_chars(prefix.data(), prefix.data() + prefix.size(), bits);
            if (error != std::errc{} || end != prefix.data() + prefix.size()) return false;
            std::array<std::uint8_t, 16> bytes{};
            int family = address.find(':') == std::string::npos ? AF_INET : AF_INET6;
            return bits <= (family == AF_INET ? 32U : 128U) &&
                   ::inet_pton(family, address.c_str(), bytes.data()) == 1;
        }
    }

    auto normalize_rule(Rule rule) -> std::expected<Rule, Error> {
        if (rule.type == "domain-suffix") {
            if (!normalize_domain(rule.value)) return invalid("invalid ASCII domain suffix");
        } else if (rule.type == "ip-cidr") {
            if (!valid_cidr(rule.value)) return invalid("invalid IPv4/IPv6 CIDR");
        } else {
            return invalid("unsupported rule type: " + rule.type);
        }
        return rule;
    }
}
