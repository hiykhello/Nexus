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
    auto valid_domain(std::string_view name) -> bool;

    Matcher::Matcher() = default;
    Matcher::Matcher(Matcher const&) = default;
    Matcher::Matcher(Matcher&&) noexcept = default;
    auto Matcher::operator=(Matcher const&) -> Matcher& = default;
    auto Matcher::operator=(Matcher&&) noexcept -> Matcher& = default;
    Matcher::~Matcher() = default;

    namespace {
        auto address(std::string_view text, std::array<std::uint8_t, 16>& out) -> unsigned {
            if (text.empty() || text.size() >= INET6_ADDRSTRLEN || text.find('\0') != std::string_view::npos) return 0;
            char buffer[INET6_ADDRSTRLEN]{};
            std::memcpy(buffer, text.data(), text.size());
            auto family = text.find(':') == std::string_view::npos ? AF_INET : AF_INET6;
            return ::inet_pton(family, buffer, out.data()) == 1 ? static_cast<unsigned>(family) : 0;
        }

        auto suffix_matches(std::string_view domain, std::string_view suffix) -> bool {
            if (domain.size() < suffix.size()) return false;
            auto start = domain.size() - suffix.size();
            if (start != 0 && domain[start - 1] != '.') return false;
            for (std::size_t i = 0; i < suffix.size(); ++i) {
                auto c = domain[start + i];
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
                if (c != suffix[i]) return false;
            }
            return true;
        }

        auto prefix_matches(std::array<std::uint8_t, 16> const& network,
                            std::array<std::uint8_t, 16> const& candidate, unsigned bits) -> bool {
            auto bytes = bits / 8;
            if (!std::equal(network.begin(), network.begin() + bytes, candidate.begin())) return false;
            auto remaining = bits % 8;
            if (remaining == 0) return true;
            auto mask = static_cast<std::uint8_t>(0xffU << (8 - remaining));
            return (network[bytes] & mask) == (candidate[bytes] & mask);
        }
    }

    auto Matcher::compile(RuleSet const& set) -> std::expected<Matcher, Error> {
        if (set.rules.size() > max_rules) return std::unexpected(Error{ErrorCode::limit, "too many rules"});
        Matcher result;
        result.entries_.reserve(set.rules.size());
        for (auto const& input : set.rules) {
            auto rule = normalize_rule(input);
            if (!rule) return std::unexpected(std::move(rule.error()));
            Entry entry;
            if (rule->type == "domain-suffix") {
                entry.suffix = std::move(rule->value);
            } else {
                auto slash = rule->value.find('/');
                auto prefix = std::string_view(rule->value).substr(slash + 1);
                entry.family = address(std::string_view(rule->value).substr(0, slash), entry.address);
                auto parsed = std::from_chars(prefix.data(), prefix.data() + prefix.size(), entry.prefix);
                if (!entry.family || parsed.ec != std::errc{} || parsed.ptr != prefix.data() + prefix.size())
                    return std::unexpected(Error{ErrorCode::invalid_rule, "invalid IP prefix"});
            }
            result.entries_.push_back(std::move(entry));
        }
        return result;
    }

    auto Matcher::match(MatchInput input) const -> std::expected<std::optional<std::size_t>, Error> {
        if (input.domain && !valid_domain(*input.domain))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid ASCII domain"});
        std::array<std::uint8_t, 16> bytes{};
        unsigned family = 0;
        if (input.ip && !(family = address(*input.ip, bytes)))
            return std::unexpected(Error{ErrorCode::invalid_query, "invalid IP address"});
        for (std::size_t i = 0; i < entries_.size(); ++i) {
            auto const& entry = entries_[i];
            if ((!entry.suffix.empty() && input.domain && suffix_matches(*input.domain, entry.suffix)) ||
                (entry.family && entry.family == family && prefix_matches(entry.address, bytes, entry.prefix)))
                return std::optional<std::size_t>(i);
        }
        return std::optional<std::size_t>{};
    }
    auto RouteMatcher::compile(std::span<RouteRule const> rules, std::size_t default_outbound,
                               std::size_t outbound_count) -> std::expected<RouteMatcher, Error> {
        if (!outbound_count || default_outbound>=outbound_count || rules.size()>max_rules)
            return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route action or rule count"});
        RuleSet flattened;
        RouteMatcher result;
        result.default_outbound_=default_outbound;
        for (auto const& rule : rules) {
            if (rule.outbound>=outbound_count || rule.predicates.rules.empty() ||
                rule.predicates.rules.size()>max_rules-flattened.rules.size())
                return std::unexpected(Error{ErrorCode::invalid_rule,"invalid route rule or action"});
            for (auto const& predicate : rule.predicates.rules) {
                result.ip_predicates_.push_back(predicate.type=="ip-cidr");
                flattened.rules.push_back(predicate);
            }
            result.actions_.insert(result.actions_.end(),rule.predicates.rules.size(),rule.outbound);
        }
        auto matcher=Matcher::compile(flattened);
        if (!matcher) return std::unexpected(std::move(matcher.error()));
        result.matcher_=std::move(*matcher);
        return result;
    }
    auto RouteMatcher::preflight(std::string_view domain) const
        -> std::expected<std::optional<std::size_t>, Error> {
        auto matched=matcher_.match({domain,{}});
        if (!matched) return std::unexpected(std::move(matched.error()));
        auto selected=*matched ? actions_[**matched] : default_outbound_;
        auto limit=*matched ? **matched : actions_.size();
        for (std::size_t i=0;i<limit;++i)
            if (ip_predicates_[i] && actions_[i]!=selected) return std::optional<std::size_t>{};
        return std::optional<std::size_t>(selected);
    }
    auto RouteMatcher::match(MatchInput input) const -> std::expected<std::size_t, Error> {
        auto result=matcher_.match(input);
        if (!result) return std::unexpected(std::move(result.error()));
        auto first=*result;
        if (input.ip) {
            std::array<std::uint8_t,16> bytes{};
            if (address(*input.ip,bytes)==AF_INET6 &&
                std::all_of(bytes.begin(),bytes.begin()+10,[](auto byte) { return byte==0; }) &&
                bytes[10]==0xff && bytes[11]==0xff) {
                char text[INET_ADDRSTRLEN]{};
                if (!::inet_ntop(AF_INET,bytes.data()+12,text,sizeof(text)))
                    return std::unexpected(Error{ErrorCode::invalid_query,"cannot format mapped address"});
                auto mapped=matcher_.match({input.domain,std::string_view(text)});
                if (!mapped) return std::unexpected(std::move(mapped.error()));
                if (*mapped && (!first || **mapped<*first)) first=**mapped;
            }
        }
        return first ? actions_[*first] : default_outbound_;
    }
}
