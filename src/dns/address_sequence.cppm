export module dns.address_sequence;
import std;
export import dns.corosio_resolver;

export namespace dns::detail {
    enum class AddressStrategy { prefer_ipv4, prefer_ipv6, ipv4_only, ipv6_only };
    using FamilyCachePolicy=std::array<bool,2>; // disable-cache for A, AAAA
    inline auto address_types(AddressStrategy strategy) noexcept -> std::array<std::uint16_t,2> {
        return strategy==AddressStrategy::prefer_ipv6 || strategy==AddressStrategy::ipv6_only ?
            std::array<std::uint16_t,2>{28,1} : std::array<std::uint16_t,2>{1,28};
    }
    inline auto address_type_count(AddressStrategy strategy) noexcept -> unsigned {
        return strategy==AddressStrategy::ipv4_only || strategy==AddressStrategy::ipv6_only ? 1u : 2u;
    }
    template<bool Full> using AddressResult=std::conditional_t<Full,AddressAnswer,std::vector<Address>>;

    // Every selected question belongs to one lookup and one absolute deadline.
    // Preserve the distinction between NODATA and contradictory NXDOMAIN, and
    // never combine address families with different terminal names.
    template<bool Full>
    class AddressAnswers {
        AddressAnswer answer_;
        bool no_data_=false;
    public:
        auto add(std::expected<AddressAnswer,ResolveError> result) -> std::expected<void,ResolveError> {
            if (!result) {
                if (result.error()==ResolveError::no_data) { no_data_=true; return {}; }
                if (result.error()==ResolveError::name_not_found && (!answer_.addresses.empty() || no_data_))
                    return std::unexpected(ResolveError::protocol);
                return std::unexpected(result.error());
            }
            if (!answer_.canonical_name.empty() && answer_.canonical_name!=result->canonical_name)
                return std::unexpected(ResolveError::protocol);
            if (result->addresses.size()>64-answer_.addresses.size()) return std::unexpected(ResolveError::limit);
            if (answer_.canonical_name.empty()) {
                answer_.canonical_name=std::move(result->canonical_name);
                answer_.addresses=std::move(result->addresses);
                answer_.ttl=result->ttl;
                if constexpr (Full) answer_.chain=std::move(result->chain);
            } else {
                answer_.addresses.insert(answer_.addresses.end(),result->addresses.begin(),result->addresses.end());
                if (result->ttl) answer_.ttl=answer_.ttl ? std::min(*answer_.ttl,*result->ttl) : result->ttl;
            }
            return {};
        }
        auto finish() -> std::expected<AddressResult<Full>,ResolveError> {
            if (answer_.addresses.empty()) return std::unexpected(ResolveError::no_data);
            if constexpr (Full) return std::move(answer_);
            else return std::move(answer_.addresses);
        }
    };
}
