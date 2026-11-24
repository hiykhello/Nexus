export module dns.cache_types;
import std;
import dns.message;

export namespace dns {
    enum class CacheError { invalid_key, invalid_answer, time_reversed, stale_generation, stale_query, generation_exhausted, query_limit, disabled, reader_required };
    enum class NegativeKind { name_not_found, no_data };
    struct CacheKey {
        std::uint64_t view;
        std::string name;
        std::uint16_t type;
    };
    struct CacheToken { std::uint64_t generation; std::uint64_t query; };
    struct StaleAddressAnswer { AddressAnswer answer; std::uint64_t age_ms; };
}

export namespace dns::detail {
    // A valid logical length alone does not bound an rvalue's reserved storage.
    // Compact only oversized inputs; ordinary resolver results keep their buffers.
    inline auto compact_name_storage(std::string& name) -> bool {
        constexpr std::size_t limit = 254;
        if (name.capacity() <= limit) return true;
        std::string compact(name.data(), name.size());
        if (compact.capacity() > limit) return false;
        name = std::move(compact);
        return true;
    }

    inline auto compact_key_storage(CacheKey& key) -> bool { return compact_name_storage(key.name); }

    inline auto compact_answer_storage(AddressAnswer& answer) -> bool {
        if (!compact_name_storage(answer.canonical_name)) return false;
        if (answer.chain.capacity() > 16) {
            std::vector<std::string> compact(answer.chain.begin(), answer.chain.end());
            if (compact.capacity() > 16) return false;
            answer.chain = std::move(compact);
        }
        for (auto& name : answer.chain) if (!compact_name_storage(name)) return false;
        if (answer.addresses.capacity() > 128) {
            std::vector<Address> compact(answer.addresses.begin(), answer.addresses.end());
            if (compact.capacity() > 128) return false;
            answer.addresses = std::move(compact);
        }
        return true;
    }

    struct SnapshotKeyHash {
        auto operator()(CacheKey const& key) const noexcept -> std::size_t {
            auto hash = std::hash<std::string>{}(key.name);
            hash ^= std::hash<std::uint64_t>{}(key.view) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            hash ^= std::hash<std::uint16_t>{}(key.type) + 0x9e3779b9 + (hash << 6) + (hash >> 2);
            return hash;
        }
    };

    struct SnapshotKeyEqual {
        auto operator()(CacheKey const& a, CacheKey const& b) const noexcept -> bool {
            return a.view == b.view && a.type == b.type && a.name == b.name;
        }
    };
}
