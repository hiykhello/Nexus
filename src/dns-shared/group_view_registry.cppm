// Generation-local DNS view registry module.
export module dns.group_view_registry;
import std;
import corosio;
import dns.corosio_query;
import dns.message;

export namespace dns_hp_experiment {
    class ViewRegistry {
    public:
        enum class Error { invalid, limit, allocation, sealed, not_sealed, wrong_owner };
        class Profile {
            friend class ViewRegistry;
            ViewRegistry const* owner_;
            std::size_t index_;
            std::shared_ptr<dns::detail::ProtectedQuery const> protection_;
            Profile(ViewRegistry const& owner, std::size_t index,
                    std::shared_ptr<dns::detail::ProtectedQuery const> protection) noexcept
                : owner_(&owner), index_(index), protection_(std::move(protection)) {}
        public:
            [[nodiscard]] auto protection() const noexcept -> std::shared_ptr<dns::detail::ProtectedQuery const> {
                return protection_;
            }
        };
    private:
        struct Hop {
            std::array<std::uint8_t, 16> address{};
            std::string host;
            std::uint16_t port = 0;
            bool ipv6 = false, tcp = false;
            std::shared_ptr<dns::detail::ProtectedQuery const> protection{};
            auto operator==(Hop const&) const -> bool = default;
        };
        struct Policy {
            std::vector<Hop> chain;
            std::uint32_t strategy = 0;
            bool edns = false, disable_cache = false;
            auto operator==(Policy const&) const -> bool = default;
            [[nodiscard]] auto charge() const noexcept -> std::size_t {
                auto result = sizeof(Policy) + chain.capacity() * sizeof(Hop);
                for (auto const& hop : chain) result += hop.host.capacity() + 1;
                return result;
            }
        };
        using Endpoint = corosio::endpoint;
        using ViewKey = std::tuple<std::size_t, Endpoint, std::optional<dns::ClientSubnet>, std::uint32_t>;
        mutable std::mutex mutex_;
        std::vector<Policy> policies_;
        std::map<ViewKey, std::uint64_t> views_;
        std::size_t max_profiles_, max_policy_bytes_, max_views_, policy_bytes_ = 0;
        bool sealed_ = false;

        template<class Routing>
        static auto policy(Routing const& routing, std::size_t selected) -> std::expected<Policy, Error> {
            if (routing.servers.empty() || routing.servers.size() > 64 || selected >= routing.servers.size())
                return std::unexpected(Error::invalid);
            Policy result;
            result.strategy = static_cast<std::uint32_t>(routing.strategy);
            result.edns = routing.edns;
            result.disable_cache = routing.disable_cache;
            result.chain.reserve(routing.servers.size());
            std::array<bool, 64> visited{};
            for (;;) {
                if (visited[selected]) return std::unexpected(Error::invalid);
                visited[selected] = true;
                auto const& server = routing.servers[selected];
                if (server.host.size() > 254) return std::unexpected(Error::invalid);
                Hop hop{server.address, std::string(server.host), server.port, server.ipv6, server.tcp};
                if constexpr (requires { server.protection; }) hop.protection = server.protection;
                if (!hop.host.empty()) {
                    bool absolute = hop.host.ends_with('.');
                    if (!dns::canonicalize_name(hop.host) || !hop.port)
                        return std::unexpected(Error::invalid);
                    if (absolute && hop.host != ".") hop.host.push_back('.');
                }
                result.chain.push_back(std::move(hop));
                if (server.host.empty()) {
                    if (server.resolver) return std::unexpected(Error::invalid);
                    break;
                }
                if (!server.resolver || *server.resolver >= routing.servers.size()) return std::unexpected(Error::invalid);
                selected = *server.resolver;
            }
            return result;
        }
    public:
        ViewRegistry(std::size_t profiles, std::size_t policy_bytes, std::size_t views)
            : max_profiles_(profiles), max_policy_bytes_(policy_bytes), max_views_(views) {
            policies_.reserve(profiles);
        }
        ViewRegistry(ViewRegistry const&) = delete;
        template<class Routing>
        [[nodiscard]] auto register_profile(Routing const& routing, std::size_t selected) -> std::expected<Profile, Error> {
            std::lock_guard lock(mutex_);
            if (sealed_) return std::unexpected(Error::sealed);
            try {
                auto candidate = policy(routing, selected);
                if (!candidate) return std::unexpected(candidate.error());
                auto found = std::ranges::find(policies_, *candidate);
                if (found != policies_.end())
                    return Profile(*this, static_cast<std::size_t>(found - policies_.begin()), found->chain.front().protection);
                auto charge = candidate->charge();
                if (policies_.size() >= max_profiles_ || charge > max_policy_bytes_ - policy_bytes_)
                    return std::unexpected(Error::limit);
                policies_.push_back(std::move(*candidate));
                policy_bytes_ += charge;
                return Profile(*this, policies_.size() - 1, policies_.back().chain.front().protection);
            } catch (std::bad_alloc const&) { return std::unexpected(Error::allocation); }
        }
        auto seal() noexcept -> void { std::lock_guard lock(mutex_); sealed_ = true; }
        [[nodiscard]] auto sealed() const noexcept -> bool { std::lock_guard lock(mutex_); return sealed_; }
        template<class Routing>
        [[nodiscard]] auto matches(Profile profile, Routing const& routing, std::size_t selected) -> std::expected<bool, Error> {
            std::lock_guard lock(mutex_);
            if (profile.owner_ != this || profile.index_ >= policies_.size()) return std::unexpected(Error::wrong_owner);
            try {
                auto candidate = policy(routing, selected);
                if (!candidate) return std::unexpected(candidate.error());
                return *candidate == policies_[profile.index_];
            } catch (std::bad_alloc const&) { return std::unexpected(Error::allocation); }
        }
        [[nodiscard]] auto view(Profile profile, Endpoint endpoint, std::optional<dns::ClientSubnet> subnet = {},
            std::uint32_t rule_scope = 0)
            -> std::expected<std::uint64_t, Error> {
            std::lock_guard lock(mutex_);
            if (profile.owner_ != this || profile.index_ >= policies_.size()) return std::unexpected(Error::wrong_owner);
            if (!sealed_) return std::unexpected(Error::not_sealed);
            if (!endpoint.port() || (subnet && !dns::valid_client_subnet(*subnet))) return std::unexpected(Error::invalid);
            ViewKey key{profile.index_, endpoint, subnet, rule_scope};
            if (auto found = views_.find(key); found != views_.end()) return found->second;
            if (views_.size() >= max_views_ || views_.size() >= std::numeric_limits<std::uint64_t>::max())
                return std::unexpected(Error::limit);
            auto id = static_cast<std::uint64_t>(views_.size()) + 1;
            try { views_.emplace(std::move(key), id); }
            catch (std::bad_alloc const&) { return std::unexpected(Error::allocation); }
            return id;
        }
        [[nodiscard]] auto counts() const noexcept -> std::pair<std::size_t, std::size_t> {
            std::lock_guard lock(mutex_);
            return {policies_.size(), views_.size()};
        }
        [[nodiscard]] auto policy_bytes() const noexcept -> std::size_t {
            std::lock_guard lock(mutex_);
            return policy_bytes_;
        }
    };

    class ViewBinding {
        using Endpoint = corosio::endpoint;
        struct Entry {
            ViewRegistry::Profile profile;
            std::optional<Endpoint> endpoint;
            std::optional<dns::ClientSubnet> subnet;
            std::uint32_t rule_scope = 0;
            std::uint64_t view = 0;
        };
        ViewRegistry& registry_;
        std::vector<Entry> entries_;
    public:
        ViewBinding(ViewRegistry& registry, std::span<ViewRegistry::Profile const> profiles) : registry_(registry) {
            entries_.reserve(profiles.size());
            for (auto profile : profiles) entries_.push_back({profile, {}, {}, 0, {}});
        }
        ViewBinding(ViewBinding const&) = delete;
        [[nodiscard]] auto protection(std::size_t index) const noexcept -> std::shared_ptr<dns::detail::ProtectedQuery const> {
            return entries_[index].profile.protection();
        }
        [[nodiscard]] auto view(std::size_t index, Endpoint endpoint, std::optional<dns::ClientSubnet> subnet = {},
            std::uint32_t rule_scope = 0)
            -> std::expected<std::uint64_t, ViewRegistry::Error> {
            if (index >= entries_.size()) return std::unexpected(ViewRegistry::Error::invalid);
            auto& entry = entries_[index];
            if (entry.endpoint && *entry.endpoint == endpoint && entry.subnet == subnet && entry.rule_scope == rule_scope) return entry.view;
            auto result = registry_.view(entry.profile, endpoint, subnet, rule_scope);
            if (result) { entry.endpoint = endpoint; entry.subnet = subnet; entry.rule_scope = rule_scope; entry.view = *result; }
            return result;
        }
    };
}
