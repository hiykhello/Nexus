// Bridges executor-owned DNS message rows to "NXDN03" policy shards.
export module cli.dns_cache_unified;
import std;
import cli.dns_transports;
import config;
import corosio;
import dns.message_cache;
import dns.message_exchange;
import rulefile;
import state.dns_cache;
import state.serde;

export namespace cli {
    class UnifiedDnsCache {
        ::state::DnsCache disk_;
        ::state::Fingerprint fingerprint_;
        std::vector<bool> persistent_;
        std::size_t limit_;
        std::optional<std::uint64_t> epoch_;
        std::uint64_t view_ = 0;
        mutable std::mutex save_mutex_;
        mutable std::optional<std::pair<std::uint64_t, ::state::Fingerprint>> last_saved_;
        static constexpr std::size_t prefix_bytes = 10, row_bytes = 27;

        static auto wall_seconds() noexcept -> std::uint64_t {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        auto decode(std::span<std::byte const> bytes, dns::MessageCache& cache) const
            -> std::expected<void, std::string> {
            ::state::Reader input{bytes};
            auto rows = input.number(2), saved = input.number(8), now = wall_seconds();
            if (input.invalid || rows > 256 || saved > now) return std::unexpected("invalid DNS cache shard");
            auto elapsed = static_cast<std::uint32_t>(std::min<std::uint64_t>(now - saved, 600) + 1);
            auto clock = std::chrono::steady_clock::now();
            for (std::uint64_t index = 0; index < rows; ++index) {
                auto upstream = input.number(2);
                auto flags = input.number(1);
                auto port = static_cast<std::uint16_t>(input.number(2));
                auto address = input.take(16);
                auto ttl = input.number(2);
                auto query_size = input.number(2), answer_size = input.number(2);
                auto question = input.take(query_size), answer = input.take(answer_size);
                if (input.invalid || upstream >= persistent_.size() || !persistent_[upstream] || flags > 3 ||
                    !port || !ttl || ttl > 600 || question.empty() || answer.empty()) break;
                std::array<std::uint8_t, 16> raw;
                std::memcpy(raw.data(), address.data(), raw.size());
                corosio::endpoint endpoint;
                if (flags & 1) endpoint = {corosio::ipv6_address(raw), port};
                else {
                    std::array<std::uint8_t, 4> ipv4;
                    std::ranges::copy(raw | std::views::take(4), ipv4.begin());
                    endpoint = {corosio::ipv4_address(ipv4), port};
                }
                auto query = std::span(reinterpret_cast<std::uint8_t const*>(question.data()), question.size());
                auto response = reinterpret_cast<std::uint8_t const*>(answer.data());
                if (!cache.restore({static_cast<std::size_t>(upstream), endpoint, bool(flags & 2), nullptr, view_}, query,
                    {response, response + answer.size()}, static_cast<std::uint32_t>(ttl), elapsed, clock)) break;
                if (index + 1 == rows && input.complete()) return {};
            }
            if (!rows && input.complete()) return {};
            cache.clear();
            return std::unexpected("invalid DNS cache shard rows");
        }

        static auto append_be32(std::string& out, std::uint64_t value) -> void {
            for (unsigned i = 4; i > 0; --i) out.push_back(static_cast<char>(value >> ((i - 1) * 8)));
        }

    public:
        UnifiedDnsCache(config::DnsRouting const& routing, std::span<dns::MessageUpstream const> upstreams)
            : disk_(routing.unified_cache_root, routing.unified_cache_bytes),
              limit_(std::min(routing.unified_cache_bytes - ::state::header_bytes, ::state::dns_shard_payload)) {
            (void)upstreams;
            std::string identity("NXDN03");
            append_be32(identity, routing.message_cache_policy.size());
            identity += routing.message_cache_policy;
            if (!routing.cache_rule_fingerprints.empty()) {
                append_be32(identity, routing.cache_rule_fingerprints.size());
                identity += routing.cache_rule_fingerprints;
            }
            for (auto const& server : routing.servers) {
                append_be32(identity, server.upstream ? server.upstream->binding.routing_mark.value_or(0) : 0);
            }
            for (auto const& server : routing.servers) {
                // Local snapshots are process-local; numeric, TLS, and detour upstreams
                // are cacheable because their detour/trust identities enter the shard hash.
                persistent_.push_back(bool(server.upstream));
                if (server.upstream && server.upstream->detour) {
                    identity.push_back('|');
                    identity.append(*server.upstream->detour);
                }
                if (!server.upstream || !server.upstream->tls) continue;
                if (server.upstream->tls->ca_file.empty()) {
                    identity.append("|system-ca:");
                    auto sys_id = dns_system_trust_identity();
                    if (!sys_id) throw std::runtime_error(sys_id.error());
                    identity.append(*sys_id);
                } else {
                    identity.append("|ca-file:");
                    auto trust = ::rulefile::read_regular_file(server.upstream->tls->ca_file);
                    if (!trust) throw std::runtime_error("cannot read DNS cache trust identity");
                    auto hash = ::state::fingerprint(std::as_bytes(std::span(*trust)));
                    identity.append(reinterpret_cast<char const*>(hash.data()), hash.size());
                }
            }
            fingerprint_ = ::state::fingerprint(std::as_bytes(std::span(identity)));
        }

        [[nodiscard]] auto identity_fingerprint() const noexcept -> ::state::Fingerprint const& { return fingerprint_; }
        [[nodiscard]] auto active_epoch() const noexcept -> std::optional<std::uint64_t> {
            std::lock_guard lock(save_mutex_);
            return epoch_;
        }

        auto restore(dns::MessageCache& cache, std::uint64_t view) -> std::expected<void, std::string> {
            view_ = view;
            auto loaded = disk_.lookup(fingerprint_);
            if (!loaded) return std::unexpected(std::string(::state::describe(loaded.error().stage)));
            {
                std::lock_guard lock(save_mutex_);
                epoch_ = loaded->epoch;
                last_saved_.reset();
            }
            if (loaded->payload) return decode(*loaded->payload, cache);
            return {};
        }

        auto refresh_epoch() -> std::expected<void, std::string> {
            bool has_epoch = false;
            {
                std::lock_guard lock(save_mutex_);
                last_saved_.reset();
                has_epoch = epoch_.has_value();
            }
            if (!has_epoch) return {};
            auto current = disk_.epoch();
            if (!current) return std::unexpected(std::string(::state::describe(current.error().stage)));
            std::lock_guard lock(save_mutex_);
            if (epoch_ && *current >= *epoch_) epoch_ = *current;
            last_saved_.reset();
            return {};
        }

        struct PendingSave {
            std::uint64_t epoch = 0;
            ::state::Bytes body;
            ::state::Fingerprint content_hash{};
        };

        auto prepare_save(dns::MessageCache const& cache, std::uint64_t view) const -> std::optional<PendingSave> {
            std::optional<std::uint64_t> captured_epoch;
            {
                std::lock_guard lock(save_mutex_);
                captured_epoch = epoch_;
            }
            if (!captured_epoch || view != view_) return {};
            auto rows = cache.checkpoint(std::chrono::steady_clock::now(), limit_ - prefix_bytes, row_bytes,
                [&](dns::MessageCache::View const& key) {
                    return key.policy_view == view && !key.local && key.upstream < persistent_.size() &&
                        persistent_[key.upstream];
                });
            ::state::Bytes body;
            ::state::append_le(body, rows.size(), 2);
            ::state::append_le(body, wall_seconds(), 8);
            for (auto const& [key, query, answer, ttl] : rows) {
                ::state::append_le(body, key.upstream, 2);
                ::state::append_le(body, key.ipv6 | (key.tcp << 1), 1);
                ::state::append_le(body, key.port, 2);
                body.append_range(std::as_bytes(std::span(key.address)));
                ::state::append_le(body, ttl, 2);
                ::state::append_le(body, query.size(), 2);
                ::state::append_le(body, answer.size(), 2);
                body.append_range(std::as_bytes(std::span(query)));
                body.append_range(std::as_bytes(std::span(answer)));
            }
            auto content_hash = ::state::fingerprint(std::span(body).subspan(prefix_bytes));
            {
                std::lock_guard lock(save_mutex_);
                if (!epoch_ || *epoch_ != *captured_epoch) return {};
                if (last_saved_ && last_saved_->first == *captured_epoch && last_saved_->second == content_hash) return {};
            }
            return PendingSave{*captured_epoch, std::move(body), content_hash};
        }

        auto commit_save(PendingSave const& pending) -> std::expected<void, std::string> {
            std::lock_guard lock(save_mutex_);
            if (last_saved_ && last_saved_->first == pending.epoch && last_saved_->second == pending.content_hash) return {};
            auto saved = disk_.store(fingerprint_, pending.epoch, pending.body);
            if (!saved && saved.error().stage != ::state::Stage::stale_epoch)
                return std::unexpected(std::string(::state::describe(saved.error().stage)));
            if (saved && (!last_saved_ || pending.epoch >= last_saved_->first))
                last_saved_ = {pending.epoch, pending.content_hash};
            return {};
        }

        auto save(dns::MessageCache const& cache, std::uint64_t view) -> std::expected<void, std::string> {
            auto pending = prepare_save(cache, view);
            if (!pending) return {};
            return commit_save(*pending);
        }
    };

    class AsyncDnsCheckpointer {
        std::mutex mutex_;
        std::condition_variable cv_;
        std::function<void()> pending_;
        bool busy_ = false, stopping_ = false;
        std::thread worker_;

        auto run() -> void {
            std::unique_lock lock(mutex_);
            for (;;) {
                cv_.wait(lock, [this] { return stopping_ || static_cast<bool>(pending_); });
                if (!pending_ && stopping_) return;
                auto job = std::exchange(pending_, {});
                busy_ = true;
                lock.unlock();
                if (job) job();
                lock.lock();
                busy_ = false;
                cv_.notify_all();
            }
        }
    public:
        ~AsyncDnsCheckpointer() { stop(); }

        auto submit(std::function<void()> job) -> void {
            std::lock_guard lock(mutex_);
            if (stopping_) return;
            if (!worker_.joinable()) worker_ = std::thread([this] { run(); });
            pending_ = std::move(job);
            cv_.notify_one();
        }

        auto flush() noexcept -> void {
            std::unique_lock lock(mutex_);
            if (!worker_.joinable()) return;
            cv_.wait(lock, [this] { return !busy_ && !pending_; });
        }

        auto stop() noexcept -> void {
            std::thread to_join;
            {
                std::lock_guard lock(mutex_);
                stopping_ = true;
                to_join = std::move(worker_);
            }
            cv_.notify_all();
            if (to_join.joinable()) to_join.join();
            std::lock_guard lock(mutex_);
            stopping_ = false;
        }
    };
}
