// Bridges executor-owned DNS message rows to "NXDN03" policy shards.
#pragma once
namespace cli {
    class UnifiedDnsCache {
        ::state::DnsCache disk_;
        ::state::Fingerprint fingerprint_;
        DnsCacheState::Scope scope_;
        std::string legacy_;
        std::vector<bool> persistent_;
        std::size_t limit_;
        std::optional<std::uint64_t> epoch_;
        std::uint64_t view_=0;
        mutable std::optional<::state::Fingerprint> last_saved_hash_;
        static constexpr std::size_t prefix_bytes=10, row_bytes=27;

        static auto wall_seconds() noexcept -> std::uint64_t {
            return std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        auto decode(std::span<std::byte const> bytes,dns::MessageCache& cache) const
            -> std::expected<void,std::string> {
            ::state::Reader input{bytes};
            auto rows=input.number(2), saved=input.number(8), now=wall_seconds();
            if (input.invalid || rows>256 || saved>now) return std::unexpected("invalid DNS cache shard");
            auto elapsed=static_cast<std::uint32_t>(std::min<std::uint64_t>(now-saved,600)+1);
            auto clock=std::chrono::steady_clock::now();
            for (std::uint64_t index=0;index<rows;++index) {
                auto upstream=input.number(2);
                auto flags=input.number(1);
                auto port=static_cast<std::uint16_t>(input.number(2));
                auto address=input.take(16);
                auto ttl=input.number(2);
                auto query_size=input.number(2), answer_size=input.number(2);
                auto question=input.take(query_size), answer=input.take(answer_size);
                if (input.invalid || upstream>=persistent_.size() || !persistent_[upstream] || flags>3 ||
                    !port || !ttl || ttl>600 || question.empty() || answer.empty()) break;
                std::array<std::uint8_t,16> raw;
                std::memcpy(raw.data(),address.data(),raw.size());
                nex::corosio::endpoint endpoint;
                if (flags&1) endpoint={nex::corosio::ipv6_address(raw),port};
                else {
                    std::array<std::uint8_t,4> ipv4;
                    std::ranges::copy(raw | std::views::take(4),ipv4.begin());
                    endpoint={nex::corosio::ipv4_address(ipv4),port};
                }
                auto query=std::span(reinterpret_cast<std::uint8_t const*>(question.data()),question.size());
                auto response=reinterpret_cast<std::uint8_t const*>(answer.data());
                if (!cache.restore({static_cast<std::size_t>(upstream),endpoint,bool(flags&2),nullptr,view_},query,
                    {response,response+answer.size()},static_cast<std::uint32_t>(ttl),elapsed,clock)) break;
                if (index+1==rows && input.complete()) return {};
            }
            if (!rows && input.complete()) return {};
            cache.clear();
            return std::unexpected("invalid DNS cache shard rows");
        }

    public:
        UnifiedDnsCache(config::DnsRouting const& routing,std::span<dns::MessageUpstream const> upstreams)
            :disk_(routing.unified_cache_root,routing.unified_cache_bytes),scope_(routing,upstreams),
             legacy_(routing.message_cache_directory),
             limit_(std::min(routing.unified_cache_bytes-::state::header_bytes,::state::dns_shard_payload)) {
            auto identity=scope_.identity+routing.cache_rule_fingerprints;
            for (auto const& server:routing.servers) {
                // Local snapshots are process-local; numeric, TLS, and detour upstreams
                // are cacheable because their detour/trust identities enter the shard hash.
                persistent_.push_back(bool(server.upstream));
                if (server.upstream && server.upstream->detour) {
                    identity.push_back('|');
                    identity.append(*server.upstream->detour);
                }
                if (!server.upstream || !server.upstream->tls) continue;
                auto trust=::rulefile::read_regular_file(server.upstream->tls->ca_file);
                if (!trust) throw std::runtime_error("cannot read DNS cache trust identity");
                auto hash=::state::fingerprint(std::as_bytes(std::span(*trust)));
                identity.append(reinterpret_cast<char const*>(hash.data()),hash.size());
            }
            fingerprint_=::state::fingerprint(std::as_bytes(std::span(identity)));
        }

        auto restore(dns::MessageCache& cache,std::uint64_t view) -> std::expected<void,std::string> {
            view_=view;
            auto loaded=disk_.lookup(fingerprint_);
            if (!loaded) return std::unexpected(std::string(::state::describe(loaded.error().stage)));
            epoch_=loaded->epoch;
            if (loaded->payload) return decode(*loaded->payload,cache);
            if (!legacy_.empty() && !*epoch_) {
                for (auto& upstream:scope_.views) upstream.policy_view=view;
                auto file=DnsCacheState::open(legacy_);
                if (!file) return std::unexpected(std::move(file.error()));
                auto read=(*file)->restore(cache,scope_);
                if (!read) return read;
                return save(cache,view);
            }
            return {};
        }

        auto save(dns::MessageCache const& cache,std::uint64_t view) const -> std::expected<void,std::string> {
            if (!epoch_ || view!=view_) return {};
            auto rows=cache.checkpoint(std::chrono::steady_clock::now(),limit_-prefix_bytes,row_bytes,
                [&](dns::MessageCache::View const& key) {
                    return key.policy_view==view && !key.local && key.upstream<persistent_.size() &&
                        persistent_[key.upstream];
                });
            ::state::Bytes body;
            ::state::append_le(body,rows.size(),2);
            ::state::append_le(body,wall_seconds(),8);
            for (auto const& [key,query,answer,ttl]:rows) {
                ::state::append_le(body,key.upstream,2);
                ::state::append_le(body,key.ipv6 | (key.tcp<<1),1);
                ::state::append_le(body,key.port,2);
                body.append_range(std::as_bytes(std::span(key.address)));
                ::state::append_le(body,ttl,2);
                ::state::append_le(body,query.size(),2);
                ::state::append_le(body,answer.size(),2);
                body.append_range(std::as_bytes(std::span(query)));
                body.append_range(std::as_bytes(std::span(answer)));
            }
            auto content_hash=::state::fingerprint(std::span(body).subspan(prefix_bytes));
            if (last_saved_hash_ && *last_saved_hash_==content_hash) return {};
            auto saved=disk_.store(fingerprint_,*epoch_,body);
            if (!saved && saved.error().stage!=::state::Stage::stale_epoch)
                return std::unexpected(std::string(::state::describe(saved.error().stage)));
            if (saved) last_saved_hash_=content_hash;
            return {};
        }
    };
}
