module state.dns_cache;
import std;
import state.file;
import state.snapshot;

namespace state {
    namespace {
        const SnapshotSpec epoch_file{"epoch.state",".epoch.next",
            {.magic=dns_cache_magic,.tier=Tier::cache,.max_payload=0,.fingerprint={std::byte{'E'}}}};

        auto shard(Fingerprint const& view) -> SnapshotSpec {
            std::string name;
            constexpr std::string_view digits="0123456789abcdef";
            for (auto octet:view) {
                auto byte=std::to_integer<unsigned>(octet);
                name.push_back(digits[byte>>4]);
                name.push_back(digits[byte&15]);
            }
            return {name+".state","."+name+".next",
                {.magic=dns_cache_magic,.tier=Tier::cache,.max_payload=dns_shard_payload,.fingerprint=view}};
        }

        auto read_epoch(InstanceLock const& directory) -> std::expected<std::uint64_t,StateError> {
            auto marker=load_snapshot(directory,epoch_file);
            if (!marker) return std::unexpected(marker.error());
            if (!*marker) return 0;
            if (!(**marker).header.clear_epoch || (**marker).header.clear_epoch!=(**marker).header.revision)
                return std::unexpected(StateError{Stage::format});
            return (**marker).header.clear_epoch;
        }

        auto owned(std::string_view name) -> bool {
            return dns_shard_fingerprint(name).has_value() ||
                (name.size()==70 && name.starts_with('.') && name.ends_with(".next") &&
                 name.substr(1,64).find_first_not_of("0123456789abcdef")==name.npos);
        }

        auto discardable(Stage stage) noexcept -> bool {
            return stage==Stage::format || stage==Stage::version || stage==Stage::checksum;
        }
    }

    auto dns_shard_fingerprint(std::string_view name) noexcept -> std::optional<Fingerprint> {
        if (name.size()!=70 || !name.ends_with(".state")) return {};
        Fingerprint value{};
        for (std::size_t i=0;i<value.size();++i) {
            unsigned byte=0;
            auto* begin=name.data()+2*i;
            auto [end,status]=std::from_chars(begin,begin+2,byte,16);
            if (status!=std::errc{} || end!=begin+2 ||
                std::ranges::any_of(std::string_view(begin,2),[](char c) {return c>='A' && c<='F';})) return {};
            value[i]=static_cast<std::byte>(byte);
        }
        return value;
    }

    auto DnsCache::epoch() const -> std::expected<std::uint64_t,StateError> {
        auto lock=InstanceLock::open_child(root_,"dns");
        if (!lock) return std::unexpected(lock.error());
        return read_epoch(*lock);
    }

    auto DnsCache::lookup(Fingerprint const& view) const -> std::expected<DnsCacheShard,StateError> {
        auto lock=InstanceLock::open_child(root_,"dns");
        if (!lock) return std::unexpected(lock.error());
        auto current=read_epoch(*lock);
        if (!current) return std::unexpected(current.error());
        auto spec=shard(view);
        auto loaded=load_snapshot(*lock,spec);
        if (!loaded && !discardable(loaded.error().stage)) return std::unexpected(loaded.error());
        if (!loaded || (*loaded && (**loaded).header.clear_epoch!=*current)) {
            auto deleted=unlink_dir_file(lock->directory(),spec.name,Stage::remove_blob);
            if (!deleted) return std::unexpected(deleted.error());
            return DnsCacheShard{*current,{}};
        }
        if (!*loaded || (**loaded).payload.size()+header_bytes>budget_) return DnsCacheShard{*current,{}};
        return DnsCacheShard{*current,std::move((**loaded).payload)};
    }

    auto DnsCache::store(Fingerprint const& view,std::uint64_t captured,std::span<std::byte const> payload) const
        -> std::expected<void,StateError> {
        auto total=payload.size()+header_bytes;
        if (payload.size()>dns_shard_payload || total>budget_)
            return std::unexpected(StateError{Stage::capacity});
        auto lock=InstanceLock::open_child(root_,"dns");
        if (!lock) return std::unexpected(lock.error());
        auto current=read_epoch(*lock);
        if (!current) return std::unexpected(current.error());
        if (*current!=captured) return std::unexpected(StateError{Stage::stale_epoch});
        auto spec=shard(view);
        auto prior=load_snapshot(*lock,spec);
        if (!prior) {
            if (!discardable(prior.error().stage)) return std::unexpected(prior.error());
            auto deleted=unlink_dir_file(lock->directory(),spec.name,Stage::remove_blob);
            if (!deleted) return deleted;
        }
        auto entries=directory_entries(lock->directory(),owned);
        if (!entries) return std::unexpected(entries.error());
        std::ranges::sort(*entries,{},&DirectoryEntry::name);
        for (auto const& item:*entries) {
            if (item.name==spec.name) continue;
            if (item.private_file && dns_shard_fingerprint(item.name) && item.size<=budget_-total) total+=item.size;
            else if (auto deleted=unlink_dir_file(lock->directory(),item.name,Stage::remove_blob); !deleted) return deleted;
        }
        auto revision=prior && *prior ? (**prior).header.revision+1 : 1;
        auto saved=commit_snapshot(*lock,spec,revision,*current,payload);
        if (!saved) return std::unexpected(saved.error());
        if (saved->error) return std::unexpected(*saved->error);
        return {};
    }

    auto DnsCache::clear() const -> std::expected<void,StateError> {
        auto lock=InstanceLock::open_child(root_,"dns");
        if (!lock) return std::unexpected(lock.error());
        auto current=read_epoch(*lock);
        if (!current) return std::unexpected(current.error());
        ClearEpoch barrier(*current);
        auto next=barrier.advance();
        if (!next) return std::unexpected(next.error());
        auto saved=commit_snapshot(*lock,epoch_file,*next,*next,{});
        if (!saved) return std::unexpected(saved.error());
        if (saved->error) return std::unexpected(*saved->error);
        auto entries=directory_entries(lock->directory(),owned);
        if (!entries) return std::unexpected(entries.error());
        for (auto const& item:*entries)
            if (auto deleted=unlink_dir_file(lock->directory(),item.name,Stage::remove_blob); !deleted) return deleted;
        return sync_handle(lock->directory(),Stage::sync_directory);
    }
}
