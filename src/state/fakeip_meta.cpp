module state.fakeip_disk;
import std;
import crypto;
import state.serde;
import state.snapshot;
import state.fakeip;
import state.file;

namespace state {
    namespace {
        const SnapshotSpec meta_file{"fakeip.meta", ".meta.next",
            {.magic={'N','X','F','P','0','1'}, .tier=Tier::lease, .max_payload=4096}};

        auto scope_bytes(FakeIpScope const& value) -> Bytes {
            Bytes bytes;
            for (auto number:{value.first,value.last,value.alloc_first,value.alloc_last})
                append_le(bytes,number,4);
            bytes.append_range(value.identity);
            append_le(bytes,value.exclude_cidrs.size(),2);
            for (auto [first,last]:value.exclude_cidrs) {
                append_le(bytes,first,4);
                append_le(bytes,last,4);
            }
            return bytes;
        }
    }

    auto save_fakeip_meta(InstanceLock const& directory, FakeIpScope const& scope, FakeIpMeta const& meta)
        -> std::expected<void,StateError> {
        auto bytes=scope_bytes(scope);
        bytes.append_range(meta.owner);
        append_le(bytes,meta.reserved,8);
        auto written=commit_snapshot(directory,meta_file,meta.generation,0,bytes);
        if (!written) return std::unexpected(written.error());
        if (written->error) return std::unexpected(*written->error);
        return {};
    }

    auto fakeip_meta(InstanceLock const& directory, FakeIpScope const& scope) -> std::expected<FakeIpMeta,StateError> {
        auto loaded=load_snapshot(directory,meta_file);
        if (!loaded) return std::unexpected(loaded.error());
        FakeIpMeta meta;
        if (!*loaded) {
            // Orphan data without its reservation record cannot prove which
            // addresses were published. A new owner requires an empty store.
            for (auto name:{"fakeip.wal","fakeip.ckpt"}) {
                auto exists = dir_entry_exists(directory.directory(), name, Stage::open);
                if (!exists) return std::unexpected(exists.error());
                if (*exists) return std::unexpected(StateError{Stage::format});
            }
            auto raw = std::span(reinterpret_cast<std::uint8_t*>(meta.owner.data()), meta.owner.size());
            if (!crypto::random_bytes(raw))
                return std::unexpected(StateError{Stage::read, std::make_error_code(std::errc::io_error)});
            auto saved=save_fakeip_meta(directory,scope,meta);
            if (!saved) return std::unexpected(saved.error());
            return meta;
        }
        auto const& snapshot=**loaded;
        auto prefix=scope_bytes(scope);
        Reader reader{snapshot.payload};
        if (!std::ranges::equal(reader.take(prefix.size()),prefix)) return std::unexpected(StateError{Stage::format});
        std::ranges::copy(reader.take(meta.owner.size()),meta.owner.begin());
        meta.reserved=reader.number(8);
        meta.generation=snapshot.header.revision;
        auto capacity=std::uint64_t(scope.alloc_last)-scope.alloc_first+1;
        if (!reader.complete() || !meta.generation || meta.reserved>capacity)
            return std::unexpected(StateError{Stage::format});
        return meta;
    }

    auto valid_fakeip_name(std::string_view value) noexcept -> bool {
        if (value.empty() || value.size()>253) return false;
        for (auto label:value | std::views::split('.')) {
            auto length=std::ranges::distance(label);
            if (!length || length>63 || !std::ranges::all_of(label,[](char ch) {
                return (ch>='a' && ch<='z') || (ch>='0' && ch<='9') || ch=='-';
            })) return false;
        }
        return true;
    }
}
