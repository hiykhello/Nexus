module state.fakeip;
import std;
import nexus.compat;
import state.fakeip_disk;
import state.lock;
import state.file;

namespace state {
    struct FakeIpStore::Impl {
        InstanceLock directory;
        FakeIpScope scope;
        FakeIpMeta meta;
        FakeIpMeta const wal_identity;
        CrashMode mode;
        File wal;
        std::vector<FakeIpRow> disk_rows;
        std::size_t wal_bytes;
        std::uint64_t cursor;
        std::map<std::pair<std::uint64_t,std::string>,std::uint32_t> forward;
        std::mutex mutex;
        std::condition_variable changed;
        std::vector<FakeIpRow> pending, batch;
        std::optional<StateError> failed;
        bool stopping=false, started=false;
        std::thread worker;

        Impl(InstanceLock locked, FakeIpScope spec, FakeIpMeta header, CrashMode crash, File file, FakeIpReplay replay)
            : directory(std::move(locked)),scope(std::move(spec)),meta(header),wal_identity(header),mode(crash),
              wal(std::move(file)),disk_rows(std::move(replay.rows)),wal_bytes(replay.wal_bytes),
              cursor(meta.reserved) {
            if (!disk_rows.empty()) cursor=std::max(cursor,std::uint64_t(disk_rows.back().address)-scope.alloc_first+1);
            for (auto const& row:disk_rows) forward.emplace(std::pair(row.view,row.domain),row.address);
            pending.reserve(128);
            batch.reserve(128);
        }

        ~Impl() {
            {
                std::lock_guard lock(mutex);
                stopping=true;
            }
            changed.notify_one();
            if (worker.joinable()) worker.join();
        }

        auto flush(std::span<FakeIpRow> rows) -> std::expected<void,StateError> {
            for (auto& row:rows) {
                auto result=append_fakeip(wal.get(),wal_identity,disk_rows.size()+1,row);
                if (!result) return std::unexpected(result.error());
                wal_bytes+=*result;
                disk_rows.push_back(std::move(row));
            }
            if (auto synced=sync_handle(wal.get(),Stage::sync_stage); !synced) return std::unexpected(synced.error());
            if (wal_bytes<fakeip_wal_limit) return {};
            auto compacted=compact_fakeip(directory,wal_identity,wal.get(),disk_rows);
            if (compacted) wal_bytes=0;
            return compacted;
        }

        auto drive() -> void {
            std::unique_lock lock(mutex);
            while (!failed) {
                changed.wait(lock,[&]{return stopping || !pending.empty();});
                if (pending.empty()) return;
                changed.wait_for(lock,std::chrono::milliseconds(250),[&]{return stopping || pending.size()>=64;});
                batch.swap(pending);
                lock.unlock();
                std::optional<StateError> error;
                try {
                    auto result=flush(batch);
                    if (!result) error=result.error();
                } catch (std::bad_alloc const&) {error=StateError{Stage::capacity};}
                batch.clear();
                lock.lock();
                if (error) failed=*error;
            }
        }
    };

    FakeIpStore::FakeIpStore(std::unique_ptr<Impl> owner) noexcept : owner_(std::move(owner)) {}
    FakeIpStore::~FakeIpStore()=default;

    auto FakeIpStore::open(std::filesystem::path const& root, FakeIpScope scope, CrashMode mode)
        -> std::expected<std::unique_ptr<FakeIpStore>,StateError> {
        if (scope.first>scope.alloc_first || scope.alloc_first>scope.alloc_last || scope.alloc_last>scope.last ||
            std::uint64_t(scope.last)-scope.first>=65536 || scope.exclude_cidrs.size()>256)
            return std::unexpected(StateError{Stage::validate});
        std::ranges::sort(scope.exclude_cidrs);
        for (std::size_t i=0;i<scope.exclude_cidrs.size();++i) {
            auto [first,last]=scope.exclude_cidrs[i];
            if (first<scope.first || last>scope.last || first>last || (i && scope.exclude_cidrs[i-1].second>=first))
                return std::unexpected(StateError{Stage::validate});
        }
        auto lock=InstanceLock::open_child(root,"fakeip");
        if (!lock) return std::unexpected(lock.error());
        auto meta=fakeip_meta(*lock,scope);
        if (!meta) return std::unexpected(meta.error());
        auto wal=open_dir_append(lock->directory(),"fakeip.wal",Stage::open);
        if (!wal) return std::unexpected(wal.error());
        auto replay=replay_fakeip(*lock,scope,*meta,wal->get());
        if (!replay) return std::unexpected(replay.error());

        auto owner=std::make_unique<Impl>(std::move(*lock),std::move(scope),*meta,mode,std::move(*wal),std::move(*replay));
        return std::unique_ptr<FakeIpStore>(new FakeIpStore(std::move(owner)));
    }

    auto FakeIpStore::visit_recovered(nexus::function_ref<bool(FakeIpRow const&)> visit) const -> bool {
        std::lock_guard lock(owner_->mutex);
        return !owner_->started && std::ranges::all_of(owner_->disk_rows,visit);
    }

    auto FakeIpStore::assign(std::string_view canonical, std::uint64_t view)
        -> std::expected<std::uint32_t,StateError> {
        auto& owner=*owner_;
        std::lock_guard lock(owner.mutex);
        if (owner.failed) return std::unexpected(*owner.failed);
        owner.started=true;
        if (!valid_fakeip_name(canonical)) return std::unexpected(StateError{Stage::validate});
        auto key=std::pair(view,std::string(canonical));
        auto existing=owner.forward.find(key);
        if (existing!=owner.forward.end()) return existing->second;
        auto capacity=std::uint64_t(owner.scope.alloc_last)-owner.scope.alloc_first+1;
        while (owner.cursor<capacity) {
            auto address=owner.scope.alloc_first+owner.cursor;
            auto excluded=std::ranges::find_if(owner.scope.exclude_cidrs,[&](auto range) {
                return address>=range.first && address<=range.second;
            });
            if (excluded==owner.scope.exclude_cidrs.end()) break;
            owner.cursor=std::uint64_t(excluded->second)-owner.scope.alloc_first+1;
        }
        if (owner.cursor>=capacity || owner.pending.size()==128)
            return std::unexpected(StateError{Stage::capacity});
        if (owner.mode==CrashMode::range_reserve && owner.cursor>=owner.meta.reserved) {
            owner.meta.reserved=std::min(capacity,owner.cursor+fakeip_range);
            ++owner.meta.generation;
            auto reserved=save_fakeip_meta(owner.directory,owner.scope,owner.meta);
            if (!reserved) {
                owner.failed=reserved.error();
                return std::unexpected(*owner.failed);
            }
        }
        auto address=static_cast<std::uint32_t>(owner.scope.alloc_first+owner.cursor);
        FakeIpRow row{address,view,key.second};
        auto saved_key=owner.forward.emplace(std::move(key),address).first;
        if (owner.mode==CrashMode::per_mapping) {
            try {
                auto saved=owner.flush(std::span(&row,1));
                if (!saved) owner.failed=saved.error();
            } catch (std::bad_alloc const&) {owner.failed=StateError{Stage::capacity};}
            if (owner.failed) {
                owner.forward.erase(saved_key);
                return std::unexpected(*owner.failed);
            }
        } else {
            if (!owner.worker.joinable()) {
                try {owner.worker=std::thread([&owner]{owner.drive();});}
                catch (std::system_error const& error) {
                    owner.forward.erase(saved_key);
                    return std::unexpected(StateError{Stage::worker,error.code()});
                }
            }
            owner.pending.push_back(std::move(row));
            owner.changed.notify_one();
        }
        ++owner.cursor;
        return address;
    }
}
