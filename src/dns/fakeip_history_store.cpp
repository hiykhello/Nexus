module;
#include <cerrno>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
module nexus.dns.fakeip_history_store;
import std;
import nexus.dns.fakeip_history;
import nexus.dns.fakeip_recovery;
import nexus.crypto;
namespace nexus::dns {
    namespace {
        auto regular(int fd,off_t size) -> bool {
            struct stat st{};
            return ::fstat(fd,&st)==0 && S_ISREG(st.st_mode) && st.st_uid==::geteuid() &&
                   (st.st_mode&07777)==0600 && st.st_nlink==1 && st.st_size==size;
        }
        auto read_all(int fd,std::span<std::uint8_t> bytes) -> bool {
            std::size_t offset=0;
            while (offset<bytes.size()) { auto n=::read(fd,bytes.data()+offset,bytes.size()-offset);
                if (n<0 && errno==EINTR) continue; if (n<=0) return false; offset+=static_cast<std::size_t>(n); }
            return true;
        }
        auto write_all(int fd,std::span<std::uint8_t const> bytes) -> bool {
            std::size_t offset=0;
            while (offset<bytes.size()) { auto n=::write(fd,bytes.data()+offset,bytes.size()-offset);
                if (n<0 && errno==EINTR) continue; if (n<=0) return false; offset+=static_cast<std::size_t>(n); }
            return true;
        }
        auto read_credential(int directory,char const* name,std::span<std::uint8_t> bytes)
            -> std::expected<void,FakeIpHistoryStoreError> {
            int fd=::openat(directory,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
            if (fd<0) return std::unexpected(errno==ENOENT ? FakeIpHistoryStoreError::missing : FakeIpHistoryStoreError::io);
            if (!regular(fd,static_cast<off_t>(bytes.size()))) { ::close(fd); return std::unexpected(FakeIpHistoryStoreError::permission); }
            bool ok=read_all(fd,bytes);
            if (::close(fd)!=0) ok=false;
            return ok ? std::expected<void,FakeIpHistoryStoreError>{}
                      : std::unexpected(FakeIpHistoryStoreError::io);
        }
    }
    FakeIpHistoryStore::FakeIpHistoryStore(FakeIpHistoryStore&& other) noexcept
        : directory_(std::exchange(other.directory_,-1)),lock_(std::exchange(other.lock_,-1)),instance_(other.instance_),
          key_(other.key_),generation_(other.generation_),history_(std::move(other.history_)),failed_(other.failed_) {
        crypto::cleanse(other.key_);
    }
    auto FakeIpHistoryStore::operator=(FakeIpHistoryStore&& other) noexcept -> FakeIpHistoryStore& {
        if (this!=&other) {
            if (lock_>=0) ::close(lock_); if (directory_>=0) ::close(directory_);
            crypto::cleanse(key_);
            directory_=std::exchange(other.directory_,-1); lock_=std::exchange(other.lock_,-1);
            instance_=other.instance_; key_=other.key_; generation_=other.generation_;
            history_=std::move(other.history_); failed_=other.failed_; crypto::cleanse(other.key_);
        }
        return *this;
    }
    FakeIpHistoryStore::~FakeIpHistoryStore() {
        crypto::cleanse(key_);
        if (lock_>=0) ::close(lock_); if (directory_>=0) ::close(directory_);
    }
    auto FakeIpHistoryStore::read_history() -> std::expected<std::optional<FakeIpHistorySnapshot>,FakeIpHistoryStoreError> {
        int fd=::openat(directory_,"history",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if (fd<0 && errno==ENOENT) return std::optional<FakeIpHistorySnapshot>{};
        if (fd<0) return std::unexpected(FakeIpHistoryStoreError::io);
        struct stat st{};
        if (::fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_uid!=::geteuid() || (st.st_mode&07777)!=0600 ||
            st.st_nlink!=1 || st.st_size<80 || st.st_size>4160) { ::close(fd); return std::unexpected(FakeIpHistoryStoreError::permission); }
        std::vector<std::uint8_t> bytes(static_cast<std::size_t>(st.st_size));
        auto ok=read_all(fd,bytes); if (::close(fd)!=0) ok=false;
        if (!ok) return std::unexpected(FakeIpHistoryStoreError::io);
        auto decoded=decode_fakeip_history(bytes,instance_,key_);
        if (!decoded) return std::unexpected(decoded.error()==FakeIpHistoryError::authentication ? FakeIpHistoryStoreError::authentication : FakeIpHistoryStoreError::corrupt);
        return std::optional{std::move(*decoded)};
    }
    auto FakeIpHistoryStore::read_highwater() -> std::expected<std::optional<std::uint64_t>,FakeIpHistoryStoreError> {
        int fd=::openat(directory_,"highwater",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if (fd<0 && errno==ENOENT) return std::optional<std::uint64_t>{};
        if (fd<0) return std::unexpected(FakeIpHistoryStoreError::io);
        if (!regular(fd,8)) { ::close(fd); return std::unexpected(FakeIpHistoryStoreError::permission); }
        std::array<std::uint8_t,8> bytes{}; auto ok=read_all(fd,bytes); if (::close(fd)!=0) ok=false;
        if (!ok) return std::unexpected(FakeIpHistoryStoreError::io);
        std::uint64_t value=0; for (auto byte:bytes) value=(value<<8)|byte;
        if (!value) return std::unexpected(FakeIpHistoryStoreError::corrupt);
        return std::optional{value};
    }
    auto FakeIpHistoryStore::open(std::string_view path,std::span<std::uint8_t const,16> instance,
        std::span<std::uint8_t const,32> key,FakeIpHistoryStoreMode mode) -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError> {
        return open_impl(path,mode,instance,key,false);
    }
    auto FakeIpHistoryStore::open_impl(std::string_view path,FakeIpHistoryStoreMode mode,
        std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key,bool from_files)
        -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError> {
        if (path.empty() || path.front()!='/' || path.find('\0')!=path.npos) return std::unexpected(FakeIpHistoryStoreError::invalid);
        int directory=::open(std::string(path).c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (directory<0) return std::unexpected(FakeIpHistoryStoreError::io);
        struct stat dir{};
        if (::fstat(directory,&dir)<0 || dir.st_uid!=::geteuid() || (dir.st_mode&07777)!=0700) { ::close(directory); return std::unexpected(FakeIpHistoryStoreError::permission); }
        // Lock the directory inode as well as owner.lock: unlinking or replacing
        // the named lock cannot permit another cooperating owner of this directory.
        if (::flock(directory,LOCK_EX|LOCK_NB)<0) {
            auto e=errno; ::close(directory);
            return std::unexpected(e==EWOULDBLOCK ? FakeIpHistoryStoreError::busy : FakeIpHistoryStoreError::io);
        }
        int lock=::openat(directory,"owner.lock",O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
        if (lock<0) { ::close(directory); return std::unexpected(FakeIpHistoryStoreError::io); }
        struct stat lock_stat{};
        if (::fstat(lock,&lock_stat)<0 || !S_ISREG(lock_stat.st_mode) || lock_stat.st_uid!=::geteuid() ||
            (lock_stat.st_mode&07777)!=0600 || lock_stat.st_nlink!=1 || ::flock(lock,LOCK_EX|LOCK_NB)<0) {
            auto e=errno; ::close(lock); ::close(directory); return std::unexpected(e==EWOULDBLOCK ? FakeIpHistoryStoreError::busy : FakeIpHistoryStoreError::permission);
        }
        struct stat named{};
        if (::fstatat(directory,"owner.lock",&named,AT_SYMLINK_NOFOLLOW)<0 || named.st_dev!=lock_stat.st_dev || named.st_ino!=lock_stat.st_ino || named.st_nlink!=1) {
            ::close(lock); ::close(directory); return std::unexpected(FakeIpHistoryStoreError::permission);
        }
        FakeIpHistoryStore store(directory,lock,instance,key);
        if (from_files) {
            auto loaded_instance=read_credential(directory,"instance.id",store.instance_);
            if (!loaded_instance) return std::unexpected(loaded_instance.error());
            auto loaded_key=read_credential(directory,"history.key",store.key_);
            if (!loaded_key) return std::unexpected(loaded_key.error());
        }
        auto history=store.read_history(); if (!history) return std::unexpected(history.error());
        auto high=store.read_highwater(); if (!high) return std::unexpected(high.error());
        if (mode==FakeIpHistoryStoreMode::create_new) {
            if (history->has_value() || high->has_value()) return std::unexpected(FakeIpHistoryStoreError::rollback);
            return store;
        }
        if (mode!=FakeIpHistoryStoreMode::open_existing) return std::unexpected(FakeIpHistoryStoreError::invalid);
        if (!history->has_value() || !high->has_value()) return std::unexpected(FakeIpHistoryStoreError::missing);
        if (history->has_value()) {
            store.generation_=history->value().generation;
            store.history_=std::move(*history);
            if (high->has_value() && store.generation_<high->value()) return std::unexpected(FakeIpHistoryStoreError::rollback);
        } else if (high->has_value()) return std::unexpected(FakeIpHistoryStoreError::rollback);
        return store;
    }
    auto FakeIpHistoryStore::open_with_credentials(std::string_view path,FakeIpHistoryStoreMode mode)
        -> std::expected<FakeIpHistoryStore,FakeIpHistoryStoreError> {
        std::array<std::uint8_t,16> instance{};
        std::array<std::uint8_t,32> key{};
        return open_impl(path,mode,instance,key,true);
    }
    auto FakeIpHistoryStore::write_file(std::string_view temporary,std::string_view final,std::span<std::uint8_t const> bytes)
        -> std::expected<void,FakeIpHistoryStoreError> {
        if (::unlinkat(directory_,temporary.data(),0)<0 && errno!=ENOENT) return std::unexpected(FakeIpHistoryStoreError::io);
        // Both names are internal null-terminated literals.
        int fd=::openat(directory_,temporary.data(),O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if (fd<0) return std::unexpected(FakeIpHistoryStoreError::io);
        bool ok=write_all(fd,bytes) && ::fsync(fd)==0;
        if (::close(fd)!=0) ok=false;
        if (!ok) return std::unexpected(FakeIpHistoryStoreError::io);
        if (::renameat(directory_,temporary.data(),directory_,final.data())<0 || ::fsync(directory_)<0)
            return std::unexpected(FakeIpHistoryStoreError::io);
        return {};
    }
    auto FakeIpHistoryStore::commit(FakeIpHistorySnapshot const& snapshot) -> std::expected<void,FakeIpHistoryStoreError> {
        if (failed_ || directory_<0 || lock_<0) return std::unexpected(FakeIpHistoryStoreError::io);
        if (!snapshot.generation || snapshot.generation<=generation_) return std::unexpected(FakeIpHistoryStoreError::rollback);
        auto wire=encode_fakeip_history(snapshot,instance_,key_);
        if (!wire) return std::unexpected(wire.error()==FakeIpHistoryError::crypto ? FakeIpHistoryStoreError::crypto : FakeIpHistoryStoreError::corrupt);
        // Every old address must remain covered for at least its previous
        // protection period, regardless of the caller's generation number.
        if (history_) for (auto const& previous:history_->ranges) {
            auto covering=std::ranges::find_if(snapshot.ranges,[&](auto const& candidate) {
                return candidate.first<=previous.first && candidate.last>=previous.last &&
                       candidate.protection>=previous.protection;
            });
            if (covering==snapshot.ranges.end()) return std::unexpected(FakeIpHistoryStoreError::rollback);
        }
        // Copy before any durable mutation, including when snapshot aliases history_.
        auto next=snapshot;
        static_assert(std::is_nothrow_move_constructible_v<FakeIpHistorySnapshot> &&
                      std::is_nothrow_move_assignable_v<FakeIpHistorySnapshot>);
        auto saved=write_file("history.next","history",*wire); if (!saved) { failed_=true; history_.reset(); return saved; }
        std::array<std::uint8_t,8> high{}; for (unsigned i=8;i;--i) high[8-i]=static_cast<std::uint8_t>(snapshot.generation>>((i-1)*8));
        auto marked=write_file("highwater.next","highwater",high); if (!marked) { failed_=true; history_.reset(); return marked; }
        generation_=next.generation; history_=std::move(next); return {};
    }
    auto start_fakeip(FakeIpHistoryStore&& store,FakeIpRecoveryPool current,std::chrono::seconds transit)
        -> std::expected<std::shared_ptr<FakeIpShared>,FakeIpStartupError> {
        auto locked=std::make_shared<FakeIpHistoryStore>(std::move(store));
        if (locked->failed()) return std::unexpected(FakeIpStartupError{FakeIpHistoryStoreError::io});
        if (locked->generation()==std::numeric_limits<std::uint64_t>::max())
            return std::unexpected(FakeIpStartupError{FakeIpHistoryStoreError::rollback});
        auto history=locked->history() ? std::span<FakeIpHistoricalRange const>{locked->history()->ranges}
                                       : std::span<FakeIpHistoricalRange const>{};
        auto next=update_fakeip_history(current,history);
        if (!next) return std::unexpected(FakeIpStartupError{next.error()});
        // Validate the complete recovery plan before changing durable state.
        auto plan=recover_fakeip(current,*next,transit,std::chrono::steady_clock::now());
        if (!plan) return std::unexpected(FakeIpStartupError{plan.error()});
        auto committed=locked->commit({locked->generation()+1,std::move(*next)});
        if (!committed) return std::unexpected(FakeIpStartupError{committed.error()});
        auto owner=recover_fakeip(current,locked->history()->ranges,transit,
                                  std::chrono::steady_clock::now(),locked);
        if (!owner) return std::unexpected(FakeIpStartupError{owner.error()});
        return *std::move(owner);
    }
}
