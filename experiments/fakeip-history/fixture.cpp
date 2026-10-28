#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../state-owner/owner_lock.hpp"
import std;
import nexus.dns.fakeip_history;
import nexus.dns.fakeip_recovery;
import nexus.dns.fakeip_shared;
import nexus.dns.message;
import nexus.dns.fakeip_response;
using namespace std::chrono_literals;
namespace d=nexus::dns;
constexpr std::uint32_t old_base=0xc6120000, new_base=0xc6130000;
std::array<std::uint8_t,16> instance{};
std::array<std::uint8_t,32> key{};
auto read_secret(int dir,char const* name,std::span<std::uint8_t> output) -> bool {
    int fd=::openat(dir,name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return false; struct stat st{};
    if (::fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_uid!=::geteuid() ||
        (st.st_mode&07777)!=0600 || st.st_nlink!=1 || st.st_size!=static_cast<off_t>(output.size())) { ::close(fd); return false; }
    std::size_t off=0;
    while (off<output.size()) { auto n=::read(fd,output.data()+off,output.size()-off);
        if (n<0 && errno==EINTR) continue; if (n<=0) { ::close(fd); return false; } off+=static_cast<std::size_t>(n); }
    return ::close(fd)==0;
}
auto load(int dir) -> std::optional<d::FakeIpHistorySnapshot> {
    int fd=::openat(dir,"history",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0) return {};
    struct stat st{};
    if (::fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_uid!=::geteuid() ||
        (st.st_mode&07777)!=0600 || st.st_nlink!=1 || st.st_size<80 || st.st_size>4160) { ::close(fd); return {}; }
    std::vector<std::uint8_t> wire(static_cast<std::size_t>(st.st_size));
    std::size_t off=0;
    while (off<wire.size()) {
        auto n=::read(fd,wire.data()+off,wire.size()-off);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { ::close(fd); return {}; }
        off+=static_cast<std::size_t>(n);
    }
    if (::close(fd)!=0) return {};
    auto value=d::decode_fakeip_history(wire,instance,key);
    if (!value) return {};
    return std::move(*value);
}
auto watermark(int dir) -> std::expected<std::optional<std::uint64_t>,bool> {
    int fd=::openat(dir,"highwater",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0 && errno==ENOENT) return std::optional<std::uint64_t>{};
    if (fd<0) return std::unexpected(true);
    struct stat st{};
    if (::fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || st.st_uid!=::geteuid() ||
        (st.st_mode&07777)!=0600 || st.st_nlink!=1 || st.st_size!=8) { ::close(fd); return std::unexpected(true); }
    std::array<std::uint8_t,8> bytes{}; auto n=::read(fd,bytes.data(),bytes.size()); ::close(fd);
    if (n!=8) return std::unexpected(true);
    std::uint64_t value=0; for (auto byte:bytes) value=(value<<8)|byte; return std::optional{value};
}
auto save_watermark(int dir,std::uint64_t generation) -> bool {
    if (::unlinkat(dir,"highwater.next",0)<0 && errno!=ENOENT) return false;
    int fd=::openat(dir,"highwater.next",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return false; std::array<std::uint8_t,8> bytes{};
    for (unsigned i=8;i;--i) bytes[8-i]=static_cast<std::uint8_t>(generation>>((i-1)*8));
    auto ok=::write(fd,bytes.data(),bytes.size())==8 && ::fsync(fd)==0; if (::close(fd)!=0) ok=false;
    if (!ok || ::renameat(dir,"highwater.next",dir,"highwater")<0 || ::fsync(dir)<0) return false;
    return true;
}
[[noreturn]] auto pause_for_kill() -> void { std::println("ready"); std::cout.flush(); for (;;) ::pause(); }
auto save(int dir,std::span<std::uint8_t const> wire,std::string_view mode) -> bool {
    if (::unlinkat(dir,"next",0)<0 && errno!=ENOENT) return false;
    int fd=::openat(dir,"next",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return false;
    std::size_t off=0;
    while (off<wire.size() && mode!="fail-write") {
        auto n=::write(fd,wire.data()+off,wire.size()-off);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) break;
        off+=static_cast<std::size_t>(n);
    }
    bool ok=off==wire.size() && mode!="fail-file-sync" && ::fsync(fd)==0;
    if (::close(fd)!=0) ok=false;
    if (!ok) return false;
    if (mode=="before-rename") pause_for_kill();
    if (mode=="fail-rename" || ::renameat(dir,"next",dir,"history")<0) return false;
    if (mode=="after-rename") pause_for_kill();
    if (mode=="fail-dir-sync" || ::fsync(dir)<0) return false;
    if (mode=="after-sync") pause_for_kill();
    return true;
}
auto main(int argc,char** argv) -> int {
    if (argc!=3) return 2;
    auto [lock,error]=OwnerLock::acquire(argv[1]);
    if (error) return 3;
    auto dir=lock.directory_fd(); std::string_view mode=argv[2];
    if (!read_secret(dir,"instance.id",instance) || !read_secret(dir,"history.key",key)) return 4;
    bool init=mode=="init";
    if (init) {
        struct stat st{};
        if (::fstatat(dir,"history",&st,AT_SYMLINK_NOFOLLOW)==0 || errno!=ENOENT) return 5;
    }
    auto history=init ? std::optional{d::FakeIpHistorySnapshot{}} : load(dir);
    if (!history) return 5;
    if (!init) {
        auto high=watermark(dir);
        if (!high || !history->generation || (high->has_value() && history->generation<**high)) return 5;
    }
    if (mode=="verify-old" || mode=="verify-new") {
        auto expected=mode=="verify-old" ? 1u : 2u;
        if (history->ranges.size()!=expected || history->ranges.at(0).first!=old_base ||
            (expected==2 && history->ranges.at(1).first!=new_base)) return 5;
        return 0;
    }
    auto base=init ? old_base : new_base;
    d::FakeIpRecoveryPool pool{base,base+3,base+1,base+1,1s,0s};
    auto next=d::update_fakeip_history(pool,history->ranges);
    if (!next) return 7;
    auto wire=d::encode_fakeip_history({static_cast<std::uint64_t>(init ? 1 : 2),*next},instance,key);
    if (!wire) return 8;
    auto saved=save(dir,*wire,mode);
    if (mode.starts_with("fail-")) return saved ? 9 : 0;
    if (!saved) return 10;
    if (!save_watermark(dir,init ? 1 : 2)) return 10;
    // No owner capable of publishing is created before the durable commit.
    auto now=std::chrono::steady_clock::time_point{};
    auto owner=d::recover_fakeip(pool,*next,0s,now);
    auto query=d::make_query(1,{"example.test",1});
    if (!owner || !query || (*owner)->respond(base,*query,1,now) ||
        (base==new_base && !(*owner)->contains(old_base).value_or(false))) return 11;
    auto answer=(*owner)->respond(base,*query,1,now+1s);
    if (!answer || !(*answer)->finish(false,now+1s)) return 12;
    std::println("published");
    return 0;
}
