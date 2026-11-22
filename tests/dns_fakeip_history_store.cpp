#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
import std;
import dns.fakeip_history_store;
import dns.fakeip_recovery;
import dns.fakeip_shared;
import dns.message;
namespace d=dns;
using namespace std::chrono_literals;
auto put_file(std::string const& path,std::span<std::uint8_t const> bytes,mode_t mode=0600) -> bool {
    int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,mode); if(fd<0) return false;
    auto n=::write(fd,bytes.data(),bytes.size()); return n==static_cast<ssize_t>(bytes.size()) && ::close(fd)==0;
}
auto main(int argc,char** argv) -> int {
    if (argc==3 && std::string_view(argv[1])=="check-lock") {
        std::array<std::uint8_t,16> child_instance{}; child_instance[0]=7;
        std::array<std::uint8_t,32> child_key{}; std::iota(child_key.begin(),child_key.end(),std::uint8_t{1});
        auto attempt=d::FakeIpHistoryStore::open(argv[2],child_instance,child_key,d::FakeIpHistoryStoreMode::open_existing);
        return !attempt && attempt.error()==d::FakeIpHistoryStoreError::busy ? 0 : 1;
    }
    if (argc!=1) return 50;
    std::array<char,64> name{}; std::ranges::copy(std::string{"/tmp/nexus-history-store-XXXXXX"},name.begin());
    auto dir=::mkdtemp(name.data()); if(!dir) return 1;
    std::array<std::uint8_t,16> instance{}; instance[0]=7;
    std::array<std::uint8_t,32> key{}; std::iota(key.begin(),key.end(),std::uint8_t{1});
    auto fresh_dir=std::string(dir)+"/fresh";
    if (::mkdir(fresh_dir.c_str(),0700)!=0) return 27;
    if (!put_file(fresh_dir+"/instance.id",instance) || !put_file(fresh_dir+"/history.key",key)) return 42;
    auto fresh=d::FakeIpHistoryStore::open_with_credentials(fresh_dir,d::FakeIpHistoryStoreMode::create_new);
    if (!fresh) return 28;
    d::FakeIpRecoveryPool first_pool{0xc6120000,0xc6120003,0xc6120001,0xc6120001,10s,2s};
    auto first=d::start_fakeip(std::move(*fresh),first_pool,3s);
    if (!first || d::FakeIpHistoryStore::open(fresh_dir,instance,key,d::FakeIpHistoryStoreMode::open_existing)) return 29;
    first->reset();
    auto first_history=d::FakeIpHistoryStore::open(fresh_dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (!first_history || first_history->generation()!=1 || !first_history->history() ||
        first_history->history()->ranges.size()!=1 || first_history->history()->ranges[0].protection!=12s) return 30;
    if (!put_file(std::string(dir)+"/instance.id",instance) || !put_file(std::string(dir)+"/history.key",key)) return 2;
    auto secure_missing=d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing);
    if (secure_missing || secure_missing.error()!=d::FakeIpHistoryStoreError::missing) return 31;
    auto id_path=std::string(dir)+"/instance.id";
    if (::chmod(id_path.c_str(),0644)!=0 || d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::create_new) ||
        ::chmod(id_path.c_str(),0600)!=0) return 43;
    auto absent=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (absent || absent.error()!=d::FakeIpHistoryStoreError::missing) return 16;
    auto opened=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::create_new); if(!opened || opened->generation()!=0 || opened->history()) return 3;
    std::optional<d::FakeIpHistoryStore> store{std::move(*opened)};
    auto busy=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing); if(busy || busy.error()!=d::FakeIpHistoryStoreError::busy) return 4;
    // A second process cannot acquire this directory after its named lock is
    // removed and replaced: the original owner holds the directory inode lock.
    auto lock_path=std::string(dir)+"/owner.lock";
    if (::unlink(lock_path.c_str())!=0 || !put_file(lock_path,{})) return 47;
    auto child=::fork(); if (child<0) return 48;
    if (child==0) {
        ::execl("/proc/self/exe","nexus-dns-fakeip-history-store-test","check-lock",dir,static_cast<char*>(nullptr));
        ::_exit(127);
    }
    int child_status=0;
    if (::waitpid(child,&child_status,0)!=child || !WIFEXITED(child_status) || WEXITSTATUS(child_status)!=0) return 49;
    std::array ranges{d::FakeIpHistoricalRange{0xc6120000,0xc6120003,12s}};
    if (!store->commit({1,std::vector<d::FakeIpHistoricalRange>(ranges.begin(),ranges.end())}) || store->generation()!=1) return 5;
    if (!store->history() || store->history()->generation!=1 || store->history()->ranges.size()!=1) return 5;
    if (store->commit({1,std::vector<d::FakeIpHistoricalRange>(ranges.begin(),ranges.end())}).error()!=d::FakeIpHistoryStoreError::rollback) return 6;
    store.reset();
    auto reopened_result=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing); if(!reopened_result || reopened_result->generation()!=1 || !reopened_result->history()) return 7;
    std::optional<d::FakeIpHistoryStore> reopened{std::move(*reopened_result)};
    auto removed=ranges; removed[0].first++;
    auto shortened=ranges; shortened[0].protection=11s;
    auto rejected=reopened->commit({2,std::vector<d::FakeIpHistoricalRange>(removed.begin(),removed.end())});
    if (rejected || rejected.error()!=d::FakeIpHistoryStoreError::rollback) return 14;
    rejected=reopened->commit({2,std::vector<d::FakeIpHistoricalRange>(shortened.begin(),shortened.end())});
    if (rejected || rejected.error()!=d::FakeIpHistoryStoreError::rollback || reopened->failed() ||
        !reopened->history() || reopened->generation()!=1) return 15;
    d::FakeIpRecoveryPool next_pool{0xc6130000,0xc6130003,0xc6130001,0xc6130001,12s,2s};
    auto invalid=d::start_fakeip(std::move(*reopened),next_pool,-1s);
    if (invalid || !std::holds_alternative<d::FakeIpRecoveryError>(invalid.error())) return 25;
    reopened.reset();
    auto valid_store=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (!valid_store || valid_store->generation()!=1) return 26;
    auto before_start=std::chrono::steady_clock::now();
    auto recovered=d::start_fakeip(std::move(*valid_store),next_pool,3s);
    auto after_start=std::chrono::steady_clock::now();
    auto query=d::make_query(1,{"example.test",1});
    if (!recovered || !query || !(*recovered)->contains(0xc6120000).value_or(false) ||
        (*recovered)->respond(0xc6130000,*query,7,before_start)) return 8;
    auto before=(*recovered)->respond(0xc6130000,*query,7,before_start+17s-1ns);
    if (before) return 8;
    auto after=(*recovered)->respond(0xc6130000,*query,7,after_start+17s);
    if (!after) return 8;
    auto target=(*recovered)->acquire(0xc6130001,7,after_start+17s);
    if (!target || !*target) return 21;
    recovered->reset();
    auto held=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (held || held.error()!=d::FakeIpHistoryStoreError::busy) return 22;
    if (!(*after)->finish(false,after_start+17s) || !(*target)->release(after_start+17s)) return 23;
    after->reset();
    held=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (held || held.error()!=d::FakeIpHistoryStoreError::busy) return 24;
    target->reset();
    auto old_result=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing); if(!old_result || old_result->generation()!=2) return 9;
    std::optional<d::FakeIpHistoryStore> old{std::move(*old_result)};
    old.reset();
    {
        auto secure=d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing);
        if (!secure || secure->generation()!=2) return 32;
        auto busy_secure=d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing);
        if (busy_secure || busy_secure.error()!=d::FakeIpHistoryStoreError::busy) return 33;
    }
    auto key_path=std::string(dir)+"/history.key", link_path=std::string(dir)+"/key.link";
    if (::chmod(key_path.c_str(),0644)!=0 || d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing)) return 34;
    if (::chmod(key_path.c_str(),0600)!=0 || ::link(key_path.c_str(),link_path.c_str())!=0 ||
        d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing)) return 35;
    if (::unlink(key_path.c_str())!=0 || ::symlink("key.link",key_path.c_str())!=0 ||
        d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing)) return 36;
    if (::unlink(key_path.c_str())!=0 || ::rename(link_path.c_str(),key_path.c_str())!=0) return 37;
    int key_fd=::open(key_path.c_str(),O_WRONLY|O_CLOEXEC);
    std::uint8_t wrong=0; if (key_fd<0 || ::write(key_fd,&wrong,1)!=1 || ::close(key_fd)!=0) return 38;
    auto wrong_key=d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing);
    if (wrong_key || wrong_key.error()!=d::FakeIpHistoryStoreError::authentication) return 39;
    if (::unlink(key_path.c_str())!=0 || !put_file(key_path,std::span{key}.first(31)) ||
        d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing)) return 40;
    if (::unlink(key_path.c_str())!=0 || !put_file(key_path,key)) return 41;
    int id_fd=::open(id_path.c_str(),O_WRONLY|O_CLOEXEC);
    if (id_fd<0 || ::write(id_fd,&wrong,1)!=1 || ::close(id_fd)!=0) return 44;
    auto wrong_id=d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing);
    if (wrong_id || wrong_id.error()!=d::FakeIpHistoryStoreError::authentication) return 45;
    if (::unlink(id_path.c_str())!=0 || d::FakeIpHistoryStore::open_with_credentials(dir,d::FakeIpHistoryStoreMode::open_existing) ||
        !put_file(id_path,instance)) return 46;
    std::array<std::uint8_t,8> higher{}; higher[7]=3;
    int fd=::open((std::string(dir)+"/highwater").c_str(),O_WRONLY|O_CLOEXEC); if(fd<0 || ::write(fd,higher.data(),8)!=8 || ::close(fd)!=0) return 10;
    if (d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing) || d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing).error()!=d::FakeIpHistoryStoreError::rollback) return 11;
    higher[7]=2; fd=::open((std::string(dir)+"/highwater").c_str(),O_WRONLY|O_CLOEXEC); if(fd<0 || ::write(fd,higher.data(),8)!=8 || ::close(fd)!=0) return 11;
    auto duplicate=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::create_new);
    if (duplicate || duplicate.error()!=d::FakeIpHistoryStoreError::rollback) return 17;
    if (::unlink((std::string(dir)+"/highwater").c_str())!=0) return 18;
    auto missing=d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing);
    if (missing || missing.error()!=d::FakeIpHistoryStoreError::missing) return 19;
    if (!put_file(std::string(dir)+"/highwater",higher)) return 20;
    ::chmod((std::string(dir)+"/history").c_str(),0644);
    if (d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing) || d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing).error()!=d::FakeIpHistoryStoreError::permission) return 12;
    ::chmod((std::string(dir)+"/history").c_str(),0600);
    ::unlink((std::string(dir)+"/history").c_str()); ::symlink("instance.id",(std::string(dir)+"/history").c_str());
    if (d::FakeIpHistoryStore::open(dir,instance,key,d::FakeIpHistoryStoreMode::open_existing)) return 13;
    std::filesystem::remove_all(dir);
    std::println("FakeIP history store lock, commit, rollback and credential checks passed");
}
