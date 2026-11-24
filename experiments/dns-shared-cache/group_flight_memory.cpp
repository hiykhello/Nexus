// Real DNS sockets and executor-owned tasks at the experimental flight limits.
// This is a resource measurement, not a production proxy or an RSS guarantee.
#include <arpa/inet.h>
#include <dirent.h>
#include <linux/sock_diag.h>
#include <malloc.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
import capy;
import corosio;
import std;
import dns.corosio_cached;
import dns.message;
import dns.corosio_query;
import dns.cache;
import dns.group_cache_binding;
import dns.group_singleflight;

namespace d=dns;
namespace io = ::corosio;
namespace capy=boost::capy;
namespace hp=dns_hp_experiment;
using Clock=std::chrono::steady_clock;
using namespace std::chrono_literals;

namespace {
constexpr std::size_t flight_count=256,worker_count=4,waiter_count=4096;
constexpr std::size_t aliases=15,addresses=113;
auto require(bool condition,char const* message) -> void { if (!condition) throw std::runtime_error(message); }

auto names() -> std::vector<std::string> {
    auto suffix=std::string(63,'a')+"."+std::string(63,'b')+"."+std::string(63,'c')+"."+std::string(56,'d');
    std::vector<std::string> result; result.reserve(flight_count);
    for (std::size_t i=0;i<flight_count;++i) {
        auto name=std::format("n{:03}.{}",i,suffix);
        require(name.size()==253 && d::canonicalize_name(name),"maximal DNS name invalid");
        result.push_back(std::move(name));
    }
    return result;
}
auto put16(std::vector<std::uint8_t>& data,std::uint16_t value) -> void {
    data.push_back(static_cast<std::uint8_t>(value>>8)); data.push_back(static_cast<std::uint8_t>(value));
}
auto record_header(std::vector<std::uint8_t>& data,std::size_t owner,std::uint16_t type,std::uint16_t length) -> void {
    require(owner<0x4000,"compressed name offset invalid");
    put16(data,static_cast<std::uint16_t>(0xc000|owner)); put16(data,type); put16(data,1);
    data.insert(data.end(),{0,0,0,60}); put16(data,length);
}

class Peer {
public:
    struct Packet { std::array<std::uint8_t,512> data{}; std::size_t size=0,index=0; sockaddr_in sender{}; };
private:
    int fd_=-1;
    io::endpoint endpoint_{io::ipv4_address::loopback(),0};
    std::vector<Packet> queries_;
    std::array<bool,flight_count> seen_{};
public:
    Peer() {
        fd_=::socket(AF_INET,SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        require(fd_>=0,"DNS peer socket failed");
        int receive_buffer=4*1024*1024;
        require(::setsockopt(fd_,SOL_SOCKET,SO_RCVBUF,&receive_buffer,sizeof(receive_buffer))==0,"DNS peer buffer failed");
        sockaddr_in address{}; address.sin_family=AF_INET; address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
        require(::bind(fd_,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0,"DNS peer bind failed");
        socklen_t size=sizeof(address);
        require(::getsockname(fd_,reinterpret_cast<sockaddr*>(&address),&size)==0,"DNS peer address failed");
        endpoint_=io::endpoint(io::ipv4_address::loopback(),ntohs(address.sin_port));
        queries_.reserve(flight_count);
    }
    ~Peer() { if (fd_>=0) ::close(fd_); }
    [[nodiscard]] auto endpoint() const noexcept -> io::endpoint { return endpoint_; }
    [[nodiscard]] auto count() const noexcept -> std::size_t { return queries_.size(); }
    auto drain() -> void {
        for (;;) {
            Packet packet; socklen_t length=sizeof(packet.sender);
            auto n=::recvfrom(fd_,packet.data.data(),packet.data.size(),0,reinterpret_cast<sockaddr*>(&packet.sender),&length);
            if (n<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) break;
            if (n<0 && errno==EINTR) continue;
            require(n==271 && packet.data[12]==4 && packet.data[13]=='n',"unexpected DNS query");
            auto index=(packet.data[14]-'0')*100+(packet.data[15]-'0')*10+(packet.data[16]-'0');
            require(index>=0 && static_cast<std::size_t>(index)<flight_count && !seen_[index],"duplicate or invalid DNS query");
            seen_[index]=true; packet.size=static_cast<std::size_t>(n); packet.index=static_cast<std::size_t>(index);
            queries_.push_back(std::move(packet));
        }
    }
    auto answer_all(std::vector<std::string> const& all_names) -> void {
        require(queries_.size()==flight_count,"DNS queries were lost");
        std::vector<std::uint8_t> reply; reply.reserve(4096); bool checked=false;
        for (auto const& query:queries_) {
            reply.assign(query.data.begin(),query.data.begin()+query.size);
            reply[2]=0x81; reply[3]=0x80; reply[6]=0; reply[7]=static_cast<std::uint8_t>(aliases+addresses);
            std::size_t owner=12;
            for (std::size_t i=0;i<aliases;++i) {
                record_header(reply,owner,5,7); owner=reply.size();
                reply.insert(reply.end(),{4,'c',static_cast<std::uint8_t>('0'+i/100),
                    static_cast<std::uint8_t>('0'+(i/10)%10),static_cast<std::uint8_t>('0'+i%10),0xc0,17});
            }
            for (std::size_t i=0;i<addresses;++i) {
                record_header(reply,owner,1,4);
                reply.insert(reply.end(),{127,0,0,static_cast<std::uint8_t>(i+1)});
            }
            require(reply.size()<=4096,"DNS response too large");
            if (!checked) {
                auto id=static_cast<std::uint16_t>((std::uint16_t(reply[0])<<8)|reply[1]);
                auto parsed=d::parse_addresses(reply,id,{all_names[query.index],1});
                require(parsed && parsed->chain.size()==aliases+1 && parsed->addresses.size()==addresses &&
                        parsed->canonical_name.size()==253,"large DNS response was invalid");
                checked=true;
            }
            auto sent=::sendto(fd_,reply.data(),reply.size(),0,reinterpret_cast<sockaddr const*>(&query.sender),sizeof(query.sender));
            require(sent==static_cast<ssize_t>(reply.size()),"DNS reply send failed");
        }
    }
};

class Worker {
    using Owner=hp::FlightOwner<hp::GroupBinding>;
    using Operation=hp::FlightOperation<hp::GroupBinding>;
    struct Request {
        Operation operation;
        std::optional<hp::FlightGroup::Result> result;
        Request(hp::FlightGroup& group,Owner& owner) : operation(group,owner) {}
    };
    struct State {
        io::io_context context;
        hp::GroupBinding binding;
        hp::GroupSnapshot::Reader reader;
        Owner owner;
        std::vector<std::unique_ptr<Request>> requests;
        std::size_t completed=0;
        State(bool uring,hp::GroupSnapshot& cache,hp::FlightGroup& group,std::size_t index)
#if BOOST_COROSIO_HAVE_LIBURING
            : context(uring ? io::io_context(io::uring) : io::io_context(io::epoll)),
#else
            : context(io::epoll),
#endif
              binding(cache,0),reader(cache.reader(index)),owner(context,binding,group,30s) {
#if !BOOST_COROSIO_HAVE_LIBURING
            (void)uring;
#endif
            requests.reserve(waiter_count/worker_count);
        }
    };
    hp::FlightGroup& group_;
    std::vector<std::string> const& names_;
    io::endpoint upstream_;
    std::atomic<std::size_t>& completed_;
    std::atomic<std::size_t>& failed_;
    State state_;
    std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<std::move_only_function<void()>> commands_;
    bool quitting_=false;
    std::thread thread_;
    static auto run(Request& request,hp::FlightGroup::Key key) -> capy::task<> {
        request.result.emplace(co_await request.operation.resolve(std::move(key),Clock::now()+30s));
    }
    auto enqueue(std::move_only_function<void()> command) -> void {
        { std::lock_guard lock(mutex_); commands_.push_back(std::move(command)); }
        condition_.notify_one();
    }
    auto loop() -> void {
        for (;;) {
            std::deque<std::move_only_function<void()>> commands;
            {
                std::unique_lock lock(mutex_);
                condition_.wait_for(lock,2ms,[&] { return !commands_.empty(); });
                commands.swap(commands_);
            }
            for (auto& command:commands) command();
            state_.context.restart(); (void)state_.context.run_for(2ms);
            if (quitting_ && state_.completed==state_.requests.size() && state_.owner.drained()) {
                state_.requests.clear(); break;
            }
        }
    }
public:
    Worker(bool uring,hp::GroupSnapshot& cache,hp::FlightGroup& group,std::size_t index,
           std::vector<std::string> const& all_names,io::endpoint upstream,
           std::atomic<std::size_t>& completed,std::atomic<std::size_t>& failed)
        : group_(group),names_(all_names),upstream_(upstream),completed_(completed),failed_(failed),
          state_(uring,cache,group,index),thread_([this] { loop(); }) {}
    Worker(Worker const&)=delete;
    ~Worker() {
        if (!thread_.joinable()) return;
        enqueue([this] {
            for (auto& request:state_.requests) request->operation.cancel();
            state_.owner.stop(); quitting_=true;
        });
        thread_.join();
    }
    auto launch(std::size_t rounds) -> void {
        std::promise<void> ack; auto future=ack.get_future();
        enqueue([this,rounds,ack=std::move(ack)]() mutable {
            try {
                for (std::size_t round=0;round<rounds;++round) for (auto const& name:names_) {
                    auto request=std::make_unique<Request>(group_,state_.owner);
                    hp::FlightGroup::Key key{{1,name,1},upstream_,false,false,true};
                    auto* value=request.get(); state_.requests.push_back(std::move(request));
                    try {
                        capy::run_async(state_.context.get_executor(),[this] {
                            ++state_.completed; completed_.fetch_add(1,std::memory_order_release);
                        },[this](std::exception_ptr) noexcept {
                            ++state_.completed; failed_.fetch_add(1); completed_.fetch_add(1,std::memory_order_release);
                        })(run(*value,std::move(key)));
                    } catch (...) { state_.requests.pop_back(); throw; }
                }
                ack.set_value();
            } catch (...) { ack.set_exception(std::current_exception()); }
        });
        future.get();
    }
    auto pause() -> std::promise<void> {
        std::promise<void> ack,release; auto ready=ack.get_future(),gate=release.get_future();
        enqueue([ack=std::move(ack),gate=std::move(gate)]() mutable { ack.set_value(); (void)gate.wait_for(20s); });
        require(ready.wait_for(5s)==std::future_status::ready,"executor pause failed");
        ready.get(); return release;
    }
    auto active() -> std::size_t {
        std::promise<std::size_t> ack; auto future=ack.get_future();
        enqueue([this,ack=std::move(ack)]() mutable { ack.set_value(state_.owner.active()); });
        return future.get();
    }
    auto verify() -> bool {
        std::promise<bool> ack; auto future=ack.get_future();
        enqueue([this,ack=std::move(ack)]() mutable {
            bool good=state_.requests.size()==waiter_count/worker_count && state_.owner.drained();
            for (auto const& request:state_.requests) {
                if (!request->result || !*request->result || (**request->result).chain.size()!=aliases+1 ||
                    (**request->result).addresses.size()!=addresses || (**request->result).canonical_name.size()!=253) good=false;
            }
            ack.set_value(good);
        });
        return future.get();
    }
    auto clear_results() -> void {
        std::promise<void> ack; auto future=ack.get_future();
        enqueue([this,ack=std::move(ack)]() mutable {
            for (auto& request:state_.requests) request->result.reset();
            ack.set_value();
        });
        future.get();
    }
};

struct Memory {
    unsigned long long rss_kb=0,pss_kb=0,anonymous_kb=0,virtual_kb=0,threads=0;
};
auto memory() -> Memory {
    Memory result; char line[512];
    if (auto* file=std::fopen("/proc/self/smaps_rollup","r")) {
        while (std::fgets(line,sizeof(line),file)) {
            (void)(std::sscanf(line,"Rss: %llu kB",&result.rss_kb)==1 ||
                   std::sscanf(line,"Pss: %llu kB",&result.pss_kb)==1 ||
                   std::sscanf(line,"Anonymous: %llu kB",&result.anonymous_kb)==1);
        }
        std::fclose(file);
    } else throw std::runtime_error("cannot read smaps_rollup");
    if (auto* file=std::fopen("/proc/self/status","r")) {
        while (std::fgets(line,sizeof(line),file)) {
            (void)(std::sscanf(line,"VmSize: %llu kB",&result.virtual_kb)==1 ||
                   std::sscanf(line,"Threads: %llu",&result.threads)==1);
        }
        std::fclose(file);
    } else throw std::runtime_error("cannot read process status");
    return result;
}
struct FdStats {
    std::size_t descriptors=0,udp=0,unavailable=0;
    std::uint64_t receive=0,receive_limit=0,send=0,send_limit=0,forward=0,queued=0,options=0,backlog=0,drops=0;
};
auto fd_stats() -> FdStats {
    auto* directory=::opendir("/proc/self/fd"); require(directory!=nullptr,"cannot read file descriptors");
    FdStats result;
    while (auto* entry=::readdir(directory)) {
        if (entry->d_name[0]=='.') continue;
        char* end=nullptr; auto number=std::strtol(entry->d_name,&end,10);
        if (!end || *end || number==::dirfd(directory)) continue;
        ++result.descriptors;
        int type=0,domain=0; socklen_t size=sizeof(type);
        if (::getsockopt(static_cast<int>(number),SOL_SOCKET,SO_TYPE,&type,&size)!=0 || type!=SOCK_DGRAM) continue;
        size=sizeof(domain);
        if (::getsockopt(static_cast<int>(number),SOL_SOCKET,SO_DOMAIN,&domain,&size)!=0 || (domain!=AF_INET && domain!=AF_INET6)) continue;
        ++result.udp; std::array<std::uint32_t,SK_MEMINFO_VARS> info{}; size=sizeof(info);
        if (::getsockopt(static_cast<int>(number),SOL_SOCKET,SO_MEMINFO,info.data(),&size)!=0 || size<sizeof(info)) {
            ++result.unavailable; continue;
        }
        result.receive+=info[SK_MEMINFO_RMEM_ALLOC]; result.receive_limit+=info[SK_MEMINFO_RCVBUF];
        result.send+=info[SK_MEMINFO_WMEM_ALLOC]; result.send_limit+=info[SK_MEMINFO_SNDBUF];
        result.forward+=info[SK_MEMINFO_FWD_ALLOC]; result.queued+=info[SK_MEMINFO_WMEM_QUEUED];
        result.options+=info[SK_MEMINFO_OPTMEM]; result.backlog+=info[SK_MEMINFO_BACKLOG]; result.drops+=info[SK_MEMINFO_DROPS];
    }
    ::closedir(directory); return result;
}
auto sample(char const* stage,hp::FlightGroup& group,hp::GroupSnapshot& cache,std::size_t completed) -> void {
    auto m=memory(); auto fd=fd_stats(); auto heap=::mallinfo2(); struct rusage usage{};
    require(::getrusage(RUSAGE_SELF,&usage)==0,"getrusage failed");
    auto [flights,waiters]=group.counts();
    std::printf("{\"stage\":\"%s\",\"rss_kb\":%llu,\"pss_kb\":%llu,\"anonymous_kb\":%llu,"
                "\"virtual_kb\":%llu,\"threads\":%llu,\"fds\":%zu,\"heap_allocated\":%zu,"
                "\"heap_mapped\":%zu,\"maxrss_kb\":%ld,\"cache_charged\":%zu,\"flights\":%zu,"
                "\"waiters\":%zu,\"completed\":%zu,\"udp_sockets\":%zu,\"sock_mem_unavailable\":%zu,"
                "\"sock_receive\":%llu,\"sock_receive_limit\":%llu,\"sock_send\":%llu,\"sock_send_limit\":%llu,"
                "\"sock_forward\":%llu,\"sock_queued\":%llu,\"sock_options\":%llu,\"sock_backlog\":%llu,\"sock_drops\":%llu}\n",
                stage,m.rss_kb,m.pss_kb,m.anonymous_kb,m.virtual_kb,m.threads,fd.descriptors,heap.uordblks,heap.hblkhd,
                usage.ru_maxrss,cache.charged_bytes(),flights,waiters,completed,fd.udp,fd.unavailable,
                static_cast<unsigned long long>(fd.receive),static_cast<unsigned long long>(fd.receive_limit),
                static_cast<unsigned long long>(fd.send),static_cast<unsigned long long>(fd.send_limit),
                static_cast<unsigned long long>(fd.forward),static_cast<unsigned long long>(fd.queued),
                static_cast<unsigned long long>(fd.options),static_cast<unsigned long long>(fd.backlog),static_cast<unsigned long long>(fd.drops));
    std::fflush(stdout);
}
template<class Check> auto wait_until(Check&& check,char const* message) -> void {
    auto deadline=Clock::now()+25s;
    while (!check()) { require(Clock::now()<deadline,message); std::this_thread::sleep_for(2ms); }
}
auto execute(bool uring) -> void {
    auto all_names=names(); Peer peer;
    std::array<std::size_t,1> capacities{256}; hp::GroupSnapshot cache(capacities,worker_count,0,16*1024*1024);
    hp::FlightGroup group(flight_count,waiter_count);
    std::atomic<std::size_t> completed=0,failed=0;
    std::vector<std::unique_ptr<Worker>> workers; workers.reserve(worker_count);
    for (std::size_t i=0;i<worker_count;++i)
        workers.push_back(std::make_unique<Worker>(uring,cache,group,i,all_names,peer.endpoint(),completed,failed));
    sample("idle",group,cache,completed.load());

    workers[0]->launch(1);
    wait_until([&] { peer.drain(); return peer.count()==flight_count && group.counts()==std::pair<std::size_t,std::size_t>{flight_count,flight_count}; },
               "leaders did not open all DNS queries");
    workers[0]->launch(3);
    for (std::size_t i=1;i<worker_count;++i) workers[i]->launch(4);
    wait_until([&] { peer.drain(); return group.counts()==std::pair<std::size_t,std::size_t>{flight_count,waiter_count}; },
               "waiters did not reach the group limit");
    require(peer.count()==flight_count && completed.load()==0,"unexpected query or early completion");
    require(workers[0]->active()==flight_count,"network owners did not start");
    for (std::size_t i=1;i<worker_count;++i) require(workers[i]->active()==0,"unexpected network owner");
    require(group.counts()==std::pair<std::size_t,std::size_t>{flight_count,waiter_count},"waiters changed at the sampling barrier");
    sample("network_pending",group,cache,completed.load());

    std::vector<std::promise<void>> gates; gates.reserve(worker_count-1);
    for (std::size_t i=1;i<worker_count;++i) gates.push_back(workers[i]->pause());
    peer.answer_all(all_names);
    wait_until([&] { return completed.load(std::memory_order_acquire)==waiter_count/worker_count &&
                           group.counts()==std::pair<std::size_t,std::size_t>{flight_count,3*waiter_count/worker_count}; },
               "leaders or retained answers did not finish");
    require(failed.load()==0,"task failed while retaining answers");
    wait_until([&] { return workers[0]->active()==0; },"network owners did not drain");
    sample("followers_paused",group,cache,completed.load());
    for (auto& gate:gates) gate.set_value();
    wait_until([&] { return completed.load(std::memory_order_acquire)==waiter_count &&
                           group.counts()==std::pair<std::size_t,std::size_t>{0,0}; },"followers did not drain");
    require(failed.load()==0,"task failed after replies");
    for (auto& worker:workers) require(worker->verify(),"DNS response or owner validation failed");
    sample("answers_held",group,cache,completed.load());
    for (auto& worker:workers) worker->clear_results();
    sample("answers_released",group,cache,completed.load());
    workers.clear();
    sample("workers_stopped",group,cache,completed.load());
}
}

auto main(int argc,char** argv) -> int {
    try {
        bool uring=argc==2 && std::string_view(argv[1])=="--uring";
        require(argc==1 || uring,"usage: group_flight_memory [--uring]");
#if !BOOST_COROSIO_HAVE_LIBURING
        require(!uring,"io_uring unavailable in this build");
#endif
        execute(uring); return 0;
    } catch (std::exception const& error) { std::fprintf(stderr,"memory experiment: %s\n",error.what()); return 1; }
}
