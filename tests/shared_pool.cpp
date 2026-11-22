import std;
import net.connection_pool;
struct Connection{
    static inline unsigned destroyed=0;
    unsigned id,leases=0,cancels=0,stops=0;
    bool accepting=true,running=true;
    explicit Connection(unsigned value):id(value){}
    ~Connection(){if(leases||running)std::abort();++destroyed;}
    auto usable() const noexcept->bool{return accepting;}
    auto available() const noexcept->bool{return accepting&&leases<2;}
    auto acquired() noexcept->void{++leases;}
    auto released() noexcept->void{--leases;}
    auto cancel() noexcept->void{accepting=false;++cancels;}
    auto stop() noexcept->void{accepting=false;++stops;}
    auto drained() const noexcept->bool{return !running&&!leases;}
};
static auto require(bool value,std::string_view name)->void{if(!value)throw std::runtime_error(std::string(name));}
int main(){try{
    using Pool=net::ConnectionPool<Connection,true>;
    Pool pool({.max_sessions=3});auto c0=pool.reserve();require(bool(c0),"reserve0");
    auto first=std::make_unique<Connection>(0);auto* p0=first.get();auto a=c0->commit(std::move(first));require(bool(a),"commit0");
    auto b=pool.acquire();require(b&&b->connection().id==0&&p0->leases==2,"two leases share physical connection");
    require(!pool.acquire(),"physical RPC slot bounded");auto c1=pool.reserve();require(bool(c1)&&!pool.reserve(),"creation counts toward global business cap");
    auto second=std::make_unique<Connection>(1);auto* p1=second.get();auto c=c1->commit(std::move(second));require(bool(c),"commit1");
    require(!pool.acquire()&&!pool.reserve(),"global max-sessions3 counts business leases");
    a->reset();require(p0->leases==1&&!p0->cancels,"returning one shared lease keeps other business alive");
    auto d=pool.acquire();require(d&&d->connection().id==1,"newest available connection retained");require(!pool.acquire(),"global bound remains exact");
    p1->accepting=false;c->reset();d->reset();require(p1->cancels==1&&!p1->stops&&p1->leases==0,"GOAWAY retirement is soft and one-shot");
    pool.reap(net::PoolClock::now());require(pool.size()==2&&!Connection::destroyed,"running root keeps retired connection alive");
    p1->running=false;pool.reap(net::PoolClock::now());require(pool.size()==1&&Connection::destroyed==1,"retired root reaped after drain");
    auto e=pool.acquire();require(e&&e->connection().id==0&&p0->leases==2,"healthy old connection reused");
    pool.stop();require(p0->stops==1&&p0->cancels==1&&!pool.drained()&&!pool.acquire()&&!pool.reserve(),"hard worker stop preserves outstanding leases");
    b->reset();e->reset();require(!pool.drained()&&p0->leases==0,"physical run root still pending");
    p0->running=false;pool.reap(net::PoolClock::now());require(pool.drained()&&!pool.size()&&Connection::destroyed==2,"all physical owners naturally destroyed");
    std::println("shared pool physical slots, global business cap, soft GOAWAY, hard stop and drain passed; exclusive-size={} shared-size={} lease-size={}",sizeof(net::ConnectionPool<Connection>),sizeof(Pool),sizeof(Pool::Lease));return 0;
}catch(std::exception const& error){std::println("{}",error.what());return 1;}}
