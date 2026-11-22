import std;
import snell.client_pool;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
namespace io=nex::corosio;
using namespace std::chrono_literals;
struct State {int destroyed=0;bool destroyed_during_cancel=false;};
struct Node {
    State& state;bool stopped=false,ready=true,in_cancel=false;std::function<void()> callback;
    explicit Node(State& s):state(s){}
    ~Node(){++state.destroyed;if(in_cancel)state.destroyed_during_cancel=true;}
    auto reusable() const noexcept ->bool {return ready&&!stopped;}
    auto stopping() const noexcept ->bool{return stopped;}
    auto cancel() noexcept ->void {if(stopped)return;stopped=true;in_cancel=true;if(callback)callback();in_cancel=false;}
};
int main(int argc,char** argv){
    bool uring=argc>1&&std::string_view(argv[1])=="uring";if(uring&&!io::has_uring)return 77;
    auto context=io::make_io_context(uring);State state;
    using Pool=snell::ClientPool<Node>;using Lease=Pool::Lease;
    Pool pool(context);pool.start();std::vector<std::unique_ptr<Lease>> leases;
    for(int i=0;i<12;++i){auto lease=pool.take([&]{return std::make_unique<Node>(state);});if(!lease)return 1;leases.push_back(std::make_unique<Lease>(std::move(*lease)));}
    auto* first=&leases.front()->node();leases.clear();if(state.destroyed!=2)return 2;
    auto reused=pool.take([&]{return std::make_unique<Node>(state);});if(!reused)return 3;
    // The idle pool is LIFO; acquiring any old node proves it was retained.
    if(state.destroyed!=2||!reused->node().reusable())return 4;
    (void)first;reused.reset();pool.reap(std::chrono::steady_clock::now()+181s);if(state.destroyed!=12)return 5;
    auto active=pool.take([&]{return std::make_unique<Node>(state);});if(!active)return 6;
    active->node().callback=[&]{active.reset();};pool.stop();
    if(active||state.destroyed_during_cancel||state.destroyed!=13)return 7;
    context.run_for(1s);if(!pool.drained())return 8;
    std::println("Snell idle limits, reuse, expiry and synchronous stop release passed");return 0;
}
