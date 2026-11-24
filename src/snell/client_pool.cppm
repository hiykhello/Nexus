export module snell.client_pool;
import std;
import capy;
import corosio;

export namespace snell {
    // One pool per executor, credential profile, dial options and detour.
    // Active nodes belong to leases; idle nodes belong to the pool.  Callers
    // cancel and drain lease I/O before release, and drain all leases and the
    // monitor before destroying this pool.  Node::reusable() may be true only
    // after both authenticated EOFs and all in-flight operations have drained.
    // Node::cancel() must mark stopping() before invoking any callback, which
    // permits stop() to tolerate synchronous lease release and list mutation.
    template<class Node> class ClientPool {
        using Clock=std::chrono::steady_clock;
        struct Idle {std::shared_ptr<Node> node;Clock::time_point since;};
        corosio::io_context& context_;std::vector<Idle> idle_;std::vector<std::shared_ptr<Node>> active_;
        std::stop_source stop_;bool stopped_=false,monitor_running_=false;
        static constexpr std::size_t max_idle=10;
        static constexpr auto max_age=std::chrono::seconds(180),interval=std::chrono::seconds(20);
        struct Monitor {
            ClientPool* owner;
            explicit Monitor(ClientPool& value):owner(&value){}
            Monitor(Monitor const&)=delete;
            Monitor(Monitor&& other) noexcept:owner(std::exchange(other.owner,nullptr)){}
            ~Monitor(){if(owner){owner->stop();owner->monitor_running_=false;}}
        };
        static auto monitor(Monitor lifetime)->capy::task<> {
            auto& owner=*lifetime.owner;
            while(!owner.stopped_){owner.reap(Clock::now());auto [error]=co_await corosio::delay(interval);if(error)break;}
        }
        auto release(std::shared_ptr<Node> node) noexcept ->void {
            auto found=std::ranges::find(active_,node);if(found==active_.end())std::terminate();active_.erase(found);
            if(!stopped_&&node->reusable()&&idle_.size()<max_idle){
                // Capacity is reserved at construction; no allocation can
                // fail while a lease destructor returns an idle connection.
                idle_.push_back(Idle{std::move(node),Clock::now()});return;
            }
            node->cancel();
        }
    public:
        class Lease {
            friend class ClientPool;
            ClientPool* owner_=nullptr;std::shared_ptr<Node> node_;
            Lease(ClientPool& owner,std::shared_ptr<Node> node):owner_(&owner),node_(std::move(node)){}
        public:
            Lease(Lease const&)=delete;auto operator=(Lease const&)->Lease& =delete;
            Lease(Lease&& value) noexcept:owner_(std::exchange(value.owner_,nullptr)),node_(std::move(value.node_)){}
            auto operator=(Lease&&)->Lease& =delete;
            ~Lease(){auto* owner=std::exchange(owner_,nullptr);auto node=std::move(node_);if(owner)owner->release(std::move(node));}
            auto node() const noexcept ->Node& {return *node_;}
            auto hold() const noexcept ->std::shared_ptr<Node> {return node_;}
        };
        explicit ClientPool(corosio::io_context& context):context_(context){idle_.reserve(max_idle);}
        ClientPool(ClientPool const&)=delete;auto operator=(ClientPool const&)->ClientPool& =delete;
        ~ClientPool(){stop();if(!drained())std::terminate();}
        auto start()->void {
            if(stopped_||monitor_running_)throw std::logic_error("Snell pool cannot start");monitor_running_=true;
            try{capy::run_async(context_.get_executor(),stop_.get_token(),[] {},
                [this](std::exception_ptr) noexcept {stop();})(monitor(Monitor(*this)));}
            catch(...){monitor_running_=false;stop();throw;}
        }
        auto stop() noexcept ->void {
            if(stopped_)return;stopped_=true;stop_.request_stop();
            for(auto& item:idle_)item.node->cancel();idle_.clear();
            for(;;){auto found=std::ranges::find_if(active_,[](auto const& value){return !value->stopping();});
                if(found==active_.end())break;auto node=*found;node->cancel();}
        }
        [[nodiscard]] auto drained() const noexcept ->bool {return !monitor_running_&&active_.empty();}
        auto reap(Clock::time_point now) noexcept ->void {
            std::erase_if(idle_,[now](Idle& entry){
                if(!entry.node->reusable()||(now>=entry.since&&now-entry.since>=max_age)){entry.node->cancel();return true;}return false;
            });
        }
        // Registration happens before any asynchronous connection startup, so
        // stop() also cancels nodes which are still resolving or connecting.
        template<class Create> auto take(Create&& create)->std::optional<Lease> {
            if(stopped_)return {};reap(Clock::now());std::shared_ptr<Node> node;
            if(!idle_.empty()){node=std::move(idle_.back().node);idle_.pop_back();}
            else node=std::forward<Create>(create)();
            if(!node)return {};
            try{active_.push_back(node);}catch(...){node->cancel();throw;}
            return Lease(*this,std::move(node));
        }
    };
}
