export module cli.masque_enabled;
import std;
import config;
import proxy;
import masque.config;
import masque.ip_server;
import masque.listener;
import tls.server_credential;
import dns.local_config;
import nexus.thirdparty.corosio;

export namespace cli::masque_enabled {
    // A listener worker owns its io_context; immutable credentials and target
    // policy outlive every worker and are erased only after all joins.
    class Runtime {
        struct Worker {
            nex::corosio::io_context context;
            masque::Listener<> listener;
            Worker(bool uring,masque::HostConfig const& config,tls::ServerCredential const& credential,
                masque::IpServerPort* ip,proxy::Server& accounting)
                :context(nex::corosio::make_io_context(uring)),listener(context,config,credential,dns::system_local_snapshots(),ip,&accounting) {}
        };
        struct Profile {
            tls::ServerCredential credential;
            masque::HostConfig config;
            std::unique_ptr<masque::IpServerPort> ip;
            std::array<std::uint8_t,16> address{};bool ipv6=false;
            std::vector<std::unique_ptr<Worker>> workers;
            std::vector<std::thread> threads;
            std::atomic_bool stopped{false},failed{false};
            Profile(tls::ServerCredential key,masque::HostConfig value):credential(std::move(key)),config(std::move(value)) {}
        };
        std::vector<std::unique_ptr<Profile>> profiles_;
        bool uring_;
        static auto loop(Profile&,Worker&) noexcept -> void;
        static auto stop_profile(Profile&) noexcept -> void;
    public:
        explicit Runtime(bool uring):uring_(uring) {}
        Runtime(Runtime const&)=delete;auto operator=(Runtime const&) -> Runtime& = delete;
        ~Runtime(){stop();}
        auto resize(std::size_t count) -> void {profiles_.resize(count);}
        auto configure(std::size_t,config::InboundConfig const&) -> std::expected<void,std::string>;
        auto start(std::size_t,proxy::Server&,std::uint16_t,unsigned) -> std::expected<std::uint16_t,std::string>;
        auto healthy() const noexcept -> bool {return std::ranges::all_of(profiles_,[](auto const& p){return !p || !p->failed.load(std::memory_order_acquire);});}
        auto failure() const -> std::optional<std::string> {return healthy() ? std::nullopt : std::optional<std::string>{"MASQUE listener worker failed"};}
        auto stop() noexcept -> void {for(auto& p:profiles_)if(p)stop_profile(*p);}
    };
}
