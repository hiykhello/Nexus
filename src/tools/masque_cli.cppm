export module cli.masque_enabled;
import std;
import config;
import relay;
import masque.config;
import masque.ip_server;
import masque.listener;
import tls.ech_server;
import tls.server_credential;
import cli.cert_reloader;
import logging.cli;
import dns.local_config;
import corosio;

export namespace cli::masque_enabled {
    // A listener worker owns its io_context; immutable credentials and target
    // policy outlive every worker and are erased only after all joins.
    class Runtime {
        struct Worker {
            corosio::io_context context;
            masque::Listener<> listener;
            Worker(bool uring,masque::HostConfig const& config,tls::ServerCredential const* credential,
                std::shared_ptr<tls::AtomicServerCredential> atomic_credential,
                masque::IpServerPort* ip,relay::Server& accounting,std::shared_ptr<tls::EchServerKeys const> ech_keys)
                :context(corosio::make_io_context(uring)),
                 listener(context,config,credential,std::move(atomic_credential),dns::system_local_snapshots(),ip,&accounting,std::move(ech_keys)) {}
        };
        struct Profile {
            std::optional<tls::ServerCredential> credential;
            std::shared_ptr<tls::AtomicServerCredential> atomic_credential;
            std::shared_ptr<tls::EchServerKeys const> ech_keys;
            masque::HostConfig config;
            masque::IpServerPort ip;
            std::array<std::uint8_t,16> address{};bool ipv6=false;
            std::vector<std::unique_ptr<Worker>> workers;
            std::vector<std::thread> threads;
            std::atomic_bool stopped{false},failed{false};
            Profile(std::optional<tls::ServerCredential> key,std::shared_ptr<tls::AtomicServerCredential> atomic_key,
                std::shared_ptr<tls::EchServerKeys const> ech,masque::HostConfig value)
                :credential(std::move(key)),atomic_credential(std::move(atomic_key)),ech_keys(std::move(ech)),config(std::move(value)) {}
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
        auto configure(std::size_t,config::InboundConfig const&,std::shared_ptr<void> const& acme_credential={},
            cli::CertReloaderHub* cert_reloaders=nullptr,logging::Runtime const* logs=nullptr) -> std::expected<void,std::string>;
        auto start(std::size_t,relay::Server&,std::uint16_t,unsigned) -> std::expected<std::uint16_t,std::string>;
        auto healthy() const noexcept -> bool {return std::ranges::all_of(profiles_,[](auto const& p){return !p || !p->failed.load(std::memory_order_acquire);});}
        auto failure() const -> std::optional<std::string> {return healthy() ? std::nullopt : std::optional<std::string>{"MASQUE listener worker failed"};}
        auto stop() noexcept -> void {for(auto& p:profiles_)if(p)stop_profile(*p);}
    };
}
