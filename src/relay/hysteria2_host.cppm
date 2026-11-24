export module relay.hysteria2_host;
import std;
import relay;
import relay.hysteria2_business;
import hysteria2.credential;
import hysteria2.listener;
import hysteria2.transport_options;
import tls.server_credential;
import quic.retry_admission;
import quic.datagram_port;
import net.datagram_driver;
import corosio;

export namespace relay {
    // A configured Hysteria2 listener owns one typed QUIC owner per executor.
    // Credentials and routing are borrowed until every worker has joined.
    using Hysteria2HostFailure=std::variant<std::error_code,quic::RetryFailure,std::exception_ptr>;
    struct Hysteria2RuntimeFailure {
        enum class Kind {driver,initialization,callback,close,timeout,udp,unexpected} kind;
        std::optional<net::DatagramFailure> driver;
        std::optional<quic::DatagramPortError> port;
        std::optional<quic::RetryFailure> retry;
        std::error_code system;
        std::exception_ptr exception;
        int native=0;
    };
    class Hysteria2Host {
        struct Worker {
            Server routing{RoutingOnly{}};
            Hysteria2Business hooks;
            hysteria2::Listener<Hysteria2Business,16,16,16384> listener;
            static auto inherit(Server&,Server&,std::size_t,std::size_t,std::span<hysteria2::Password const>,std::span<std::string const>) -> Hysteria2Business;
            Worker(Server&,std::size_t,std::size_t,std::span<hysteria2::Password const>,std::span<std::string const>,tls::ServerCredential const&,hysteria2::TransportOptions);
            ~Worker();
        };
        Server& parent_;tls::ServerCredential const& credential_;std::span<hysteria2::Password const> passwords_;
        std::span<std::string const> names_;hysteria2::TransportOptions options_;
        std::vector<std::unique_ptr<Worker>> workers_;std::vector<std::thread> threads_;
        std::atomic_bool stop_{false},failed_{false};
        mutable std::mutex failure_mutex_;std::optional<Hysteria2RuntimeFailure> failure_;
        auto record(Hysteria2RuntimeFailure) noexcept -> void;
        auto loop(Worker&) noexcept -> void;
    public:
        Hysteria2Host(Server&,tls::ServerCredential const&,std::span<hysteria2::Password const>,std::span<std::string const>,hysteria2::TransportOptions options={});
        Hysteria2Host(Hysteria2Host const&)=delete;auto operator=(Hysteria2Host const&) -> Hysteria2Host& = delete;
        ~Hysteria2Host();
        auto start(std::uint16_t,bool,unsigned) -> std::expected<std::uint16_t,Hysteria2HostFailure>;
        auto start(corosio::endpoint,unsigned) -> std::expected<std::uint16_t,Hysteria2HostFailure>;
        [[nodiscard]] auto queue_outbound_probe(std::shared_ptr<OutboundProbe> probe) -> bool {
            return !workers_.empty() && workers_.front()->routing.queue_outbound_probe(std::move(probe));
        }
        auto healthy() const noexcept -> bool {return !failed_.load(std::memory_order_acquire);}
        auto failure() const -> std::optional<Hysteria2RuntimeFailure>;
        auto stop() noexcept -> void;
    };
}
