export module proxy.host;
import std;
import proxy;

export namespace proxy {
    // Register services in dependency order. Hooks run on the host's control
    // thread and any objects they borrow outlive the Host.
    struct HostService {
        std::move_only_function<std::expected<void,std::string>()> start;
        std::move_only_function<void() noexcept> stop;
        std::move_only_function<bool() const> healthy{};
        std::move_only_function<void()> begin_drain{};
        std::move_only_function<bool()> poll_drain{};
        std::move_only_function<void(std::chrono::milliseconds)> poll{};
    };

    struct HostTcpListener {
        std::uint16_t port=0;
        Inbound inbound=Inbound::socks5;
        unsigned workers=1;
        bool ipv6=false;
        std::optional<std::array<std::uint8_t,16>> address;
        bool traffic_stats=false;
    };

    [[nodiscard]] inline auto start_host_tcp(Server& server,HostTcpListener const& listener)
        -> std::expected<std::uint16_t,std::string> {
        if (listener.traffic_stats && !server.enable_traffic_stats())
            return std::unexpected("cannot enable traffic statistics");
        auto bound=server.start(listener.port,listener.inbound,listener.workers,listener.ipv6,listener.address);
        if (!bound) return std::unexpected(bound.error().message());
        return *bound;
    }

    // Services are stopped in reverse start order. A partial startup drains
    // each attempted service before start() returns its error.
    class Host {
        std::vector<HostService> services_;
        std::size_t started_=0;
        bool sealed_=false,active_=false;
    public:
        Host()=default;
        Host(Host const&)=delete;
        auto operator=(Host const&) -> Host& = delete;
        ~Host() { stop(); }

        [[nodiscard]] auto add(HostService service) -> bool {
            if (sealed_ || !service.start || !service.stop ||
                bool(service.begin_drain)!=bool(service.poll_drain)) return false;
            services_.push_back(std::move(service));
            return true;
        }

        [[nodiscard]] auto add_tcp(Server& server,HostTcpListener& listener) -> bool {
            return add({
                [&]() -> std::expected<void,std::string> {
                    auto bound=start_host_tcp(server,listener);
                    if (!bound) return std::unexpected(std::move(bound.error()));
                    listener.port=*bound;
                    return {};
                },
                [&]() noexcept {server.stop();},
                [&] {return server.healthy();},
                [&] {server.begin_drain();},
                [&] {
                    if (!server.drained()) server.poll(std::chrono::milliseconds(0));
                    return server.drained();
                },
                [&](std::chrono::milliseconds wait) {server.poll(wait);}
            });
        }

        [[nodiscard]] auto start(std::function_ref<bool()> canceled) -> std::expected<void,std::string> {
            if (std::exchange(sealed_,true)) return std::unexpected("host startup already attempted");
            struct Rollback {
                Host& host;
                ~Rollback() {if (!host.active_) host.stop();}
            } rollback{*this};
            for (auto& service : services_) {
                if (canceled()) return std::unexpected("startup canceled");
                ++started_;
                if (auto result=service.start(); !result) return result;
            }
            if (canceled()) return std::unexpected("startup canceled");
            active_=true;
            return {};
        }

        [[nodiscard]] auto start() -> std::expected<void,std::string> {
            auto running=[] {return false;};
            return start(running);
        }

        [[nodiscard]] auto healthy() const -> bool {
            return active_ && std::ranges::all_of(services_,[](HostService const& service) {
                return !service.healthy || service.healthy();
            });
        }

        auto poll(std::chrono::milliseconds wait_per_service={}) -> void {
            if (!active_) return;
            for (auto& service : services_) if (service.poll) service.poll(wait_per_service);
        }

        auto drain(std::chrono::milliseconds grace) -> void {
            if (!active_ || grace<=std::chrono::milliseconds::zero()) return;
            for (auto& service : services_) if (service.begin_drain) service.begin_drain();
            auto deadline=std::chrono::steady_clock::now()+grace;
            for (;;) {
                bool complete=true;
                for (auto& service : services_)
                    if (service.poll_drain) complete&=service.poll_drain();
                if (complete || std::chrono::steady_clock::now()>=deadline) return;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        }

        auto stop() noexcept -> void {
            sealed_=true;
            active_=false;
            while (started_) services_[--started_].stop();
        }
    };
}
