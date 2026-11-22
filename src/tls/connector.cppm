export module tls.connector;
import std;
import tls.corosio_client;
import tls.corosio_application;
import tls.encrypted_extensions;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace tls::detail {
    enum class ConnectResult { connected,retryable,failed,timeout };
    using ConnectClock=std::chrono::steady_clock;
    template<class Profile>
    auto physical_handshake(Profile const& profile,std::uint64_t now,std::uint64_t deadline,
        std::int64_t verification_time,nex::corosio::endpoint const& endpoint) {
        if constexpr (requires {profile.handshake(now,deadline,verification_time,std::span<std::uint8_t const>{});}) {
            std::array<std::uint8_t,19> target{};
            target[0]=endpoint.is_v4() ? 4 : 6;
            target[1]=static_cast<std::uint8_t>(endpoint.port()>>8);
            target[2]=static_cast<std::uint8_t>(endpoint.port());
            if (endpoint.is_v4()) std::ranges::copy(endpoint.address().to_v4().to_bytes(),target.begin()+3);
            else std::ranges::copy(endpoint.address().to_v6().to_bytes(),target.begin()+3);
            return profile.handshake(now,deadline,verification_time,std::span<std::uint8_t const>(target));
        } else return profile.handshake(now,deadline,verification_time);
    }
    // Resolver owns a cancellable query slot and returns all node candidates
    // under this one deadline. Protocol authentication starts after TLS.
    template<class Resolver,class Profile>
    class PhysicalConnector {
        nex::corosio::io_context& context_;
        Resolver resolver_;
        Profile const& profile_;
        platform::TcpSocketOptions const& options_;
        std::unique_ptr<OwnedClient> owner_;
        bool starting_=false,canceled_=false;
    public:
        using Socket=nex::corosio::tcp_socket;
        PhysicalConnector(nex::corosio::io_context& context,Resolver resolver,Profile const& profile,platform::TcpSocketOptions const& options)
            : context_(context),resolver_(std::move(resolver)),profile_(profile),options_(options) {}
        PhysicalConnector(PhysicalConnector const&)=delete;
        auto operator=(PhysicalConnector const&) -> PhysicalConnector& = delete;
        auto cancel() noexcept -> void { canceled_=true; resolver_.cancel(); if (owner_) owner_->cancel(); }
        auto application() noexcept -> ApplicationConnection<nex::corosio::tcp_socket>* {
            return owner_ && owner_->client() ? owner_->client()->application() : nullptr;
        }
        auto negotiated() const noexcept -> EncryptedExtensions const* {
            return owner_ && owner_->client() ? owner_->client()->negotiated() : nullptr;
        }
        auto start(ConnectClock::time_point deadline) -> nex::capy::task<ConnectResult> {
            if (starting_ || owner_ || canceled_) co_return ConnectResult::failed;
            if (ConnectClock::now()>=deadline) co_return ConnectResult::timeout;
            starting_=true;
            struct Guard { PhysicalConnector& owner; bool done=false; ~Guard() { owner.starting_=false; if (!done) owner.cancel(); } } guard{*this};
            auto endpoints=co_await resolver_(deadline);
            if (canceled_) co_return ConnectResult::failed;
            if (!endpoints || endpoints->empty() || endpoints->size()>64)
                co_return ConnectClock::now()>=deadline ? ConnectResult::timeout : ConnectResult::retryable;
            for (auto const& endpoint:*endpoints) {
                if (!endpoint.port() || endpoint.address().is_unspecified()) continue;
                if (canceled_) co_return ConnectResult::failed;
                auto now=std::chrono::duration_cast<std::chrono::milliseconds>(ConnectClock::now().time_since_epoch()).count();
                auto end=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (now<0 || end<=now) co_return ConnectResult::timeout;
                auto handshake=physical_handshake(profile_,static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(end),seconds,endpoint);
                if (!handshake) co_return ConnectResult::failed;
                owner_=std::make_unique<OwnedClient>(context_,std::move(*handshake));
                auto* interfaces=options_.binding.network ? &options_ : nullptr;
                if (!interfaces && options_.configured()) {
                    auto* socket=owner_->unconnected_socket();
                    if (!socket || net::prepare_tcp_socket(*socket,endpoint,options_,deadline)) co_return ConnectResult::failed;
                }
                auto connected=co_await owner_->start(endpoint,interfaces);
                if (canceled_) co_return ConnectResult::failed;
                if (connected) {
                    if constexpr (requires {resolver_.connected(endpoint);}) resolver_.connected(endpoint);
                    guard.done=true;
                    co_return ConnectResult::connected;
                }
                if (connected.error()==AsyncHandshakeError::socket_policy) co_return ConnectResult::failed;
                auto timeout=connected.error()==AsyncHandshakeError::timeout || ConnectClock::now()>=deadline;
                owner_.reset();
                if (timeout) co_return ConnectResult::timeout;
            }
            co_return ConnectResult::retryable;
        }
    };
    // The TLS ClientHello is the first write on the delayed physical stream.
    // FastOpenStream retries only candidates on which no bytes were accepted;
    // after any TLS failure the caller must not replay the handshake elsewhere.
    template<class Resolver,class Profile>
    class FastOpenPhysicalConnector {
        nex::corosio::io_context& context_;
        Resolver resolver_;
        Profile const& profile_;
        platform::TcpSocketOptions const& options_;
        std::unique_ptr<net::FastOpenStream> lower_;
    public:
        using Socket=net::ByteStreamAdapter<net::FastOpenStream>;
    private:
        std::unique_ptr<Socket> socket_;
        std::unique_ptr<ClientConnection<Socket>> owner_;
        bool starting_=false,canceled_=false;
    public:
        FastOpenPhysicalConnector(nex::corosio::io_context& context,Resolver resolver,Profile const& profile,
            platform::TcpSocketOptions const& options)
            :context_(context),resolver_(std::move(resolver)),profile_(profile),options_(options) {}
        FastOpenPhysicalConnector(FastOpenPhysicalConnector const&)=delete;
        auto operator=(FastOpenPhysicalConnector const&) -> FastOpenPhysicalConnector& = delete;
        auto cancel() noexcept -> void { canceled_=true;resolver_.cancel();if(owner_)owner_->cancel();if(lower_)lower_->cancel(); }
        auto client() noexcept -> ClientConnection<Socket>* { return owner_.get(); }
        auto socket() noexcept -> Socket* { return owner_ && owner_->application() ? socket_.get() : nullptr; }
        auto application() noexcept -> ApplicationConnection<Socket>* { return owner_ ? owner_->application() : nullptr; }
        auto negotiated() const noexcept -> EncryptedExtensions const* { return owner_ ? owner_->negotiated() : nullptr; }
        auto start(ConnectClock::time_point deadline) -> nex::capy::task<ConnectResult> {
            if(starting_ || owner_ || canceled_)co_return ConnectResult::failed;
            if(ConnectClock::now()>=deadline)co_return ConnectResult::timeout;
            starting_=true;
            struct Guard {FastOpenPhysicalConnector& owner;bool done=false;~Guard(){owner.starting_=false;if(!done)owner.cancel();}} guard{*this};
            auto endpoints=co_await resolver_(deadline);
            if(canceled_)co_return ConnectResult::failed;
            if(!endpoints || endpoints->empty() || endpoints->size()>64)
                co_return ConnectClock::now()>=deadline ? ConnectResult::timeout : ConnectResult::retryable;
            auto now=std::chrono::duration_cast<std::chrono::milliseconds>(ConnectClock::now().time_since_epoch()).count();
            auto end=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
            auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            if(now<0 || end<=now)co_return ConnectResult::timeout;
            auto handshake=profile_.handshake(static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(end),seconds);
            if(!handshake)co_return ConnectResult::failed;
            lower_=std::make_unique<net::FastOpenStream>(context_,std::move(*endpoints),deadline,options_);
            socket_=std::make_unique<Socket>(*lower_);
            owner_=std::make_unique<ClientConnection<Socket>>(*socket_,std::move(*handshake));
            auto ready=co_await owner_->start();
            if(canceled_)co_return ConnectResult::failed;
            if(!ready)co_return ready.error()==AsyncHandshakeError::timeout || ConnectClock::now()>=deadline ?
                ConnectResult::timeout : ConnectResult::failed;
            if constexpr (requires {resolver_.connected(lower_->remote_endpoint());})
                resolver_.connected(lower_->remote_endpoint());
            guard.done=true;co_return ConnectResult::connected;
        }
    };
    // Lower provides a connected byte stream, node candidate state and retry.
    // Keeping it concrete preserves the existing layered TLS I/O adapter.
    template<class Lower,class Profile>
    class LayerConnector {
        Lower lower_;
        net::ByteStreamAdapter<Lower> socket_;
        Profile const& profile_;
        std::unique_ptr<ClientConnection<net::ByteStreamAdapter<Lower>>> owner_;
        bool starting_=false,canceled_=false;
    public:
        using Socket=net::ByteStreamAdapter<Lower>;
        template<class... Args>
        LayerConnector(Profile const& profile,Args&&... args)
            : lower_(std::forward<Args>(args)...),socket_(lower_),profile_(profile) {}
        LayerConnector(LayerConnector const&)=delete;
        auto operator=(LayerConnector const&) -> LayerConnector& = delete;
        auto cancel() noexcept -> void { canceled_=true; if (owner_) owner_->cancel(); lower_.cancel(); }
        auto application() noexcept -> ApplicationConnection<net::ByteStreamAdapter<Lower>>* { return owner_ ? owner_->application() : nullptr; }
        auto negotiated() const noexcept -> EncryptedExtensions const* {return owner_ ? owner_->negotiated() : nullptr;}
        auto start(ConnectClock::time_point deadline) -> nex::capy::task<ConnectResult> {
            if (starting_ || owner_ || canceled_) co_return ConnectResult::failed;
            if (ConnectClock::now()>=deadline) co_return ConnectResult::timeout;
            starting_=true;
            struct Guard { LayerConnector& owner; bool done=false; ~Guard() { owner.starting_=false; if (!done) owner.cancel(); } } guard{*this};
            typename Lower::Candidates candidates;
            for (;;) {
                auto connected=co_await lower_.connect(deadline,candidates);
                if (connected!=ConnectResult::connected || canceled_) co_return canceled_ ? ConnectResult::failed : connected;
                auto now=std::chrono::duration_cast<std::chrono::milliseconds>(ConnectClock::now().time_since_epoch()).count();
                auto end=std::chrono::duration_cast<std::chrono::milliseconds>(deadline.time_since_epoch()).count();
                auto seconds=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
                if (now<0 || end<=now) co_return ConnectResult::timeout;
                auto handshake=profile_.handshake(static_cast<std::uint64_t>(now),static_cast<std::uint64_t>(end),seconds);
                if (!handshake) co_return ConnectResult::failed;
                owner_=std::make_unique<ClientConnection<net::ByteStreamAdapter<Lower>>>(socket_,std::move(*handshake));
                auto ready=co_await owner_->start();
                if (canceled_) co_return ConnectResult::failed;
                if (ready) { guard.done=true; co_return ConnectResult::connected; }
                auto timeout=ready.error()==AsyncHandshakeError::timeout || ConnectClock::now()>=deadline;
                owner_.reset();
                if (timeout) co_return ConnectResult::timeout;
                if (!lower_.retry()) co_return ConnectResult::failed;
            }
        }
    };
}
