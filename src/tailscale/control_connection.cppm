export module tailscale.control_connection;
import std;
import tailscale.control;
import tailscale.control_stream;
import tailscale.control_early;
import tls.connector;
import tls.byte_stream;
import http2.client_channel;
import memory.budget;
import capy;

export namespace tailscale::control_connection {
    using Clock=std::chrono::steady_clock;
    enum class Error {state,limit,connect,timeout,startup,early,http2};
    struct Failure {
        Error error;
        std::optional<tls::detail::ConnectResult> connect;
        std::optional<control_stream::Failure> startup;
        std::optional<control_early::Error> early;
        std::optional<http2::ClientFailure> http2;
        std::optional<control::Error> noise;
    };
    // A direct static composition. Connector is the existing physical/layered
    // TLS connector; it and the immutable machine/profile/options outlive all
    // joined run/application tasks. Cancellation never destroys a parked task.
    template<class Connector,std::size_t Capacity=4>
    class Connection {
    public:
        using TlsStream=tls::detail::ByteStream<typename Connector::Socket>;
        using NoiseStream=control_stream::Stream<TlsStream>;
        using Frame=typename NoiseStream::Frame;
        using Channel=http2::ClientChannel<Frame,Capacity>;
    private:
        std::shared_ptr<memory::Budget> budget_;
        std::optional<memory::Budget::Reservation> transport_charge_;
        std::size_t extra_transport_bytes_;
        control::MachinePrivate const& machine_;
        control::ControlPublic pin_;
        Connector connector_;
        std::optional<TlsStream> tls_;
        std::optional<NoiseStream> noise_;
        std::optional<Channel> channel_;
        std::optional<control_early::Info> early_;
        std::optional<Failure> failure_;
        bool starting_=false;
        enum class State {initial,starting,ready,stopped} state_=State::initial;
        struct Guard {Connection& owner;bool released=false;~Guard() {owner.starting_=false;if (!released) owner.cancel();}};
        auto fail(Failure error) noexcept -> std::unexpected<Failure> {if (!failure_) failure_=error;cancel();return std::unexpected(*failure_);}
        static auto invalid_run() -> capy::task<capy::results<>> {co_return capy::results<>{std::make_error_code(std::errc::operation_not_permitted)};}
    public:
        // extra_transport_bytes is the caller's explicit admission for TLS
        // owners and task-frame overhead, in addition to this inline owner and
        // the driver's two 16KiB buffers. This logical budget is not full RSS.
        template<class... Args>
        Connection(control::MachinePrivate const& machine,control::ControlPublic pin,std::shared_ptr<memory::Budget> budget,
            std::size_t extra_transport_bytes,Args&&... args)
            : budget_(std::move(budget)),extra_transport_bytes_(extra_transport_bytes),machine_(machine),pin_(pin),connector_(std::forward<Args>(args)...) {}
        Connection(Connection const&)=delete;
        auto operator=(Connection const&) -> Connection& = delete;
        ~Connection() {cancel();}
        static constexpr auto minimum_transport_bytes() noexcept -> std::size_t {return sizeof(Connection)+Channel::transport_buffer_bytes;}
        auto transport_reserved() const noexcept -> std::size_t {return transport_charge_ ? transport_charge_->size() : 0;}
        auto early_info() const noexcept -> std::optional<control_early::Info> {return early_;}
        auto channel() noexcept -> Channel* {return state_==State::ready && channel_ ? &*channel_ : nullptr;}
        auto drained() const noexcept -> bool {return !starting_ && (!channel_ || channel_->drained());}
        auto failure() const noexcept -> std::optional<Failure> {
            if (failure_) return failure_;
            if (channel_) if (auto failure=channel_->failure()) {
                Failure result{Error::http2};result.http2=failure;
                if (noise_) if (auto record=noise_->record_failure()) result.noise=record->codec;
                return result;
            }
            return {};
        }
        auto cancel() noexcept -> void {
            state_=State::stopped;
            if (channel_) channel_->cancel(); // End native provider borrowing first.
            if (noise_) noise_->cancel();
            if (tls_) tls_->cancel();
            connector_.cancel();
        }
        // run returns the one shared H2 driver task directly. The application
        // joins it with register/Map consumers, then cancels and drains before
        // any body lease, lower stream or this owner is destroyed.
        auto run() -> capy::task<capy::results<>> {if (!channel_ || state_!=State::ready) return invalid_run();return channel_->run();}
        auto start(std::string_view authority,std::span<std::uint8_t> early_storage,Clock::time_point deadline,
                   http2::ClientLimits limits={},bool long_lived=false)
            -> capy::task<std::expected<void,Failure>> {
            if (state_!=State::initial) co_return std::unexpected(Failure{Error::state});
            state_=State::starting;starting_=true;Guard guard{*this};auto started=Clock::now();
            if (started>=deadline) co_return fail({Error::timeout});
            if (!budget_ || limits.shared_bytes!=budget_->limit() || extra_transport_bytes_>std::numeric_limits<std::size_t>::max()-minimum_transport_bytes())
                co_return fail({Error::limit});
            transport_charge_=memory::Budget::reserve(budget_,minimum_transport_bytes()+extra_transport_bytes_);
            if (!transport_charge_) co_return fail({Error::limit});
            auto connected=co_await connector_.start(deadline);
            if (state_==State::stopped) co_return fail({Error::connect,connected});
            if (connected!=tls::detail::ConnectResult::connected)
                co_return fail({connected==tls::detail::ConnectResult::timeout ? Error::timeout : Error::connect,connected});
            auto application=connector_.application();if (!application) co_return fail({Error::state});
            tls_.emplace(*application);noise_.emplace(*tls_,machine_,pin_);
            auto ready=co_await noise_->start(authority,early_storage,started,deadline);
            if (!ready) {Failure error{ready.error().error==control_stream::Error::timeout ? Error::timeout : Error::startup};error.startup=ready.error();co_return fail(error);}
            if (ready->early) {
                auto decoded=control_early::parse(*ready->early);
                if (!decoded) {Failure error{Error::early};error.early=decoded.error();co_return fail(error);}
                early_=*decoded;
            }
            auto client=http2::Client<Capacity>::create(limits,budget_);
            if (!client) {Failure error{Error::http2};error.http2=client.error();co_return fail(error);}
            auto prefix=ready->http2_prefix();
            if (!prefix.empty()) {
                auto accepted=(*client)->receive(prefix);
                if (!accepted || *accepted!=prefix.size()) {Failure error{Error::http2};error.http2=accepted ? http2::ClientFailure{http2::ClientError::http2} : accepted.error();co_return fail(error);}
            }
            if (state_==State::stopped || Clock::now()>=deadline) co_return fail({Clock::now()>=deadline ? Error::timeout : Error::connect});
            auto transport_deadline=long_lived ? http2::ChannelDeadline{} : http2::ChannelDeadline{deadline};
            channel_.emplace(*noise_->transport(),std::move(*client),transport_deadline);state_=State::ready;guard.released=true;
            co_return std::expected<void,Failure>{};
        }
    };
}
