export module endpoint.process_signals;
import std;
import platform.netlink_abi;
import platform.netlink_socket;

export namespace endpoint::process {
    inline volatile std::sig_atomic_t requested_signal=0,wake_descriptor=-1;
    extern "C" inline auto endpoint_signal(int value) -> void {
        namespace a=platform::netlink_abi;
        auto saved=*a::__errno_location();requested_signal=value;
        int fd=wake_descriptor;
        if(fd>=0) {
            char byte=1;
            // The published descriptor is stable and nonblocking. EAGAIN
            // means a wake byte is already pending; the stop latch persists.
            while(a::write(fd,&byte,1)<0 && *a::__errno_location()==std::to_underlying(std::errc::interrupted)) {}
        }
        *a::__errno_location()=saved;
    }
    struct StopRequested {
        [[nodiscard]] auto operator()() const noexcept -> bool { return requested_signal!=0; }
    };
    struct NetlinkHooks : platform::netlink::NoHooks {
        [[nodiscard]] static auto cancelled() noexcept -> bool { return requested_signal!=0; }
    };
    class SignalMask {
        platform::netlink_abi::sigset_t previous_{};
        bool active_=false;
      public:
        SignalMask() noexcept {
            namespace a=platform::netlink_abi; a::sigset_t selected{};
            if (a::sigemptyset(&selected)) return;
            for (auto signal:{a::SIGINT,a::SIGTERM,a::SIGHUP}) if (a::sigaddset(&selected,signal)) return;
            active_=a::pthread_sigmask(a::SIG_BLOCK,&selected,&previous_)==0;
        }
        SignalMask(SignalMask const&)=delete;
        auto operator=(SignalMask const&) -> SignalMask& = delete;
        ~SignalMask() { if (active_) (void)platform::netlink_abi::pthread_sigmask(platform::netlink_abi::SIG_SETMASK,&previous_,nullptr); }
        [[nodiscard]] auto active() const noexcept -> bool { return active_; }
    };
    class WakeRegistration {
        bool active_=false;
      public:
        explicit WakeRegistration(int fd) noexcept {
            SignalMask mask;
            if(!mask.active() || fd<0 || fd>std::numeric_limits<std::sig_atomic_t>::max() || wake_descriptor>=0)return;
            wake_descriptor=fd;active_=true;
        }
        WakeRegistration(WakeRegistration const&)=delete;
        auto operator=(WakeRegistration const&) -> WakeRegistration& = delete;
        ~WakeRegistration() {
            SignalMask mask;
            // The caller detaches while its own SignalMask is still live.
            // Never publish a closing/reused descriptor to the handler.
            if(active_)wake_descriptor=-1;
        }
        [[nodiscard]] auto active() const noexcept -> bool{return active_;}
    };
    class Signals {
        using Handler=void(*)(int);
        std::array<Handler,3> previous_{};
        std::size_t installed_=0;
        static constexpr std::array<int,3> signals_{platform::netlink_abi::SIGINT,platform::netlink_abi::SIGTERM,platform::netlink_abi::SIGHUP};
      public:
        Signals()=default;
        Signals(Signals const&)=delete;
        auto operator=(Signals const&) -> Signals& = delete;
        ~Signals() { while (installed_) { --installed_; std::signal(signals_[installed_],previous_[installed_]); } }
        [[nodiscard]] auto install() noexcept -> bool {
            if (installed_) return false;
            requested_signal=0;
            for (auto value:signals_) {
                auto previous=std::signal(value,endpoint_signal);
                if (previous==reinterpret_cast<Handler>(static_cast<std::intptr_t>(platform::netlink_abi::SIGNAL_ERROR))) return false;
                previous_[installed_++]=previous;
            }
            return true;
        }
        [[nodiscard]] auto requested() const noexcept -> int { return requested_signal; }
        [[nodiscard]] auto restore_handlers() const noexcept -> bool {
            for (auto value:signals_) if (std::signal(value,endpoint_signal)==reinterpret_cast<Handler>(static_cast<std::intptr_t>(platform::netlink_abi::SIGNAL_ERROR))) return false;
            return true;
        }
        static auto received(int value) noexcept -> void { if (!requested_signal) requested_signal=value; }
    };
}
