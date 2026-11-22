export module platform.resolved_bus;
import std;
import platform.sd_bus_abi;
import platform.netlink_abi;

export namespace platform::resolved {
    namespace a=sd_bus_abi;
    using Clock=std::chrono::steady_clock;
    enum class Error { state,native,remote,timeout,canceled,protocol,ownership,conflict,capacity };
    struct Failure { Error code; std::error_code system{}; bool submitted=false; };
    inline auto fail(Error code,int native=0,bool submitted=false) noexcept -> std::unexpected<Failure> {
        return std::unexpected(Failure{code,native ? std::error_code(native<0 ? -native : native,std::generic_category()) : std::error_code{},submitted});
    }
    struct NoHooks { static constexpr auto canceled() noexcept -> bool {return false;} };
    class Message {
        a::sd_bus_message* value_=nullptr;
      public:
        explicit inline Message(a::sd_bus_message* value=nullptr) noexcept:value_(value){}
        inline ~Message(){if(value_)a::sd_bus_message_unref(value_);}
        Message(Message const&)=delete;
        auto operator=(Message const&) -> Message& = delete;
        inline Message(Message&& other) noexcept:value_(std::exchange(other.value_,nullptr)){}
        inline auto operator=(Message&& other) noexcept -> Message& {
            if(this!=&other){if(value_)a::sd_bus_message_unref(value_);value_=std::exchange(other.value_,nullptr);}return *this;
        }
        [[nodiscard]] inline auto get() const noexcept -> a::sd_bus_message* {return value_;}
    };
    class Slot {
        a::sd_bus_slot* value_=nullptr;
      public:
        Slot()=default;
        inline ~Slot(){reset();}
        Slot(Slot const&)=delete;
        auto operator=(Slot const&) -> Slot& = delete;
        inline auto reset() noexcept -> void {if(value_)value_=a::sd_bus_slot_unref(value_);}
        inline auto output() noexcept -> a::sd_bus_slot** {return &value_;}
    };
    template<class Hooks=NoHooks> class Bus {
        a::sd_bus* value_=nullptr;
        struct Pending {bool done=false;int error=0;a::sd_bus_message* reply=nullptr;};
        static auto replied(a::sd_bus_message* message,void* userdata,a::sd_bus_error*) noexcept -> int {
            auto& pending=*static_cast<Pending*>(userdata);
            pending.error=a::sd_bus_message_get_errno(message);
            pending.reply=a::sd_bus_message_ref(message);pending.done=true;return 1;
        }
      public:
        Bus()=default;
        ~Bus(){close();}
        Bus(Bus const&)=delete;
        auto operator=(Bus const&) -> Bus& = delete;
        Bus(Bus&&)=delete;
        auto operator=(Bus&&) -> Bus& = delete;
        template<bool ObserveCancellation=true> static auto budget(Clock::time_point deadline) noexcept -> std::expected<void,Failure> {
            static_assert(noexcept(Hooks::canceled()));
            if constexpr(ObserveCancellation)if(Hooks::canceled())return fail(Error::canceled);
            if(Clock::now()>=deadline)return fail(Error::timeout);
            return {};
        }
        auto close() noexcept -> void {
            if(value_){a::sd_bus_close(value_);value_=a::sd_bus_unref(value_);}
        }
        [[nodiscard]] auto native_handle() const noexcept -> int {return value_ ? a::sd_bus_get_fd(value_) : -1;}
        [[nodiscard]] auto open(Clock::time_point deadline,char const* address="unix:path=/run/dbus/system_bus_socket") -> std::expected<void,Failure> {
            if(value_)return fail(Error::state);
            auto checked=budget(deadline);if(!checked)return checked;
            auto result=a::sd_bus_new(&value_);
            if(result>=0)result=a::sd_bus_set_address(value_,address);
            if(result>=0)result=a::sd_bus_set_bus_client(value_,1);
            if(result>=0)result=a::sd_bus_set_exit_on_disconnect(value_,0);
            if(result>=0)result=a::sd_bus_start(value_);
            if(result<0){close();return fail(Error::native,result);}
            checked=budget(deadline);if(!checked)close();return checked;
        }
        [[nodiscard]] auto message(char const* destination,char const* path,char const* interface,char const* member) -> std::expected<Message,Failure> {
            if(!value_)return fail(Error::state);
            a::sd_bus_message* output=nullptr;
            auto result=a::sd_bus_message_new_method_call(value_,&output,destination,path,interface,member);
            Message guard(output);if(result<0)return fail(Error::native,result);return guard;
        }
        template<bool ObserveCancellation=true,class Done> [[nodiscard]] auto until(Done done,Clock::time_point deadline) -> std::expected<void,Failure> {
            if(!value_)return fail(Error::state);
            while(!done()) {
                auto checked=budget<ObserveCancellation>(deadline);if(!checked)return checked;
                auto processed=a::sd_bus_process(value_,nullptr);if(processed<0)return fail(Error::native,processed);
                if(done())return {};
                if(processed>0)continue;
                int fd=a::sd_bus_get_fd(value_),events=a::sd_bus_get_events(value_);
                if(fd<0 || events<0)return fail(Error::native,fd<0 ? fd : events);
                std::uint64_t bus_timeout=0;
                auto timed=a::sd_bus_get_timeout(value_,&bus_timeout);if(timed<0)return fail(Error::native,timed);
                auto until=deadline;
                if(bus_timeout!=std::numeric_limits<std::uint64_t>::max() && bus_timeout<=static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(Clock::time_point::max().time_since_epoch()).count()))
                    until=std::min(until,Clock::time_point(std::chrono::microseconds(bus_timeout)));
                auto now=Clock::now();auto milliseconds=until<=now ? 0 : std::min<std::int64_t>(10,std::chrono::ceil<std::chrono::milliseconds>(until-now).count());
                netlink_abi::pollfd poll{fd,static_cast<short>(events),0};
                auto result=netlink_abi::poll(&poll,1,static_cast<int>(milliseconds));
                if(result<0 && *netlink_abi::__errno_location()!=static_cast<int>(std::errc::interrupted))return fail(Error::native,*netlink_abi::__errno_location());
            }
            return {};
        }
        template<bool ObserveCancellation=true> [[nodiscard]] auto call(Message const& request,Clock::time_point deadline) -> std::expected<Message,Failure> {
            auto checked=budget<ObserveCancellation>(deadline);if(!checked)return std::unexpected(checked.error());
            if(!value_ || !request.get())return fail(Error::state);
            auto now=Clock::now();if(now>=deadline)return fail(Error::timeout);
            auto micros=std::chrono::ceil<std::chrono::microseconds>(deadline-now).count();
            Pending pending;Slot slot;
            auto queued=a::sd_bus_call_async(value_,slot.output(),request.get(),replied,&pending,static_cast<std::uint64_t>(micros));
            if(queued<0)return fail(Error::native,queued,true);
            auto completed=until<ObserveCancellation>([&]() noexcept{return pending.done;},deadline);
            // Cancellation removes the native callback before stack state dies.
            // The remote operation may already have committed; callers must
            // reconcile attempted mutations under their rollback budget.
            slot.reset();Message reply(pending.reply);
            if(!completed){auto error=completed.error();error.submitted=true;return std::unexpected(error);}
            if(pending.error)return fail(Error::remote,pending.error,true);
            if(!reply.get())return fail(Error::protocol,0,true);
            return reply;
        }
        [[nodiscard]] auto watch(char const* match,Slot& slot,a::sd_bus_message_handler_t callback,a::sd_bus_message_handler_t installed,void* userdata) -> std::expected<void,Failure> {
            if(!value_)return fail(Error::state);
            auto result=a::sd_bus_add_match_async(value_,slot.output(),match,callback,installed,userdata);
            if(result<0)return fail(Error::native,result);return {};
        }
        [[nodiscard]] auto process(Clock::time_point deadline) -> std::expected<bool,Failure> {
            auto checked=budget(deadline);if(!checked)return std::unexpected(checked.error());
            if(!value_)return fail(Error::state);
            for(unsigned count=0;count<64;++count){auto result=a::sd_bus_process(value_,nullptr);if(result<0)return fail(Error::native,result);if(!result)return false;}
            return true;
        }
    };
}
