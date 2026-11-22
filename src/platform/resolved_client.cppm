export module platform.resolved_client;
import std;
import platform.sd_bus_abi;
import platform.resolved_bus;
import platform.resolved_types;
import platform.resolved_codec;

export namespace platform::resolved {
    template<class Hooks=NoHooks> class Client {
        Bus<Hooks> bus_;
        Slot owner_watch_,properties_watch_;
        std::array<char,64> owner_{};
        std::array<char,128> path_{};
        int index_=0,install_error_=0;
        unsigned installed_=0;
        bool revoked_=false,dirty_=false;
        static constexpr char manager[]="/org/freedesktop/resolve1",manager_interface[]="org.freedesktop.resolve1.Manager",link_interface[]="org.freedesktop.resolve1.Link";
        static auto installed(a::sd_bus_message* message,void* userdata,a::sd_bus_error*) noexcept -> int {
            auto& self=*static_cast<Client*>(userdata);++self.installed_;
            auto error=a::sd_bus_message_get_errno(message);if(error)self.install_error_=error;return 1;
        }
        static auto owner_changed(a::sd_bus_message* message,void* userdata,a::sd_bus_error*) noexcept -> int {
            auto& self=*static_cast<Client*>(userdata);char const *name=nullptr,*before=nullptr,*after=nullptr;
            if(a::sd_bus_message_read(message,"sss",&name,&before,&after)<=0 || !name || !before || !after){self.revoked_=true;return 1;}
            if(std::string_view(name)=="org.freedesktop.resolve1" && std::string_view(after)!=self.owner_.data())self.revoked_=true;
            return 1;
        }
        static auto changed(a::sd_bus_message*,void* userdata,a::sd_bus_error*) noexcept -> int {static_cast<Client*>(userdata)->dirty_=true;return 1;}
        template<bool ObserveCancellation=true> auto invoke(Message const& request,Clock::time_point deadline) -> std::expected<Message,Failure> {
            if(revoked_)return fail(Error::ownership);
            auto reply=bus_.template call<ObserveCancellation>(request,deadline);
            if(!reply)return std::unexpected(reply.error());
            auto sender=a::sd_bus_message_get_sender(reply->get());
            if(revoked_ || !sender || std::string_view(sender)!=owner_.data())return fail(Error::ownership,0,true);
            return std::move(*reply);
        }
        auto setting(char const* member) -> std::expected<Message,Failure> {
            if(!index_ || revoked_)return fail(revoked_ ? Error::ownership : Error::state);
            auto message=bus_.message(owner_.data(),manager,manager_interface,member);if(!message)return std::unexpected(message.error());
            auto appended=a::sd_bus_message_append(message->get(),"i",index_);if(appended<0)return fail(Error::native,appended);return std::move(*message);
        }
      public:
        Client()=default;
        ~Client(){close();}
        Client(Client const&)=delete;
        auto operator=(Client const&) -> Client& = delete;
        Client(Client&&)=delete;
        auto operator=(Client&&) -> Client& = delete;
        auto close() noexcept -> void {
            properties_watch_.reset();owner_watch_.reset();bus_.close();index_=0;owner_.fill(0);path_.fill(0);installed_=0;install_error_=0;revoked_=dirty_=false;
        }
        [[nodiscard]] auto native_handle() const noexcept -> int {return bus_.native_handle();}
        [[nodiscard]] auto revoked() const noexcept -> bool {return revoked_;}
        [[nodiscard]] auto dirty() const noexcept -> bool {return dirty_;}
        auto mark_clean() noexcept -> void {dirty_=false;}
        [[nodiscard]] auto open(int index,Clock::time_point deadline) -> std::expected<void,Failure> {
            if(index_ || index<=0)return fail(Error::state);index_=index;
            auto abort=[&](Failure error)->std::expected<void,Failure>{close();return std::unexpected(error);};
            auto connected=bus_.open(deadline);if(!connected)return abort(connected.error());
            {
                auto request=bus_.message("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner");if(!request)return abort(request.error());
                auto added=a::sd_bus_message_append(request->get(),"s","org.freedesktop.resolve1");if(added<0)return abort(Failure{Error::native,std::error_code(-added,std::generic_category())});
                auto reply=bus_.call(*request,deadline);if(!reply)return abort(reply.error());char const* owner=nullptr;
                if(a::sd_bus_message_read(reply->get(),"s",&owner)<=0 || !codec::text(owner,owner_) || owner_[0]!=':')return abort(Failure{Error::protocol});
            }
            if constexpr(requires{Hooks::before_owner_watch();}) {
                static_assert(noexcept(Hooks::before_owner_watch()));Hooks::before_owner_watch();
            }
            auto watched=bus_.watch("type='signal',sender='org.freedesktop.DBus',interface='org.freedesktop.DBus',member='NameOwnerChanged',arg0='org.freedesktop.resolve1'",owner_watch_,owner_changed,installed,this);
            if(!watched)return abort(watched.error());
            std::array<char,320> match{};std::size_t used=0;
            for(auto part:{std::string_view("type='signal',sender='"),std::string_view(owner_.data()),std::string_view("',path='/org/freedesktop/resolve1',interface='org.freedesktop.DBus.Properties',member='PropertiesChanged'")}){
                if(part.size()>=match.size()-used)return abort(Failure{Error::capacity});std::ranges::copy(part,match.begin()+used);used+=part.size();
            }
            watched=bus_.watch(match.data(),properties_watch_,changed,installed,this);if(!watched)return abort(watched.error());
            auto ready=bus_.until([&]() noexcept{return installed_==2 || install_error_ || revoked_;},deadline);
            if(!ready)return abort(ready.error());if(install_error_)return abort(Failure{Error::remote,std::error_code(install_error_,std::generic_category())});if(revoked_)return abort(Failure{Error::ownership});
            // Close the GetNameOwner -> installed-watch gap before sending
            // anything to the pinned unique name. A daemon can relinquish its
            // well-known name while its old process/unique name still lives.
            {
                auto request=bus_.message("org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus","GetNameOwner");if(!request)return abort(request.error());
                auto appended=a::sd_bus_message_append(request->get(),"s","org.freedesktop.resolve1");if(appended<0)return abort(Failure{Error::native,std::error_code(-appended,std::generic_category())});
                auto reply=bus_.call(*request,deadline);if(!reply)return abort(reply.error());char const* current=nullptr;
                if(a::sd_bus_message_read(reply->get(),"s",&current)<=0 || !current || std::string_view(current)!=owner_.data() || revoked_)return abort(Failure{Error::ownership});
            }
            for(;;) {
                auto request=setting("GetLink");if(!request)return abort(request.error());
                auto reply=invoke(*request,deadline);
                if(reply) {
                    char const* path=nullptr;
                    if(a::sd_bus_message_read(reply->get(),"o",&path)<=0 || !codec::text(path,path_) || !std::string_view(path_.data()).starts_with("/org/freedesktop/resolve1/link/"))return abort(Failure{Error::protocol});
                    return {};
                }
                auto error=reply.error();if(error.code!=Error::remote || (error.system!=std::errc::no_such_device_or_address && error.system!=std::errc::no_such_device))return abort(error);
                auto until=std::min(deadline,Clock::now()+std::chrono::milliseconds(5));auto waited=bus_.until([&]() noexcept{return Clock::now()>=until;},until);if(!waited)return abort(waited.error());
            }
        }
        template<bool ObserveCancellation=true> [[nodiscard]] auto snapshot(Clock::time_point deadline) -> std::expected<Snapshot,Failure> {
            if(!index_ || revoked_)return fail(revoked_ ? Error::ownership : Error::state);
            auto request=bus_.message(owner_.data(),path_.data(),"org.freedesktop.DBus.Properties","GetAll");if(!request)return std::unexpected(request.error());
            auto appended=a::sd_bus_message_append(request->get(),"s",link_interface);if(appended<0)return fail(Error::native,appended);
            auto reply=invoke<ObserveCancellation>(*request,deadline);if(!reply)return std::unexpected(reply.error());return codec::snapshot(reply->get());
        }
        template<bool ObserveCancellation=true> [[nodiscard]] auto competing_domains(Clock::time_point deadline) -> std::expected<bool,Failure> {
            if(!index_ || revoked_)return fail(revoked_ ? Error::ownership : Error::state);
            auto request=bus_.message(owner_.data(),manager,"org.freedesktop.DBus.Properties","Get");if(!request)return std::unexpected(request.error());
            auto appended=a::sd_bus_message_append(request->get(),"ss",manager_interface,"Domains");if(appended<0)return fail(Error::native,appended);
            auto reply=invoke<ObserveCancellation>(*request,deadline);if(!reply)return std::unexpected(reply.error());return codec::competing_domains(reply->get(),index_);
        }
        template<bool ObserveCancellation=true> [[nodiscard]] auto set_servers(Snapshot const& desired,Clock::time_point deadline) -> std::expected<void,Failure> {
            auto request=setting("SetLinkDNSEx");if(!request)return std::unexpected(request.error());auto appended=codec::append_servers(request->get(),desired);if(!appended)return appended;
            auto reply=invoke<ObserveCancellation>(*request,deadline);if(!reply)return std::unexpected(reply.error());return {};
        }
        template<bool ObserveCancellation=true> [[nodiscard]] auto set_domains(Snapshot const& desired,Clock::time_point deadline) -> std::expected<void,Failure> {
            auto request=setting("SetLinkDomains");if(!request)return std::unexpected(request.error());auto appended=codec::append_domains(request->get(),desired);if(!appended)return appended;
            auto reply=invoke<ObserveCancellation>(*request,deadline);if(!reply)return std::unexpected(reply.error());return {};
        }
        [[nodiscard]] auto process(Clock::time_point deadline) -> std::expected<bool,Failure> {return bus_.process(deadline);}
    };
}
