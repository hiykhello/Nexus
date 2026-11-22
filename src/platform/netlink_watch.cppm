export module platform.netlink_watch;
import std;
import platform.netlink_abi;
import platform.netlink_codec;
import platform.socket_options;

export namespace platform::netlink {
    // Private multicast monitor. Kernel sender identity is separate from each
    // message header's originating port/sequence, used by ownership journals.
    class Watch {
        int fd_=-1;
        std::uint32_t port_=0,groups_=0;
        static auto error() noexcept -> std::error_code {return {*abi::__errno_location(),std::generic_category()};}
      public:
        Watch()=default;
        Watch(Watch const&)=delete;
        auto operator=(Watch const&) -> Watch& = delete;
        ~Watch(){close();}
        auto close() noexcept -> void {if(fd_>=0){abi::close(fd_);fd_=-1;}port_=groups_=0;}
        [[nodiscard]] auto native_handle() const noexcept -> int{return fd_;}
        [[nodiscard]] auto port_id() const noexcept -> std::uint32_t{return port_;}
        [[nodiscard]] auto open(std::span<int const> groups) noexcept -> std::expected<void,Failure> {
            if(fd_>=0 || groups.empty())return fail(Error::configuration);
            fd_=abi::socket(abi::AF_NETLINK,abi::SOCK_RAW|abi::SOCK_NONBLOCK|abi::SOCK_CLOEXEC,abi::NETLINK_ROUTE);
            if(fd_<0)return fail(Error::system,error());
            auto failure=[&](std::error_code code){close();return fail(Error::system,code);};
            abi::sockaddr_nl local{.nl_family=abi::AF_NETLINK};
            if(abi::bind(fd_,reinterpret_cast<abi::sockaddr const*>(&local),sizeof(local))<0)return failure(error());
            unsigned size=sizeof(local);
            if(abi::getsockname(fd_,reinterpret_cast<abi::sockaddr*>(&local),&size)<0)return failure(error());
            if(size!=sizeof(local)||local.nl_family!=abi::AF_NETLINK||!local.nl_pid||local.nl_groups){close();return fail(Error::protocol);}
            port_=local.nl_pid;
            for(auto group:groups) {
                if(group<1 || group>32){close();return fail(Error::configuration);}
                auto bit=std::uint32_t{1}<<(group-1);if(groups_&bit){close();return fail(Error::configuration);}
                if(auto code=socket_detail::set(fd_,abi::SOL_NETLINK,abi::NETLINK_ADD_MEMBERSHIP,group))return failure(code);
                groups_|=bit;
            }
            return {};
        }
        template<class Visitor> [[nodiscard]] auto drain(std::span<std::uint8_t> input,Visitor&& visitor,std::size_t budget=64) -> std::expected<std::size_t,Failure> {
            if(fd_<0)return fail(Error::closed);
            if(input.size()<65536 || !budget)return fail(Error::configuration);
            std::size_t count=0;
            while(count<budget) {
                abi::sockaddr_nl source{};unsigned size=sizeof(source);
                auto received=abi::recvfrom(fd_,input.data(),input.size(),abi::MSG_TRUNC,reinterpret_cast<abi::sockaddr*>(&source),&size);
                if(received<0) {
                    auto code=error();
                    if(code==std::errc::resource_unavailable_try_again || code==std::errc::operation_would_block)return count;
                    if(code==std::errc::interrupted)continue;
                    return fail(code==std::errc::no_buffer_space?Error::uncertain:Error::system,code);
                }
                if(!received || static_cast<std::size_t>(received)>input.size())return fail(Error::uncertain);
                if(size!=sizeof(source)||source.nl_family!=abi::AF_NETLINK||source.nl_pid||!source.nl_groups||(source.nl_groups&~groups_))return fail(Error::protocol);
                auto parsed=messages(input.first(received),[&](Message message) -> std::expected<void,Failure> {
                    if(++count>4096 || message.header.nlmsg_type==abi::NLMSG_OVERRUN)return fail(Error::uncertain);
                    return visitor(message);
                });
                if(!parsed)return std::unexpected(parsed.error());
            }
            return fail(Error::limit);
        }
    };
}
