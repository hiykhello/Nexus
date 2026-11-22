export module platform.resolved_codec;
import std;
import platform.sd_bus_abi;
import platform.netlink_abi;
import platform.resolved_bus;
import platform.resolved_types;

export namespace platform::resolved::codec {
    namespace a=::platform::sd_bus_abi;
    template<std::size_t Size> inline auto text(char const* source,std::array<char,Size>& destination) noexcept -> bool {
        if(!source)return false;std::size_t length=0;
        while(length<Size && source[length])++length;
        if(length>=Size)return false;
        destination.fill(0);std::copy_n(source,length,destination.begin());return true;
    }
    inline auto entered(a::sd_bus_message* message,char type,char const* signature) noexcept -> bool {return a::sd_bus_message_enter_container(message,type,signature)>0;}
    inline auto exited(a::sd_bus_message* message) noexcept -> bool {return a::sd_bus_message_exit_container(message)>=0;}
    inline auto servers(a::sd_bus_message* message,Snapshot& output) noexcept -> std::expected<void,Failure> {
        if(!entered(message,'v',"a(iayqs)") || !entered(message,'a',"(iayqs)"))return fail(Error::protocol);
        for(;;) {
            auto next=a::sd_bus_message_enter_container(message,'r',"iayqs");if(next<0)return fail(Error::protocol,next);if(!next)break;
            if(output.server_count==output.servers.size())return fail(Error::capacity);
            Server item;int family=0;void const* data=nullptr;std::size_t size=0;char const* name=nullptr;
            if(a::sd_bus_message_read(message,"i",&family)<=0 || a::sd_bus_message_read_array(message,'y',&data,&size)<0 || a::sd_bus_message_read(message,"qs",&item.port,&name)<=0)return fail(Error::protocol);
            item.family=family==netlink_abi::AF_INET ? 4 : family==netlink_abi::AF_INET6 ? 6 : 0;
            if(!item.family || size!=(item.family==4 ? 4u : 16u) || !data || !text(name,item.name))return fail(Error::protocol);
            std::memcpy(item.address.data(),data,size);output.servers[output.server_count++]=item;
            if(!exited(message))return fail(Error::protocol);
        }
        if(!exited(message) || !exited(message))return fail(Error::protocol);return {};
    }
    inline auto domains(a::sd_bus_message* message,Snapshot& output) noexcept -> std::expected<void,Failure> {
        if(!entered(message,'v',"a(sb)") || !entered(message,'a',"(sb)"))return fail(Error::protocol);
        for(;;) {
            auto next=a::sd_bus_message_enter_container(message,'r',"sb");if(next<0)return fail(Error::protocol,next);if(!next)break;
            if(output.domain_count==output.domains.size())return fail(Error::capacity);
            Domain item;char const* name=nullptr;int only=0;
            if(a::sd_bus_message_read(message,"sb",&name,&only)<=0 || !text(name,item.name) || !item.name.front() || (only!=0 && only!=1))return fail(Error::protocol);
            item.route_only=only;output.domains[output.domain_count++]=item;
            if(!exited(message))return fail(Error::protocol);
        }
        if(!exited(message) || !exited(message))return fail(Error::protocol);return {};
    }
    inline auto snapshot(a::sd_bus_message* message) noexcept -> std::expected<Snapshot,Failure> {
        Snapshot output;bool dns=false,domain=false;
        if(!entered(message,'a',"{sv}"))return fail(Error::protocol);
        for(;;) {
            auto next=a::sd_bus_message_enter_container(message,'e',"sv");if(next<0)return fail(Error::protocol,next);if(!next)break;
            char const* name=nullptr;if(a::sd_bus_message_read(message,"s",&name)<=0 || !name)return fail(Error::protocol);
            auto property=std::string_view(name);
            if(property=="DNSEx") {if(dns)return fail(Error::protocol);dns=true;auto result=servers(message,output);if(!result)return std::unexpected(result.error());}
            else if(property=="Domains") {if(domain)return fail(Error::protocol);domain=true;auto result=domains(message,output);if(!result)return std::unexpected(result.error());}
            else if(a::sd_bus_message_skip(message,"v")<0)return fail(Error::protocol);
            if(!exited(message))return fail(Error::protocol);
        }
        if(!exited(message) || !dns || !domain || a::sd_bus_message_at_end(message,1)<=0)return fail(Error::protocol);return output;
    }
    // Check the complete manager domain stream without storing unrelated links.
    // Bound work independently of message size, retaining no borrowed strings.
    inline auto competing_domains(a::sd_bus_message* message,int ours) noexcept -> std::expected<bool,Failure> {
        if(!entered(message,'v',"a(isb)") || !entered(message,'a',"(isb)"))return fail(Error::protocol);
        bool conflict=false;unsigned records=0;
        for(;;) {
            auto next=a::sd_bus_message_enter_container(message,'r',"isb");if(next<0)return fail(Error::protocol,next);if(!next)break;
            if(++records>1024)return fail(Error::capacity);
            int index=0,only=0;char const* name=nullptr;
            if(a::sd_bus_message_read(message,"isb",&index,&name,&only)<=0 || !name || !*name || (only!=0 && only!=1))return fail(Error::protocol);
            if(index!=ours)conflict=true;
            if(!exited(message))return fail(Error::protocol);
        }
        if(!exited(message) || !exited(message) || a::sd_bus_message_at_end(message,1)<=0)return fail(Error::protocol);return conflict;
    }
    inline auto append_servers(a::sd_bus_message* message,Snapshot const& desired) noexcept -> std::expected<void,Failure> {
        if(desired.server_count>desired.servers.size())return fail(Error::capacity);
        for(std::size_t i=0;i<desired.server_count;++i) {
            auto const& item=desired.servers[i];
            if((item.family!=4 && item.family!=6) || std::ranges::find(item.name,'\0')==item.name.end() || (item.family==4 && std::ranges::any_of(std::span(item.address).subspan(4),[](auto byte){return byte!=0;})))return fail(Error::protocol);
        }
        auto result=a::sd_bus_message_open_container(message,'a',"(iayqs)");
        for(std::size_t i=0;result>=0 && i<desired.server_count;++i) {
            auto const& item=desired.servers[i];int family=item.family==4 ? netlink_abi::AF_INET : netlink_abi::AF_INET6;
            result=a::sd_bus_message_open_container(message,'r',"iayqs");
            if(result>=0)result=a::sd_bus_message_append(message,"i",family);
            if(result>=0)result=a::sd_bus_message_append_array(message,'y',item.address.data(),item.family==4 ? 4 : 16);
            if(result>=0)result=a::sd_bus_message_append(message,"qs",static_cast<unsigned>(item.port),item.name.data());
            if(result>=0)result=a::sd_bus_message_close_container(message);
        }
        if(result>=0)result=a::sd_bus_message_close_container(message);
        if(result<0)return fail(Error::native,result);return {};
    }
    inline auto append_domains(a::sd_bus_message* message,Snapshot const& desired) noexcept -> std::expected<void,Failure> {
        if(desired.domain_count>desired.domains.size())return fail(Error::capacity);
        for(std::size_t i=0;i<desired.domain_count;++i)if(!desired.domains[i].name.front() || std::ranges::find(desired.domains[i].name,'\0')==desired.domains[i].name.end())return fail(Error::protocol);
        auto result=a::sd_bus_message_open_container(message,'a',"(sb)");
        for(std::size_t i=0;result>=0 && i<desired.domain_count;++i) {
            auto const& item=desired.domains[i];result=a::sd_bus_message_open_container(message,'r',"sb");
            if(result>=0)result=a::sd_bus_message_append(message,"sb",item.name.data(),static_cast<int>(item.route_only));
            if(result>=0)result=a::sd_bus_message_close_container(message);
        }
        if(result>=0)result=a::sd_bus_message_close_container(message);
        if(result<0)return fail(Error::native,result);return {};
    }
}
