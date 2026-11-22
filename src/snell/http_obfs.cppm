export module snell.http_obfs;
import std;
import nexus.thirdparty.capy;

export namespace snell {
    auto http_obfs_websocket_key() -> std::optional<std::string>;
    // Each connection has one reader and one writer. The socket, host and URI
    // outlive the adapter. After the camouflage envelope the Snell stream is raw.
    template<class Socket> class HttpObfs {
        Socket& socket_;
        std::string_view host_,uri_;
        std::unique_ptr<std::array<std::uint8_t,512>> buffer_;
        std::size_t begin_=0,end_=0,header_bytes_=0,matched_=0;
        bool enabled_,server_,read_ready_=false,write_ready_=false,failed_=false;

        auto fail(std::error_code error={}) noexcept -> std::error_code {
            failed_=true;socket_.cancel();return error ? error : std::make_error_code(std::errc::protocol_error);
        }
        auto prefix(std::size_t length) -> std::optional<std::string> {
            auto key=http_obfs_websocket_key();if(!key)return {};
            if(server_)return "HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "+*key+"\r\n\r\n";
            return "GET "+std::string(uri_)+" HTTP/1.1\r\nHost: "+std::string(host_)+"\r\nUser-Agent: Mozilla/5.0\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: "+std::to_string(length)+"\r\nSec-WebSocket-Key: "+*key+"\r\n\r\n";
        }
    public:
        HttpObfs(Socket& socket,bool enabled,bool server,std::string_view host={},std::string_view uri={})
            :socket_(socket),host_(host.empty()?"bing.com":host),uri_(uri.empty()?"/":uri),enabled_(enabled),server_(server){}
        HttpObfs(HttpObfs const&)=delete;
        auto cancel() noexcept -> void {failed_=true;socket_.cancel();}
        auto read_some(nex::capy::mutable_buffer out) -> nex::capy::task<nex::capy::results<std::size_t>> {
            if(failed_)co_return nex::capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
            if(!out.size())co_return nex::capy::results<std::size_t>{std::error_code{},0};
            struct Guard {HttpObfs& owner;bool done=false;~Guard(){if(!done)owner.cancel();}} guard{*this};
            while(enabled_&&!read_ready_){
                if(!buffer_)buffer_=std::make_unique<std::array<std::uint8_t,512>>();
                if(begin_==end_){
                    auto [error,n]=co_await socket_.read_some(nex::capy::mutable_buffer(buffer_->data(),buffer_->size()));
                    if(error||!n||n>buffer_->size())co_return nex::capy::results<std::size_t>{fail(error),0};begin_=0;end_=n;
                }
                constexpr std::string_view terminator="\r\n\r\n";
                while(begin_<end_&&!read_ready_){
                    auto value=(*buffer_)[begin_++];
                    if(++header_bytes_>16384)co_return nex::capy::results<std::size_t>{fail(),0};
                    if(value==terminator[matched_])++matched_;
                    else matched_=value=='\r'?1:0;
                    if(matched_==terminator.size())read_ready_=true;
                }
            }
            if(begin_<end_){auto count=std::min(out.size(),end_-begin_);std::memcpy(out.data(),buffer_->data()+begin_,count);begin_+=count;if(begin_==end_)buffer_.reset();guard.done=true;co_return nex::capy::results<std::size_t>{std::error_code{},count};}
            buffer_.reset();
            auto [error,count]=co_await socket_.read_some(out);
            if(error && !nex::capy::is_eof(error))co_return nex::capy::results<std::size_t>{fail(error),0};
            if(count>out.size())co_return nex::capy::results<std::size_t>{fail(),0};guard.done=true;co_return nex::capy::results<std::size_t>{error,count};
        }
        auto write_some(nex::capy::const_buffer input) -> nex::capy::task<nex::capy::results<std::size_t>> {
            if(failed_)co_return nex::capy::results<std::size_t>{std::make_error_code(std::errc::operation_canceled),0};
            if(!input.size())co_return nex::capy::results<std::size_t>{std::error_code{},0};
            struct Guard {HttpObfs& owner;bool done=false;~Guard(){if(!done)owner.cancel();}} guard{*this};
            if(enabled_&&!write_ready_){
                auto header=prefix(input.size());if(!header)co_return nex::capy::results<std::size_t>{fail(std::make_error_code(std::errc::io_error)),0};
                std::vector<std::uint8_t> first;first.reserve(header->size()+input.size());
                first.insert(first.end(),header->begin(),header->end());
                auto bytes=std::span(static_cast<std::uint8_t const*>(input.data()),input.size());first.insert(first.end(),bytes.begin(),bytes.end());
                std::size_t offset=0;
                while(offset<header->size()){
                    auto [error,count]=co_await socket_.write_some(nex::capy::const_buffer(first.data()+offset,first.size()-offset));
                    if(error||!count||count>first.size()-offset)co_return nex::capy::results<std::size_t>{fail(error),0};offset+=count;
                }
                write_ready_=true;
                if(offset>header->size()){guard.done=true;co_return nex::capy::results<std::size_t>{std::error_code{},offset-header->size()};}
            }
            auto [error,count]=co_await socket_.write_some(input);
            if(error||!count||count>input.size())co_return nex::capy::results<std::size_t>{fail(error),0};guard.done=true;co_return nex::capy::results<std::size_t>{std::error_code{},count};
        }
    };
}
