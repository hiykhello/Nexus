export module snell.server_stream;
import std;
import snell.record;
import snell.cipher;
import snell.async_record;
import nexus.thirdparty.capy;
export namespace snell {
    // One executor; a reader and writer may run concurrently. The caller
    // cancels and drains both before destroying this borrowed socket owner.
    template<class Socket> class ServerStream {
        Socket& socket_;Record<Cipher> reader_,writer_;Bytes cache_;std::size_t offset_=0;
        nex::capy::async_mutex write_lock_;bool active_=true,reading_=false,input_eof_=false,output_eof_=false;
    public:
        ServerStream(Socket& socket,Record<Cipher> reader,Record<Cipher> writer,Bytes early)
            :socket_(socket),reader_(std::move(reader)),writer_(std::move(writer)),cache_(std::move(early)){}
        ServerStream(ServerStream const&)=delete;auto operator=(ServerStream const&)->ServerStream& =delete;
        auto cancel() noexcept ->void {if(active_){active_=false;socket_.cancel();}}
        [[nodiscard]] auto finish() ->std::optional<std::pair<Record<Cipher>,Record<Cipher>>> {
            if(!active_||reading_||!input_eof_||!output_eof_||offset_!=cache_.size())return {};
            if(!reader_.resume()||!writer_.resume())return {};active_=false;
            return std::pair<Record<Cipher>,Record<Cipher>>(std::move(reader_),std::move(writer_));
        }
        auto send(View bytes,Deadline deadline)->nex::capy::task<bool> {
            auto [ec,lock]=co_await write_lock_.scoped_lock();if(ec||!active_||output_eof_)co_return false;
            struct Guard{ServerStream& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{*this};
            while(!bytes.empty()){auto part=bytes.first(std::min(bytes.size(),max_payload));if(!co_await send_record(socket_,writer_,part,{},deadline))co_return false;bytes=bytes.subspan(part.size());}
            guard.done=true;co_return true;
        }
        auto close_output(Deadline deadline)->nex::capy::task<bool> {
            auto [ec,lock]=co_await write_lock_.scoped_lock();if(ec||!active_||output_eof_)co_return false;
            struct Guard{ServerStream& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{*this};
            if(!co_await send_record(socket_,writer_,{}, {},deadline))co_return false;output_eof_=true;guard.done=true;co_return true;
        }
        auto read(std::span<std::uint8_t> output,Deadline deadline)->nex::capy::task<std::expected<std::size_t,IoError>> {
            if(!active_||reading_||output.empty())co_return std::unexpected(IoError::state);
            reading_=true;struct Guard{ServerStream& s;bool done=false;~Guard(){s.reading_=false;if(!done)s.cancel();}} guard{*this};
            if(offset_==cache_.size()&&!input_eof_){auto next=co_await receive_record(socket_,reader_,deadline);if(!next)co_return std::unexpected(next.error());cache_=std::move(*next);offset_=0;if(cache_.empty())input_eof_=true;}
            if(input_eof_){guard.done=true;co_return 0;}
            auto n=std::min(output.size(),cache_.size()-offset_);std::ranges::copy(std::span(cache_).subspan(offset_,n),output.begin());offset_+=n;guard.done=true;co_return n;
        }
    };
}
