export module snell.async_record;
import std;
import snell.record;
import capy;
import corosio;
export namespace snell {
    enum class IoError { state,timeout,transport,truncated,record };
    using Deadline=std::chrono::steady_clock::time_point;
    // Single writer; a failure/abandonment cancels the borrowed transport.
    // The caller retains exclusive ownership of the record until completion.
    template<class Socket,class Cipher> auto send_record(Socket& socket,Record<Cipher>& writer,View payload,View padding,Deadline deadline)
      ->capy::task<std::expected<void,IoError>> {
        struct Guard{Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
        auto frame=writer.encode(payload,padding);if(!frame)co_return std::unexpected(IoError::record);std::size_t off=0;
        while(off<frame->size()){
            if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
            auto op=socket.write_some(capy::const_buffer(frame->data()+off,frame->size()-off));auto [ec,n]=co_await corosio::timeout(std::move(op),deadline);
            if(capy::is_timeout(ec)||(!ec && std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(IoError::timeout);
            if(ec||!n||n>frame->size()-off)co_return std::unexpected(IoError::transport);off+=n;
        }guard.done=true;co_return std::expected<void,IoError>{};
    }
    template<class Socket,class Cipher> auto receive_record(Socket& socket,Record<Cipher>& reader,Deadline deadline)
      ->capy::task<std::expected<Bytes,IoError>> {
        struct Guard{Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        auto read=[&](std::span<std::uint8_t> bytes)->capy::task<std::expected<void,IoError>> {
            std::size_t off=0;while(off<bytes.size()){
                if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
                auto op=socket.read_some(capy::mutable_buffer(bytes.data()+off,bytes.size()-off));auto [ec,n]=co_await corosio::timeout(std::move(op),deadline);
                if(capy::is_timeout(ec)||(!ec&&std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(IoError::timeout);
                if(capy::is_eof(ec)||(!ec&&!n))co_return std::unexpected(IoError::truncated);
                if(ec||n>bytes.size()-off)co_return std::unexpected(IoError::transport);off+=n;
            }co_return std::expected<void,IoError>{};
        };
        std::array<std::uint8_t,header_size> head{};auto r=co_await read(head);if(!r)co_return std::unexpected(r.error());
        auto n=reader.read_header(head);if(!n)co_return std::unexpected(IoError::record);
        if(!n->payload){guard.done=true;co_return Bytes{};}
        Bytes body(std::size_t(n->padding)+n->payload+tag_size);r=co_await read(body);if(!r)co_return std::unexpected(r.error());
        auto result=reader.read_body(body);if(!result)co_return std::unexpected(IoError::record);guard.done=true;co_return std::move(*result);
    }
    // One executor, one concurrent reader and writer. The borrowed transport
    // and this owner must outlive pending operations and cancellation drainage.
    template<class Socket,class Cipher> class AsyncRecord {
        Socket& socket_;Record<Cipher> reader_,writer_;bool active_=true,reading_=false,writing_=false,read_eof_=false,write_eof_=false;
    public:
        AsyncRecord(Socket& socket,Cipher read,Cipher write):socket_(socket),reader_(std::move(read)),writer_(std::move(write)){}
        AsyncRecord(Socket& socket,Record<Cipher> read,Record<Cipher> write):socket_(socket),reader_(std::move(read)),writer_(std::move(write)){}
        AsyncRecord(AsyncRecord const&)=delete;auto operator=(AsyncRecord const&) -> AsyncRecord& =delete;
        auto cancel() noexcept -> void {if(active_){active_=false;socket_.cancel();}}
        // Empty payload writes protocol EOF; padding must be caller-supplied random.
        auto send(View payload,View padding,Deadline deadline)->capy::task<std::expected<void,IoError>> {
            if(!active_ || writing_ || write_eof_)co_return std::unexpected(IoError::state);
            writing_=true;struct Guard{AsyncRecord& owner;bool done=false;~Guard(){owner.writing_=false;if(!done)owner.cancel();}} guard{*this};
            auto result=co_await send_record(socket_,writer_,payload,padding,deadline);if(!result)co_return std::unexpected(result.error());
            if(payload.empty())write_eof_=true;guard.done=true;co_return std::expected<void,IoError>{};
        }
        // Zero payload is clean EOF; transport EOF before a complete record is truncation.
        auto receive(Deadline deadline)->capy::task<std::expected<Bytes,IoError>> {
            if(!active_ || reading_ || read_eof_)co_return std::unexpected(IoError::state);
            reading_=true;struct Guard{AsyncRecord& owner;bool done=false;~Guard(){owner.reading_=false;if(!done)owner.cancel();}} guard{*this};
            auto result=co_await receive_record(socket_,reader_,deadline);if(!result)co_return std::unexpected(result.error());
            if(result->empty())read_eof_=true;
            guard.done=true;co_return std::move(*result);
        }
    };
}
