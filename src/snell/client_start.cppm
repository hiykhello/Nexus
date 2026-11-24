export module snell.client_start;
import std;
import crypto;
import snell.record;
import snell.kdf;
import snell.cipher;
import snell.async_record;
import capy;
import corosio;
export namespace snell {
    struct ClientReply {Record<Cipher> reader;Bytes early;ClientReply(Record<Cipher> r,Bytes e):reader(std::move(r)),early(std::move(e)){}ClientReply(ClientReply&&)=default;auto operator=(ClientReply&&)->ClientReply& =default;};
    struct RemoteError {std::uint8_t code;std::string message;};
    using ReplyError=std::variant<IoError,RemoteError>;
    template<class Socket> auto client_start(Socket& socket,View psk,Request const& request,View early,Deadline deadline)
      ->capy::task<std::expected<Record<Cipher>,IoError>> {
        struct Guard{Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
        auto plain=encode_request(request);if(!plain)co_return std::unexpected(IoError::record);
        struct ErasePlain {Bytes& bytes;~ErasePlain(){crypto::cleanse(bytes);}} erase_plain{*plain};
        if(early.size()>max_payload-plain->size())co_return std::unexpected(IoError::record);
        if(!early.empty()){
            Bytes expanded;expanded.reserve(plain->size()+early.size());
            expanded.insert(expanded.end(),plain->begin(),plain->end());expanded.insert(expanded.end(),early.begin(),early.end());
            crypto::cleanse(*plain);*plain=std::move(expanded);
        }
        std::array<std::uint8_t,16> salt{};std::array<std::uint8_t,1> choice{};
        if(!crypto::random_bytes(salt)||!crypto::random_bytes(choice))co_return std::unexpected(IoError::record);
        auto key=Key::derive(psk,salt);if(!key)co_return std::unexpected(IoError::record);Record<Cipher> writer{Cipher(std::move(*key))};
        Bytes padding(256+choice[0]);if(!crypto::random_bytes(padding))co_return std::unexpected(IoError::record);
        auto frame=writer.encode(*plain,padding);if(!frame)co_return std::unexpected(IoError::record);Bytes wire(salt.begin(),salt.end());wire.insert(wire.end(),frame->begin(),frame->end());
        std::size_t offset=0;while(offset<wire.size()){
            if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
            auto op=socket.write_some(capy::const_buffer(wire.data()+offset,wire.size()-offset));auto [ec,n]=co_await corosio::timeout(std::move(op),deadline);
            if(capy::is_timeout(ec)||(!ec&&std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(IoError::timeout);
            if(ec||!n||n>wire.size()-offset)co_return std::unexpected(IoError::transport);offset+=n;
        }guard.done=true;co_return std::move(writer);
    }
    template<class Socket> auto client_reply(Socket& socket,View psk,Deadline deadline)->capy::task<std::expected<ClientReply,ReplyError>> {
        struct Guard{Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        auto read=[&](std::span<std::uint8_t> out)->capy::task<std::expected<void,IoError>> {
            std::size_t off=0;while(off<out.size()){
                if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
                auto op=socket.read_some(capy::mutable_buffer(out.data()+off,out.size()-off));auto [ec,n]=co_await corosio::timeout(std::move(op),deadline);
                if(capy::is_timeout(ec)||(!ec&&std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(IoError::timeout);
                if(capy::is_eof(ec)||(!ec&&!n))co_return std::unexpected(IoError::truncated);
                if(ec||n>out.size()-off)co_return std::unexpected(IoError::transport);off+=n;
            }co_return std::expected<void,IoError>{};
        };
        std::array<std::uint8_t,16> salt{};auto r=co_await read(salt);if(!r)co_return std::unexpected(ReplyError(r.error()));
        auto key=Key::derive(psk,salt);if(!key)co_return std::unexpected(ReplyError(IoError::record));Record<Cipher> reader{Cipher(std::move(*key))};
        std::array<std::uint8_t,header_size> h{};r=co_await read(h);if(!r)co_return std::unexpected(ReplyError(r.error()));auto n=reader.read_header(h);
        if(!n||!n->payload)co_return std::unexpected(ReplyError(IoError::record));Bytes body(std::size_t(n->padding)+n->payload+tag_size);
        r=co_await read(body);if(!r)co_return std::unexpected(ReplyError(r.error()));auto reply=reader.read_body(body);
        if(!reply||reply->empty())co_return std::unexpected(ReplyError(IoError::record));
        if((*reply)[0]==2){if(reply->size()<3 || reply->size()!=3+std::size_t((*reply)[2]))co_return std::unexpected(ReplyError(IoError::record));
            co_return std::unexpected(ReplyError(RemoteError{(*reply)[1],std::string(reply->begin()+3,reply->end())}));}
        if((*reply)[0]!=0)co_return std::unexpected(ReplyError(IoError::record));
        Bytes early(reply->begin()+1,reply->end());guard.done=true;co_return ClientReply(std::move(reader),std::move(early));
    }
}
