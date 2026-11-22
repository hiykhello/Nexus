export module snell.server_start;
import std;
import snell.record;
import crypto;
import snell.kdf;
import snell.cipher;
import snell.replay;
import snell.async_record;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace snell {
    enum class StartError { timeout,transport,truncated,crypto,authentication,request,unauthorized,replay,capacity };
    struct ServerStart {
        Request request;Bytes early;Record<Cipher> reader;
        ServerStart(Request r,Bytes e,Record<Cipher> cipher):request(std::move(r)),early(std::move(e)),reader(std::move(cipher)){}
        ServerStart(ServerStart&&)=default;auto operator=(ServerStart&&) -> ServerStart& =default;ServerStart(ServerStart const&)=delete;
    };
    // The credential, cache, socket and task inputs must outlive the operation.
    // One cache is shared for a credential epoch across all workers. Failed
    // authentication never inserts salt; authenticated duplicate claims race
    // atomically and at most one can release request/early application data.
    template<class Socket,std::size_t N,class Authenticate>
    auto server_start(Socket& socket,View psk,ReplayCache<N>& cache,std::chrono::steady_clock::duration replay_window,Deadline deadline,Authenticate authenticate)
      -> nex::capy::task<std::expected<ServerStart,StartError>> {
        struct Guard {Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        auto read=[&](std::span<std::uint8_t> out)->nex::capy::task<std::expected<void,StartError>> {
            std::size_t off=0;while(off<out.size()){
                if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(StartError::timeout);
                auto op=socket.read_some(nex::capy::mutable_buffer(out.data()+off,out.size()-off));
                auto [ec,n]=co_await nex::corosio::timeout(std::move(op),deadline);
                if(nex::capy::is_timeout(ec)||(!ec && std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(StartError::timeout);
                if(nex::capy::is_eof(ec)||(!ec && !n))co_return std::unexpected(StartError::truncated);
                if(ec || n>out.size()-off)co_return std::unexpected(StartError::transport);off+=n;
            }co_return std::expected<void,StartError>{};
        };
        std::array<std::uint8_t,16> salt{};auto r=co_await read(salt);if(!r)co_return std::unexpected(r.error());
        auto key=Key::derive(psk,salt);if(!key)co_return std::unexpected(StartError::crypto);
        Record<Cipher> reader{Cipher(std::move(*key))};std::array<std::uint8_t,header_size> head{};
        r=co_await read(head);if(!r)co_return std::unexpected(r.error());auto lengths=reader.read_header(head);
        if(!lengths)co_return std::unexpected(lengths.error()==Error::crypto_failure?StartError::crypto:StartError::authentication);
        if(!lengths->payload)co_return std::unexpected(StartError::request);
        Bytes body(std::size_t(lengths->padding)+lengths->payload+tag_size);r=co_await read(body);if(!r)co_return std::unexpected(r.error());
        auto plain=reader.read_body(body);if(!plain)co_return std::unexpected(plain.error()==Error::crypto_failure?StartError::crypto:StartError::authentication);
        struct ErasePlain {Bytes& bytes;~ErasePlain(){crypto::cleanse(bytes);}} erase_plain{*plain};
        auto parsed=parse_request(*plain);if(!parsed)co_return std::unexpected(StartError::request);
        struct EraseIdentity {Request& request;~EraseIdentity(){crypto::cleanse(request.client_id);}} erase_identity{parsed->request};
        if(!authenticate(parsed->request))co_return std::unexpected(StartError::unauthorized);
        auto result=cache.publish(salt,std::chrono::steady_clock::now(),replay_window);
        if(result==ReplayCache<N>::Result::replay)co_return std::unexpected(StartError::replay);
        if(result!=ReplayCache<N>::Result::accepted)co_return std::unexpected(StartError::capacity);
        Bytes early(plain->begin()+parsed->consumed,plain->end());crypto::cleanse(parsed->request.client_id);parsed->request.client_id.clear();guard.done=true;
        co_return ServerStart(std::move(parsed->request),std::move(early),std::move(reader));
    }
}
