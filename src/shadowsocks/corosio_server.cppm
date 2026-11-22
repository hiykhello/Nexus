export module shadowsocks.corosio_server;
import std;
import crypto;
import shadowsocks.chunk;
import shadowsocks.header;
import shadowsocks.identity;
import shadowsocks.key;
import shadowsocks.request;
import shadowsocks.response;
import shadowsocks.replay;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace shadowsocks::detail {
    enum class ServerReadError { invalid_input, timeout, transport, truncated, invalid_request };
    struct TcpIdentityUser {
        std::span<std::uint8_t const> key;
        ReplayTable* replay;
        IdentityBlock hash;
    };
    struct AcceptedRequest {
        ChunkCipher cipher;
        std::vector<std::uint8_t> salt;
        RequestHeader header;
        std::vector<std::uint8_t> unread;
        std::optional<std::size_t> user{};
    };
    // Initial read is deliberately a single operation. All failures cancel the
    // socket; caller owns it until the canceled operations have drained.
    template<class Socket>
    auto receive_request(Socket& socket, std::span<std::uint8_t const> psk, ReplayTable* replay,
                         std::chrono::steady_clock::time_point deadline,std::span<TcpIdentityUser const> users,
                         CipherMethod method=CipherMethod::aes)
        -> nex::capy::task<std::expected<AcceptedRequest,ServerReadError>> {
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        if (psk.size()!=16 && psk.size()!=32) co_return std::unexpected(ServerReadError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerReadError::timeout);
        std::vector<std::uint8_t> input(65536);
        auto operation=socket.read_some(nex::capy::mutable_buffer(input.data(),input.size()));
        auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
        if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
            co_return std::unexpected(ServerReadError::timeout);
        if (nex::capy::is_eof(error) || (!error && !n)) co_return std::unexpected(ServerReadError::truncated);
        if (error || n>input.size()) co_return std::unexpected(ServerReadError::transport);
        input.resize(n);
        std::optional<std::size_t> user;
        if (!users.empty()) {
            if (input.size()<psk.size()+16) co_return std::unexpected(ServerReadError::invalid_request);
            auto input_bytes=std::span<std::uint8_t const>(input);
            auto hash=tcp_identity(psk,input_bytes.first(psk.size()),input_bytes.subspan(psk.size()).first<16>(),false);
            if (!hash) co_return std::unexpected(ServerReadError::invalid_request);
            for (std::size_t index=0;index<users.size();++index)
                if (crypto::constant_time_equal(*hash,users[index].hash)) user=index;
            if (!user) co_return std::unexpected(ServerReadError::invalid_request);
            psk=users[*user].key;
            replay=users[*user].replay;
        }
        if (!replay) co_return std::unexpected(ServerReadError::invalid_input);
        auto prefix=decode_request_prefix_current(psk,input,*replay,user.has_value(),method);
        if (!prefix) co_return std::unexpected(ServerReadError::invalid_request);
        auto start=prefix->consumed, end=start+prefix->header_length+16;
        if (input.size()<end) {
            auto filled=input.size(); input.resize(end);
            while (filled<end) {
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerReadError::timeout);
                auto read=socket.read_some(nex::capy::mutable_buffer(input.data()+filled,end-filled));
                auto [read_error,count]=co_await nex::corosio::timeout(std::move(read),deadline);
                if (nex::capy::is_timeout(read_error) || (!read_error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(ServerReadError::timeout);
                if (nex::capy::is_eof(read_error) || (!read_error && !count)) co_return std::unexpected(ServerReadError::truncated);
                if (read_error || count>end-filled) co_return std::unexpected(ServerReadError::transport);
                filled+=count;
            }
        }
        auto request=decode_request_header(std::move(*prefix),std::span{input}.subspan(start,end-start));
        if (!request) co_return std::unexpected(ServerReadError::invalid_request);
        std::vector<std::uint8_t> unread(input.begin()+end,input.end());
        guard.done=true;
        co_return AcceptedRequest{std::move(request->cipher),std::move(request->salt),std::move(request->header),std::move(unread),user};
    }
    template<class Socket>
    auto receive_request(Socket& socket,std::span<std::uint8_t const> psk,ReplayTable& replay,
                         std::chrono::steady_clock::time_point deadline) {
        return receive_request(socket,psk,&replay,deadline,{});
    }
    enum class ServerWriteError { invalid_input, random, timeout, transport, partial_write };
    // First payload must be nonempty and the response is submitted in one write.
    template<class Socket>
    auto send_response(Socket& socket,std::span<std::uint8_t const> psk,std::span<std::uint8_t const> request_salt,
                       std::span<std::uint8_t const> payload,std::chrono::steady_clock::time_point deadline,
                       CipherMethod method=CipherMethod::aes)
        -> nex::capy::task<std::expected<ChunkCipher,ServerWriteError>> {
        if ((psk.size()!=16 && psk.size()!=32) || request_salt.size()!=psk.size() || payload.empty() || payload.size()>65535)
            co_return std::unexpected(ServerWriteError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerWriteError::timeout);
        std::vector<std::uint8_t> salt(psk.size());
        if (!crypto::random_bytes(salt)) co_return std::unexpected(ServerWriteError::random);
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (wall<0) co_return std::unexpected(ServerWriteError::invalid_input);
        auto response=encode_response(psk,salt,request_salt,static_cast<std::uint64_t>(wall),payload,method);
        if (!response) co_return std::unexpected(ServerWriteError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ServerWriteError::timeout);
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        auto operation=socket.write_some(nex::capy::const_buffer(response->wire.data(),response->wire.size()));
        auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
        if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
            co_return std::unexpected(ServerWriteError::timeout);
        if (error) co_return std::unexpected(ServerWriteError::transport);
        if (n!=response->wire.size()) co_return std::unexpected(ServerWriteError::partial_write);
        guard.done=true; co_return std::move(response->cipher);
    }
}
