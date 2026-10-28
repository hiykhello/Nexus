export module nexus.shadowsocks.corosio_client;
import std;
import nexus.crypto;
import nexus.shadowsocks.chunk;
import nexus.shadowsocks.request;
import nexus.shadowsocks.response;
import nexus.shadowsocks.frame;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace nexus::shadowsocks::detail {
    enum class StartError { invalid_input, random, timeout, transport, partial_write };
    struct StartedRequest { std::vector<std::uint8_t> salt; ChunkCipher cipher; };
    // One executor owns the socket. Input spans and the socket must live until completion.
    // Failure after submission cancels the socket; retain it until cancellation drains.
    template<class Socket>
    auto start_request(Socket& socket, std::span<std::uint8_t const> psk,
                       std::span<std::uint8_t const> address, std::chrono::steady_clock::time_point deadline)
        -> nex::capy::task<std::expected<StartedRequest,StartError>> {
        if (psk.size()!=16 && psk.size()!=32) co_return std::unexpected(StartError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(StartError::timeout);
        std::vector<std::uint8_t> salt(psk.size()); std::array<std::uint8_t,2> choice{};
        if (!crypto::random_bytes(salt) || !crypto::random_bytes(choice)) co_return std::unexpected(StartError::random);
        auto length=1+((static_cast<std::size_t>(choice[0])<<8|choice[1])%900);
        std::vector<std::uint8_t> padding(length);
        if (!crypto::random_bytes(padding)) co_return std::unexpected(StartError::random);
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (wall<0) co_return std::unexpected(StartError::invalid_input);
        auto request=encode_request(psk,salt,static_cast<std::uint64_t>(wall),address,padding,{});
        if (!request) co_return std::unexpected(StartError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(StartError::timeout);
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        auto operation=socket.write_some(nex::capy::const_buffer(request->wire.data(),request->wire.size()));
        auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
        if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline)) {
            co_return std::unexpected(StartError::timeout);
        }
        if (error) co_return std::unexpected(StartError::transport);
        if (n!=request->wire.size()) co_return std::unexpected(StartError::partial_write);
        guard.done=true;
        co_return StartedRequest{std::move(salt),std::move(request->cipher)};
    }
    enum class SendError { invalid_frame, timeout, transport };
    // Single writer; keep the socket, encoder and payload alive until completion.
    // Any error or exception closes the encoder and cancels the socket.
    template<class Socket>
    auto send_frame(Socket& socket, FrameEncoder& encoder, std::span<std::uint8_t const> payload,
                    std::chrono::steady_clock::time_point deadline) -> nex::capy::task<std::expected<void,SendError>> {
        struct Guard {
            Socket& socket; FrameEncoder& encoder; bool done=false;
            ~Guard() { if (!done) { encoder.close(); socket.cancel(); } }
        } guard{socket,encoder};
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(SendError::timeout);
        auto frame=encoder.encode(payload);
        if (!frame) co_return std::unexpected(SendError::invalid_frame);
        std::size_t offset=0;
        while (offset<frame->size()) {
            if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(SendError::timeout);
            auto operation=socket.write_some(nex::capy::const_buffer(frame->data()+offset,frame->size()-offset));
            auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
            if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
                co_return std::unexpected(SendError::timeout);
            if (error || !n || n>frame->size()-offset) co_return std::unexpected(SendError::transport);
            offset+=n;
        }
        guard.done=true; co_return std::expected<void,SendError>{};
    }

    enum class ReceiveError { invalid_input, timeout, transport, truncated, invalid_header, authentication };
    struct StartedResponse { ChunkCipher cipher; std::vector<std::uint8_t> payload, unread; };
    // Exactly one initial read; later reads collect the first payload without consuming extra data.
    // One reader owns the socket and all inputs remain alive until completion.
    template<class Socket>
    auto receive_response(Socket& socket, std::span<std::uint8_t const> psk,
                          std::span<std::uint8_t const> request_salt, std::chrono::steady_clock::time_point deadline)
        -> nex::capy::task<std::expected<StartedResponse,ReceiveError>> {
        struct Guard { Socket& socket; bool done=false; ~Guard() { if (!done) socket.cancel(); } } guard{socket};
        if ((psk.size()!=16 && psk.size()!=32) || request_salt.size()!=psk.size())
            co_return std::unexpected(ReceiveError::invalid_input);
        if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ReceiveError::timeout);
        std::vector<std::uint8_t> input(65536);
        auto operation=socket.read_some(nex::capy::mutable_buffer(input.data(),input.size()));
        auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
        if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
            co_return std::unexpected(ReceiveError::timeout);
        if (nex::capy::is_eof(error) || (!error && !n)) co_return std::unexpected(ReceiveError::truncated);
        if (error || n>input.size()) co_return std::unexpected(ReceiveError::transport);
        input.resize(n);
        auto wall=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (wall<0) co_return std::unexpected(ReceiveError::invalid_input);
        auto prefix=decode_response_prefix(psk,request_salt,input,static_cast<std::uint64_t>(wall));
        if (!prefix) co_return std::unexpected(prefix.error()==ResponseError::authentication ? ReceiveError::authentication : ReceiveError::invalid_header);
        auto start=prefix->consumed;
        auto end=start+prefix->payload_length+16;
        if (input.size()<end) {
            auto filled=input.size(); input.resize(end);
            while (filled<end) {
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ReceiveError::timeout);
                auto read=socket.read_some(nex::capy::mutable_buffer(input.data()+filled,end-filled));
                auto [read_error,count]=co_await nex::corosio::timeout(std::move(read),deadline);
                if (nex::capy::is_timeout(read_error) || (!read_error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(ReceiveError::timeout);
                if (nex::capy::is_eof(read_error) || (!read_error && !count)) co_return std::unexpected(ReceiveError::truncated);
                if (read_error || count>end-filled) co_return std::unexpected(ReceiveError::transport);
                filled+=count;
            }
        }
        auto decoded=decode_response_payload(std::move(*prefix),std::span{input}.subspan(start,end-start));
        if (!decoded) co_return std::unexpected(decoded.error()==ResponseError::authentication ? ReceiveError::authentication : ReceiveError::invalid_header);
        std::vector<std::uint8_t> unread(input.begin()+end,input.end());
        guard.done=true; co_return StartedResponse{std::move(decoded->cipher),std::move(decoded->payload),std::move(unread)};
    }

    enum class ReadError { state, timeout, transport, truncated, authentication };
    // Single reader on one executor. The socket and this object outlive any pending read.
    template<class Socket>
    class FrameReader {
        Socket& socket_;
        FrameDecoder decoder_;
        std::vector<std::uint8_t> input_, output_;
        std::size_t input_offset_=0, output_offset_=0;
        bool reading_=false, active_=true, eof_=false;
    public:
        FrameReader(Socket& socket, StartedResponse response)
            : socket_(socket),decoder_(std::move(response.cipher)),input_(std::move(response.unread)),output_(std::move(response.payload)) {}
        FrameReader(FrameReader const&)=delete;
        auto operator=(FrameReader const&) -> FrameReader& = delete;
        auto cancel() noexcept -> void { active_=false; socket_.cancel(); }
        // Returns zero only for clean EOF. Errors and exceptions cancel the socket.
        auto read(std::span<std::uint8_t> output, std::chrono::steady_clock::time_point deadline)
            -> nex::capy::task<std::expected<std::size_t,ReadError>> {
            if (!active_ || reading_ || output.empty()) co_return std::unexpected(ReadError::state);
            reading_=true;
            struct Guard { FrameReader& self; bool done=false; ~Guard() { self.reading_=false; if (!done) self.cancel(); } } guard{*this};
            for (;;) {
                if (!active_) co_return std::unexpected(ReadError::state);
                if (std::chrono::steady_clock::now()>=deadline) co_return std::unexpected(ReadError::timeout);
                if (output_offset_<output_.size()) {
                    auto n=std::min(output.size(),output_.size()-output_offset_);
                    std::ranges::copy(std::span{output_}.subspan(output_offset_,n),output.begin()); output_offset_+=n;
                    guard.done=true; co_return n;
                }
                if (eof_) { guard.done=true; co_return 0; }
                if (input_offset_<input_.size()) {
                    auto step=decoder_.feed(std::span{input_}.subspan(input_offset_));
                    if (!step) co_return std::unexpected(step.error()==FrameError::authentication ? ReadError::authentication : ReadError::transport);
                    input_offset_+=step->consumed;
                    if (step->payload) { output_=std::move(*step->payload); output_offset_=0; }
                    continue;
                }
                std::array<std::uint8_t,16384> bytes{};
                auto operation=socket_.read_some(nex::capy::mutable_buffer(bytes.data(),bytes.size()));
                auto [error,n]=co_await nex::corosio::timeout(std::move(operation),deadline);
                if (nex::capy::is_timeout(error) || (!error && std::chrono::steady_clock::now()>=deadline))
                    co_return std::unexpected(ReadError::timeout);
                if (!active_) co_return std::unexpected(ReadError::state);
                if (nex::capy::is_eof(error) || (!error && !n)) {
                    if (!decoder_.finish()) co_return std::unexpected(ReadError::truncated);
                    eof_=true; continue;
                }
                if (error || n>bytes.size()) co_return std::unexpected(ReadError::transport);
                input_.assign(bytes.begin(),bytes.begin()+n); input_offset_=0;
            }
        }
    };

}
