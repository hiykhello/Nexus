export module tailscale.control_stream;
import std;
import tailscale.control;
import tailscale.control_http;
import net.socket_stream;
import net.buffered_input;
import net.framed_stream;
import tailscale.control_record_codec;
import crypto;
import nexus.thirdparty.capy;

export namespace tailscale::control_stream {
    namespace noise=control;
    namespace http=control_http;
    using Clock=std::chrono::steady_clock;
    enum class Error {state,timeout,transport,http,noise,early,truncated};
    struct Failure {Error error;std::optional<http::Error> http;std::optional<noise::Error> noise;};
    // Authenticated framing only. The early JSON remains caller-owned and must
    // be typed/validated before use. H2 must receive the returned initial
    // prefix before it reads any remaining plaintext from the same stream.
    struct Ready {
        std::optional<std::span<std::uint8_t const>> early;
        std::array<std::uint8_t,9> prefix{};
        std::uint8_t prefix_size=0;
        auto http2_prefix() const noexcept -> std::span<std::uint8_t const> {return std::span(prefix).first(prefix_size);}
    };
    namespace detail {
        inline auto input_failure(net::InputStatus status) noexcept -> Failure {
            return {status==net::InputStatus::timeout ? Error::timeout : status==net::InputStatus::eof ? Error::truncated : Error::transport};
        }
        // One concrete synchronous consumer. The record decoder owns the
        // existing window and nonce; this consumer only advances plaintext.
        struct EarlyConsumer {
            using Result=std::expected<Ready,Failure>;
            http::EarlyPrefaceDecoder decoder;
            std::optional<http::Error> error;
            EarlyConsumer(std::span<std::uint8_t> storage,Clock::time_point start,Clock::time_point deadline) : decoder(storage,start,deadline) {}
            auto feed(std::span<std::uint8_t const> plain) noexcept -> net::InputStep {
                auto result=decoder.feed(plain,Clock::now());error=result.error;
                return {result.consumed,0,error ? net::InputAction::fail : result.ready ? net::InputAction::complete : net::InputAction::more};
            }
            auto abort() noexcept -> void {decoder.close();}
            template<class FailureType>
            auto finish(net::InputStatus status,std::optional<FailureType> failure) -> Result {
                if (status!=net::InputStatus::ready || failure) {
                    if (error) return std::unexpected(Failure{*error==http::Error::timeout ? Error::timeout : Error::early,error});
                    if (failure && failure->codec) return std::unexpected(Failure{Error::noise,{},failure->codec});
                    if (failure && failure->error==net::RecordStreamError::timeout) return std::unexpected(Failure{Error::timeout});
                    if (failure && failure->error==net::RecordStreamError::truncated) return std::unexpected(Failure{Error::truncated});
                    return std::unexpected(input_failure(status));
                }
                Ready result;result.early=decoder.payload();auto prefix=decoder.prefix();
                if (prefix.size()>result.prefix.size()) return std::unexpected(Failure{Error::state});
                std::ranges::copy(prefix,result.prefix.begin());result.prefix_size=static_cast<std::uint8_t>(prefix.size());return result;
            }
        };
    }
    // Stable startup owner: local MachinePrivate and lower outlive this object.
    // TLS uses the same ByteStream throughout; the generic framed owner keeps
    // one window for HTTP, Noise continuation and all later application reads.
    template<class Lower>
    class Stream {
    public:
        using Frame=net::FramedByteStream<Lower,noise::RecordCodec>;
        using Window=typename Frame::Window;
    private:
        Lower& lower_;
        noise::MachinePrivate const& local_;
        noise::ControlPublic pin_;
        Frame frame_;
        std::optional<Failure> failure_;
        enum class State {initial,starting,ready,stopped} state_=State::initial;
        struct OperationGuard {Stream& owner;bool released=false;~OperationGuard() {if (!released) owner.cancel();}};
        struct HeaderState {
            using Result=std::expected<void,Failure>;
            Stream& owner;http::UpgradeResponseDecoder decoder;std::optional<http::Error> error;
            HeaderState(Stream& stream,Clock::time_point start,Clock::time_point deadline) : owner(stream),decoder(start,deadline) {}
            auto input() noexcept -> Window& {return owner.frame_.startup_input();}
            auto abort() noexcept -> void {decoder.close();owner.cancel();}
            auto feed(std::span<std::uint8_t> bytes) noexcept -> net::InputStep {
                auto result=decoder.feed(bytes,Clock::now());error=result.error;
                return {result.consumed,1,error ? net::InputAction::fail : result.ready ? net::InputAction::complete : net::InputAction::more};
            }
            auto finish(net::InputStatus status) noexcept -> Result {
                if (status==net::InputStatus::ready) return {};
                return std::unexpected(error ? Failure{*error==http::Error::timeout ? Error::timeout : Error::http,error} : detail::input_failure(status));
            }
        };
        struct NoiseState {
            using Result=std::expected<void,Failure>;
            Stream& owner;noise::ClientHandshake& handshake;std::optional<noise::Error> error;
            auto input() noexcept -> Window& {return owner.frame_.startup_input();}
            auto abort() noexcept -> void {handshake.cancel();owner.cancel();}
            auto feed(std::span<std::uint8_t> bytes) noexcept -> net::InputStep {
                if (bytes.size()<3) return {0,3};
                auto size=noise::response_size;
                if (bytes[0]==3) {
                    auto hint=(std::size_t(bytes[1])<<8)|bytes[2];
                    if (hint>noise::max_public_hint) {error=noise::Error::framing;return {0,0,net::InputAction::fail};}size=3+hint;
                }
                if (bytes.size()<size) return {0,size};
                auto result=handshake.finish(bytes.first(size),Clock::now());
                if (result) {auto keys=handshake.take_transport();result=keys ? owner.frame_.codec().install(std::move(*keys)) : std::unexpected(keys.error());}
                if (!result) error=result.error();return {size,0,error ? net::InputAction::fail : net::InputAction::complete};
            }
            auto finish(net::InputStatus status) noexcept -> Result {
                if (status==net::InputStatus::ready) return {};
                return std::unexpected(error ? Failure{*error==noise::Error::timeout ? Error::timeout : Error::noise,{},error} : detail::input_failure(status));
            }
        };
        auto fail(Failure failure) noexcept -> std::unexpected<Failure> {if (!failure_) failure_=failure;cancel();return std::unexpected(*failure_);}
    public:
        Stream(Lower& lower,noise::MachinePrivate const& local,noise::ControlPublic pin) noexcept : lower_(lower),local_(local),pin_(pin),frame_(lower) {}
        Stream(Stream const&)=delete;
        auto operator=(Stream const&) -> Stream& = delete;
        ~Stream() {cancel();}
        auto cancel() noexcept -> void {state_=State::stopped;frame_.cancel();}
        auto ready() const noexcept -> bool {return state_==State::ready;}
        auto failure() const noexcept -> std::optional<Failure> {return failure_;}
        auto record_failure() const noexcept {return frame_.failure();}
        auto transport() noexcept -> Frame* {return ready() ? &frame_ : nullptr;}
        // One original absolute budget includes dial/TLS performed by caller.
        // No data-phase read/send forwarding coroutine is introduced here.
        auto start(std::string_view authority,std::span<std::uint8_t> early_storage,Clock::time_point started,Clock::time_point deadline)
            -> nex::capy::task<std::expected<Ready,Failure>> {
            if (state_!=State::initial) co_return std::unexpected(Failure{Error::state});
            state_=State::starting;OperationGuard guard{*this};
            if (deadline<=started || Clock::now()>=deadline) co_return fail({Error::timeout});
            noise::ClientHandshake handshake(local_,pin_,148,started,deadline);
            auto ephemeral=noise::EphemeralPrivate::generate();if (!ephemeral) co_return fail({Error::noise,{},noise::Error::backend});
            auto initial=handshake.start(std::move(*ephemeral),Clock::now());if (!initial) co_return fail({Error::noise,{},initial.error()});
            std::array<std::uint8_t,1024> request{};
            struct Erase {std::span<std::uint8_t> bytes;~Erase() {crypto::cleanse(bytes);}} erase{request};
            auto encoded=http::encode_upgrade_request(request,authority,*initial);if (!encoded) co_return fail({Error::http,encoded.error()});
            if (!co_await lower_.send(std::span(request).first(*encoded),deadline) || state_==State::stopped)
                co_return fail({Clock::now()>=deadline ? Error::timeout : Error::transport});
            auto header=co_await Window::drive(lower_,[&] {return HeaderState(*this,started,deadline);},deadline);
            if (!header) co_return fail(header.error());
            auto authenticated=co_await Window::drive(lower_,[&] {return NoiseState{*this,handshake};},deadline);
            if (!authenticated) co_return fail(authenticated.error());
            auto early=co_await frame_.drive_plain([&] {return detail::EarlyConsumer(early_storage,started,deadline);},deadline);
            if (!early) co_return fail(early.error());
            if (state_==State::stopped || Clock::now()>=deadline) co_return fail({Clock::now()>=deadline ? Error::timeout : Error::transport});
            state_=State::ready;guard.released=true;co_return std::move(*early);
        }
    };
}
