export module websocket.stream;
import std;
import websocket.handshake;
import httpupgrade;
import tls.byte_stream;
import tls.corosio_application;
import tls.application_io;
import crypto;
import capy;
import corosio;

export namespace websocket {
    using tls::detail::ApplicationDeadline;
    using tls::detail::ByteStreamError;
    using tls::detail::ReadTimeoutPolicy;

    namespace detail {
        struct Frame {
            unsigned opcode;
            std::uint64_t length;
            std::array<std::uint8_t,4> mask{};
            bool final;
        };

        inline auto close_payload_valid(std::span<std::uint8_t const> bytes) noexcept -> bool {
            if (bytes.empty()) return true;
            if (bytes.size()==1) return false;
            auto status=(unsigned(bytes[0])<<8)|bytes[1];
            if (!(status>=3000 && status<5000) &&
                (status<1000 || status>1014 || status==1004 || status==1005 || status==1006)) return false;
            bytes=bytes.subspan(2);
            while (!bytes.empty()) {
                auto initial=bytes.front();
                if (initial<0x80) {bytes=bytes.subspan(1);continue;}
                auto size=initial>=0xc2 && initial<0xe0 ? 2u :
                    initial>=0xe0 && initial<0xf0 ? 3u : initial>=0xf0 && initial<=0xf4 ? 4u : 0u;
                if (!size || size>bytes.size()) return false;
                auto tail=bytes.subspan(1,size-1);
                if ((initial==0xe0 && tail.front()<0xa0) || (initial==0xed && tail.front()>=0xa0) ||
                    (initial==0xf0 && tail.front()<0x90) || (initial==0xf4 && tail.front()>=0x90) ||
                    !std::ranges::all_of(tail,[](auto byte) {return (byte&0xc0)==0x80;})) return false;
                bytes=bytes.subspan(size);
            }
            return true;
        }

        template<class Lower>
        class BinaryFrames {
            using Result=std::expected<std::size_t,ByteStreamError>;
            Lower& lower_;
            capy::async_mutex writer_;
            bool client_;
            std::uint64_t remaining_=0,position_=0;
            std::array<std::uint8_t,4> mask_{};
            bool fragmented_=false,output_closed_=false,input_closed_=false,reading_=false;

            auto fail(ByteStreamError error) -> std::unexpected<ByteStreamError> {
                lower_.cancel();
                return std::unexpected(error);
            }

            auto exact(std::span<std::uint8_t> bytes,ApplicationDeadline deadline,ReadTimeoutPolicy policy)
                -> capy::task<Result> {
                std::size_t count=0;
                while (count<bytes.size()) {
                    auto received=co_await lower_.read(bytes.subspan(count),deadline,policy);
                    if (!received) {
                        if (!count) co_return std::unexpected(received.error());
                        co_return fail(received.error());
                    }
                    if (!*received) co_return fail(ByteStreamError::protocol);
                    count+=*received;
                }
                co_return count;
            }

            auto header(ApplicationDeadline deadline,ReadTimeoutPolicy policy)
                -> capy::task<std::expected<Frame,ByteStreamError>> {
                std::array<std::uint8_t,8> bytes;
                auto head=co_await exact(std::span(bytes).first(2),deadline,policy);
                if (!head) co_return std::unexpected(head.error());
                bool final=(bytes[0]&0x80)!=0;
                bool masked=(bytes[1]&0x80)!=0;
                unsigned opcode=bytes[0]&0x0f;
                std::uint64_t length=bytes[1]&0x7f;
                auto extension=length==126 ? 2u : length==127 ? 8u : 0u;
                if ((bytes[0]&0x70) || masked==client_ || (opcode>=8 && (!final || extension)))
                    co_return fail(ByteStreamError::protocol);
                if (extension) {
                    auto extended=co_await exact(std::span(bytes).first(extension),deadline,policy);
                    if (!extended) co_return fail(extended.error());
                    length=0;
                    for (auto byte:std::span(bytes).first(extension)) length=(length<<8)|byte;
                    if ((extension==2 && length<126) || (extension==8 && length<65536) || length>1024*1024)
                        co_return fail(ByteStreamError::protocol);
                }
                Frame result{opcode,length,{},final};
                if (masked) {
                    auto mask=co_await exact(result.mask,deadline,policy);
                    if (!mask) co_return fail(mask.error());
                }
                co_return result;
            }

            auto emit(unsigned opcode,std::span<std::uint8_t const> payload,ApplicationDeadline deadline)
                -> capy::task<bool> {
                // Callers hold the writer. The frame remains contiguous at
                // the lower stream even when writes or control replies yield.
                std::vector<std::uint8_t> wire;
                wire.reserve(8+payload.size());
                wire.push_back(static_cast<std::uint8_t>(0x80|opcode));
                auto masked=static_cast<std::uint8_t>(client_ ? 0x80 : 0);
                if (payload.size()<126) wire.push_back(static_cast<std::uint8_t>(masked|payload.size()));
                else {
                    wire.push_back(static_cast<std::uint8_t>(masked|126));
                    wire.push_back(static_cast<std::uint8_t>(payload.size()>>8));
                    wire.push_back(static_cast<std::uint8_t>(payload.size()));
                }
                std::array<std::uint8_t,4> mask{};
                if (client_) {
                    if (!crypto::random_bytes(mask)) {lower_.cancel();co_return false;}
                    wire.insert(wire.end(),mask.begin(),mask.end());
                }
                for (std::size_t index=0;index<payload.size();++index) wire.push_back(payload[index]^mask[index%4]);
                co_return co_await lower_.send(wire,deadline);
            }

            auto control(unsigned opcode,std::span<std::uint8_t const> payload,ApplicationDeadline deadline)
                -> capy::task<bool> {
                auto operation=writer_.scoped_lock();
                auto [error,lock]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) :
                    co_await std::move(operation);
                if (error) co_return false;
                if (output_closed_) co_return true;
                if (opcode==8) output_closed_=true;
                if (!co_await emit(opcode,payload,deadline)) co_return false;
                if (opcode==8) co_return co_await lower_.close_output(deadline);
                co_return true;
            }

        public:
            BinaryFrames(Lower& lower,bool client) :lower_(lower),client_(client) {}

            auto send(std::span<std::uint8_t const> data,ApplicationDeadline deadline) -> capy::task<bool> {
                auto operation=writer_.scoped_lock();
                auto [error,lock]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) :
                    co_await std::move(operation);
                if (error || output_closed_) co_return false;
                while (!data.empty()) {
                    auto size=std::min<std::size_t>(data.size(),16384);
                    if (!co_await emit(2,data.first(size),deadline)) co_return false;
                    data=data.subspan(size);
                }
                co_return true;
            }

            auto close_output(ApplicationDeadline deadline) -> capy::task<bool> {
                static constexpr std::array<std::uint8_t,2> normal{3,232};
                return control(8,normal,deadline);
            }

            auto read(std::span<std::uint8_t> output,ApplicationDeadline deadline,ReadTimeoutPolicy policy)
                -> capy::task<Result> {
                if (reading_) co_return std::unexpected(ByteStreamError::state);
                if (output.empty() || input_closed_) co_return 0;
                reading_=true;
                struct Reset {bool& reading;~Reset() {reading=false;}} reset{reading_};
                while (!remaining_) {
                    auto frame=co_await header(deadline,policy);
                    if (!frame) co_return std::unexpected(frame.error());
                    if (frame->opcode==0 || frame->opcode==2) {
                        if (fragmented_!=(frame->opcode==0)) co_return fail(ByteStreamError::protocol);
                        fragmented_=!frame->final;
                        remaining_=frame->length;
                        position_=0;
                        mask_=frame->mask;
                        continue;
                    }
                    if (frame->opcode<8 || frame->opcode>10) co_return fail(ByteStreamError::protocol);
                    std::array<std::uint8_t,125> buffer;
                    auto payload=std::span(buffer).first(frame->length);
                    if (!payload.empty()) {
                        auto read=co_await exact(payload,deadline,policy);
                        if (!read) co_return fail(read.error());
                        for (std::size_t index=0;index<payload.size();++index) payload[index]^=frame->mask[index%4];
                    }
                    auto ctrl_deadline=(policy==ReadTimeoutPolicy::preserve_connection && deadline)
                        ? ApplicationDeadline{std::max(*deadline,std::chrono::steady_clock::now()+std::chrono::seconds(5))}
                        : deadline;
                    if (frame->opcode==8) {
                        if (!close_payload_valid(payload)) co_return fail(ByteStreamError::protocol);
                        if (!co_await control(8,payload,ctrl_deadline)) co_return fail(ByteStreamError::io);
                        input_closed_=true;
                        co_return 0;
                    }
                    if (frame->opcode==9) {
                        auto answered=co_await control(10,payload,ctrl_deadline);
                        if (!answered) co_return fail(ByteStreamError::io);
                    }
                }
                auto read=co_await lower_.read(output.first(std::min<std::uint64_t>(remaining_,output.size())),deadline,policy);
                if (!read) co_return std::unexpected(read.error());
                if (!*read) co_return fail(ByteStreamError::protocol);
                for (std::size_t index=0;index<*read;++index) output[index]^=mask_[(position_+index)%4];
                position_+=*read;
                remaining_-=*read;
                co_return *read;
            }
        };
    }

    template<class Socket>
    class VlessByteStream {
        using Lower=tls::detail::ByteStream<Socket>;
        Lower lower_;
        std::unique_ptr<detail::BinaryFrames<Lower>> frames_;
    public:
        explicit VlessByteStream(tls::detail::ApplicationConnection<Socket>& connection) :lower_(connection) {}
        auto cancel() noexcept -> void {lower_.cancel();}
        auto prepend_owned(std::vector<std::uint8_t>&& bytes) -> bool {return lower_.prepend_owned(std::move(bytes));}
        auto release_reader() noexcept -> tls::detail::ApplicationStreamReader<Socket>* {
            return frames_ ? nullptr : lower_.release_reader();
        }
        auto activate_websocket(httpupgrade::Profile const& profile,Clock::time_point deadline)
            -> capy::task<std::expected<std::size_t,UpgradeFailure>> {
            auto ready=co_await websocket::upgrade(lower_,profile,deadline);
            if (ready) frames_=std::make_unique<detail::BinaryFrames<Lower>>(lower_,profile.is_client());
            co_return ready;
        }
        auto read(std::span<std::uint8_t> data,ApplicationDeadline deadline={},
            ReadTimeoutPolicy policy=ReadTimeoutPolicy::cancel_connection) {
            return frames_ ? frames_->read(data,deadline,policy) : lower_.read(data,deadline,policy);
        }
        auto send(std::span<std::uint8_t const> data,ApplicationDeadline deadline={}) {
            return frames_ ? frames_->send(data,deadline) : lower_.send(data,deadline);
        }
        auto close_output(ApplicationDeadline deadline={}) {
            return frames_ ? frames_->close_output(deadline) : lower_.close_output(deadline);
        }
    };
}
