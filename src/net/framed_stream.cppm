export module net.framed_stream;
import std;
import net.buffered_input;
import net.socket_stream;
import nexus.thirdparty.capy;

export namespace net {
    enum class RecordStreamError { state,transport,timeout,truncated,codec,canceled };
    struct PlainRegion {std::size_t offset=0,size=0;};
    // The caller provides the one writer, and joins/drains both directions
    // before destroying this stable owner or its lower stream. The codec is
    // synchronous; it owns the record state and permits only exact in-place
    // opening. No extra reader, writer queue, mutex or forwarding task exists.
    template<class Lower,class Codec>
    class FramedByteStream {
    public:
        struct Failure {RecordStreamError error;std::optional<typename Codec::Error> codec;};
        using Window=BufferedInput<Codec::max_wire>;
    private:
        Lower& lower_;
        Codec codec_;
        Window input_;
        std::size_t wire_size_=0,plain_begin_=0,plain_end_=0;
        std::optional<Failure> failure_;
        bool writing_=false,output_closed_=false,eof_=false;
        auto fail(RecordStreamError error,std::optional<typename Codec::Error> codec={}) noexcept -> void {
            if (!failure_) failure_=Failure{error,codec};
        }
        auto abort() noexcept -> void {fail(RecordStreamError::canceled);codec_.cancel();input_.invalidate();}
        struct CopyConsumer {
            using Result=std::expected<std::size_t,std::error_code>;
            std::span<std::uint8_t> output;std::size_t copied=0;
            auto feed(std::span<std::uint8_t const> plain) noexcept -> InputStep {
                if (!output.empty() && plain.empty()) return {};
                copied=std::min(output.size(),plain.size());std::copy_n(plain.begin(),copied,output.begin());
                return {copied,0,InputAction::complete};
            }
            auto abort() noexcept -> void {}
            auto finish(InputStatus status,std::optional<Failure> failure) noexcept -> Result {
                if (status==InputStatus::ready && !failure) return copied;
                if (status==InputStatus::eof && !failure) return 0;
                return std::unexpected(std::make_error_code(failure && failure->error==RecordStreamError::timeout ?
                    std::errc::timed_out : failure && failure->error==RecordStreamError::state ? std::errc::operation_not_permitted : std::errc::io_error));
            }
        };
        template<class Consumer>
        struct ReadState {
            using Result=typename Consumer::Result;
            FramedByteStream& owner;Consumer consumer;
            auto input() noexcept -> Window& {return owner.input_;}
            auto abort() noexcept -> void {consumer.abort();owner.abort();}
            auto feed(std::span<std::uint8_t> wire) -> InputStep {
                if (owner.failure_) return {0,0,InputAction::fail};
                auto initial=consumer.feed({});
                if (initial.consumed) {owner.fail(RecordStreamError::state);return {0,0,InputAction::fail};}
                if (initial.action!=InputAction::more) return initial;
                if (!owner.wire_size_) {
                    if (wire.size()<Codec::header_size) return {0,Codec::header_size};
                    auto needed=owner.codec_.inspect(wire.first(Codec::header_size));
                    if (!needed) {owner.fail(RecordStreamError::codec,needed.error());return {0,0,InputAction::fail};}
                    if (*needed<Codec::header_size || *needed>Codec::max_wire) {owner.fail(RecordStreamError::state);return {0,0,InputAction::fail};}
                    if (wire.size()<*needed) return {0,*needed};
                    auto plain=owner.codec_.open(wire.first(*needed));
                    if (!plain) {owner.fail(RecordStreamError::codec,plain.error());return {0,0,InputAction::fail};}
                    if (plain->offset>*needed || plain->size>*needed-plain->offset) {owner.fail(RecordStreamError::state);return {0,0,InputAction::fail};}
                    if (!plain->size) {buffered_detail::erase(wire.first(*needed));return {*needed,Codec::header_size};}
                    owner.wire_size_=*needed;owner.plain_begin_=plain->offset;owner.plain_end_=plain->offset+plain->size;
                }
                if (wire.size()<owner.wire_size_) {owner.fail(RecordStreamError::state);return {0,0,InputAction::fail};}
                auto plain=std::span<std::uint8_t const>(wire).subspan(owner.plain_begin_,owner.plain_end_-owner.plain_begin_);
                auto step=consumer.feed(plain);
                if (step.consumed>plain.size() || (step.action==InputAction::more && step.consumed!=plain.size())) {
                    owner.fail(RecordStreamError::state);return {0,0,InputAction::fail};
                }
                owner.plain_begin_+=step.consumed;
                if (owner.plain_begin_!=owner.plain_end_) return {0,0,step.action};
                auto consumed=owner.wire_size_;buffered_detail::erase(wire.first(consumed));owner.wire_size_=owner.plain_begin_=owner.plain_end_=0;
                return {consumed,0,step.action};
            }
            auto finish(InputStatus status) -> Result {
                if (status==InputStatus::ready && !owner.failure_) return consumer.finish(status,std::optional<Failure>{});
                if (status==InputStatus::eof && owner.input_.pending().empty() && !owner.wire_size_ && !owner.failure_) {
                    owner.codec_.fail_receive();owner.eof_=true;return consumer.finish(status,std::optional<Failure>{});
                }
                auto error=status==InputStatus::timeout ? RecordStreamError::timeout :
                    status==InputStatus::eof ? RecordStreamError::truncated :
                    status==InputStatus::transport ? RecordStreamError::transport : RecordStreamError::state;
                owner.fail(error);return consumer.finish(status,owner.failure_);
            }
        };
        struct WriterGuard {
            FramedByteStream& owner;bool released=false;
            ~WriterGuard() {owner.writing_=false;if (!released) {owner.abort();owner.lower_.cancel();}}
        };
    public:
        explicit FramedByteStream(Lower& lower) noexcept : lower_(lower) {}
        ~FramedByteStream() {cancel();}
        FramedByteStream(FramedByteStream const&)=delete;
        auto operator=(FramedByteStream const&) -> FramedByteStream& = delete;
        // Only startup consumers use this window, before application read().
        // Their task returns directly from Window::drive with a stable borrow.
        auto startup_input() noexcept -> Window& {return input_;}
        auto codec() noexcept -> Codec& {return codec_;}
        auto failure() const noexcept -> std::optional<Failure> {return failure_;}
        auto input_eof() const noexcept -> bool {return eof_;}
        auto cancel() noexcept -> void {abort();lower_.cancel();}
        auto read(std::span<std::uint8_t> output,StreamDeadline deadline={}) -> nex::capy::task<std::expected<std::size_t,std::error_code>> {
            return drive_plain([output] {return CopyConsumer{output};},deadline);
        }
        template<class Factory>
        auto drive_plain(Factory factory,StreamDeadline deadline={}) {
            return Window::drive(lower_,[this,factory] {return ReadState<decltype(factory())>{*this,factory()};},deadline);
        }
        auto send(std::span<std::uint8_t const> input,StreamDeadline deadline={}) -> nex::capy::task<bool> {
            if (writing_ || output_closed_ || failure_) {fail(RecordStreamError::state);abort();lower_.cancel();co_return false;}
            writing_=true;WriterGuard guard{*this};
            std::array<std::uint8_t,Codec::max_wire> wire{};
            struct Erase {std::span<std::uint8_t> bytes;~Erase() {buffered_detail::erase(bytes);}} erase{wire};
            if (buffered_detail::expired(deadline)) {fail(RecordStreamError::timeout);co_return false;}
            while (!input.empty()) {
                auto size=std::min(input.size(),Codec::max_plaintext);
                auto sealed=codec_.seal(wire,input.first(size));
                if (!sealed) {fail(RecordStreamError::codec,sealed.error());co_return false;}
                if (!*sealed || *sealed>wire.size()) {fail(RecordStreamError::state);co_return false;}
                if (!co_await lower_.send(std::span(wire).first(*sealed),deadline) || failure_ || buffered_detail::expired(deadline)) {
                    fail(buffered_detail::expired(deadline) ? RecordStreamError::timeout : RecordStreamError::transport);co_return false;
                }
                auto committed=codec_.sent();if (!committed) {fail(RecordStreamError::codec,committed.error());co_return false;}
                buffered_detail::erase(std::span(wire).first(*sealed));input=input.subspan(size);
            }
            guard.released=true;co_return true;
        }
        auto close_output(StreamDeadline deadline={}) -> nex::capy::task<bool> {
            if (writing_ || output_closed_ || failure_) {fail(RecordStreamError::state);abort();lower_.cancel();co_return false;}
            writing_=true;WriterGuard guard{*this};
            if (buffered_detail::expired(deadline) || !co_await lower_.close_output(deadline) || failure_ || buffered_detail::expired(deadline)) {
                fail(buffered_detail::expired(deadline) ? RecordStreamError::timeout : RecordStreamError::transport);co_return false;
            }
            codec_.fail_send();output_closed_=true;guard.released=true;co_return true;
        }
    };
}
