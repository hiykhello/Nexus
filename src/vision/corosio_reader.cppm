export module vision.corosio_reader;
import std;
import vision;
import vision.corosio_writer;
import tls.corosio_application;
import tls.application_io;
import capy;
import corosio;

export namespace vision::detail {
    enum class ReadError { state, transport, protocol };
    // Single reader on the same executor as Writer. The stream reader is the
    // one already used for the VLESS header, preserving its decrypted suffix.
    // initial contains bytes already handed to the VLESS parser after the header.
    template<class Socket>
    class Reader {
        Socket& socket_;
        tls::detail::ApplicationStreamReader<Socket>& tls_reader_;
        Writer<Socket>& writer_;
        TrafficFilter& filter_;
        Receiver receiver_;
        std::array<std::uint8_t,8192> input_{};
        std::array<std::uint8_t,8192> decoded_{};
        std::size_t begin_=0,end_=0,detached_offset_=0;
        std::size_t decoded_begin_=0,decoded_end_=0;
        tls::detail::DetachedStreamInput detached_;
        bool reading_=false, canceled_=false, eof_=false, direct_=false, valid_=true;
        auto fail(ReadError error) -> std::unexpected<ReadError> { canceled_=true; writer_.cancel(); return std::unexpected(error); }
        auto drain(std::span<std::uint8_t> output,std::span<std::uint8_t const> input) -> std::size_t {
            auto count=std::min(output.size(),input.size()); std::copy_n(input.begin(),count,output.begin()); return count;
        }
    public:
        Reader(Socket& socket,tls::detail::ApplicationStreamReader<Socket>& tls_reader,Writer<Socket>& writer,TrafficFilter& filter,UserId user,std::span<std::uint8_t const> initial={})
            : socket_(socket),tls_reader_(tls_reader),writer_(writer),filter_(filter),receiver_(user),valid_(initial.size()<=input_.size()) {
            if (valid_) { std::copy(initial.begin(),initial.end(),input_.begin()); end_=initial.size(); }
        }
        Reader(Reader const&)=delete;
        auto operator=(Reader const&) -> Reader& = delete;
        [[nodiscard]] auto direct() const noexcept -> bool { return direct_; }
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; writer_.cancel(); } }
        // Zero means EOF; on direct switch, already-decrypted suffix precedes
        // the previously read raw suffix, followed by subsequent socket data.
        auto read(std::span<std::uint8_t> output,tls::detail::ApplicationDeadline deadline={})
            -> capy::task<std::expected<std::size_t,ReadError>> {
            if (reading_ || canceled_ || !valid_ || output.empty()) co_return std::unexpected(ReadError::state);
            reading_=true;
            struct ReadGuard { bool& r; ~ReadGuard() { r=false; } } rg{reading_};
            try {
                for (;;) {
                    if (canceled_) co_return fail(ReadError::transport);
                    if (decoded_begin_<decoded_end_) {
                        auto n=drain(output,std::span(decoded_).subspan(decoded_begin_,decoded_end_-decoded_begin_));
                        decoded_begin_+=n; co_return n;
                    }
                    decoded_begin_=decoded_end_=0;
                    if (direct_) {
                        if (begin_<end_) { auto n=drain(output,std::span(input_).subspan(begin_,end_-begin_)); begin_+=n; co_return n; }
                        if (detached_offset_<detached_.plaintext.size()) {
                            auto n=drain(output,std::span(detached_.plaintext).subspan(detached_offset_)); detached_offset_+=n; co_return n;
                        }
                        detached_offset_-=detached_.plaintext.size(); detached_.plaintext.clear();
                        if (detached_offset_<detached_.transport.size()) {
                            auto n=drain(output,std::span(detached_.transport).subspan(detached_offset_)); detached_offset_+=n; co_return n;
                        }
                        detached_.transport.clear(); detached_offset_=0;
                        if (canceled_) co_return fail(ReadError::transport);
                        auto op=socket_.read_some(capy::mutable_buffer(output.data(),output.size()));
                        auto [error,n]=deadline ? co_await corosio::timeout(std::move(op),*deadline) : co_await std::move(op);
                        if (canceled_) co_return fail(ReadError::transport);
                        if (capy::is_eof(error) || (!error && !n)) co_return 0;
                        if (error || n>output.size()) co_return fail(ReadError::transport);
                        co_return n;
                    }
                    auto step=receiver_.feed(std::span(input_).subspan(begin_,end_-begin_),decoded_); begin_+=step.consumed;
                    if (step.status==ReceiveStatus::invalid || step.status==ReceiveStatus::truncated) co_return fail(ReadError::protocol);
                    if (step.status==ReceiveStatus::direct) {
                        auto suffix=tls_reader_.detach_input();
                        if (!suffix) co_return fail(ReadError::protocol);
                        detached_=std::move(*suffix); direct_=true;
                    }
                    if (step.written) { decoded_end_=step.written; filter_.observe(std::span(decoded_).first(decoded_end_)); continue; }
                    if (direct_) continue;
                    if (step.status==ReceiveStatus::closed) co_return 0;
                    if (eof_ || begin_!=end_) co_return fail(ReadError::protocol);
                    begin_=end_=0;
                    auto result=co_await tls_reader_.read_some(input_,deadline);
                    if (!result || canceled_) co_return fail(ReadError::transport);
                    if (result->kind==tls::detail::AsyncStreamReadKind::data) {
                        if (result->size>input_.size()) co_return fail(ReadError::transport);
                        end_=result->size; continue;
                    }
                    if (result->kind==tls::detail::AsyncStreamReadKind::backpressure || (result->event && result->event->kind==tls::ApplicationEventKind::key_update_requested)) {
                        if (!co_await writer_.flush_control(deadline) || canceled_) co_return fail(ReadError::transport);
                        continue;
                    }
                    if (result->kind==tls::detail::AsyncStreamReadKind::eof || (result->event && result->event->kind==tls::ApplicationEventKind::close_notify)) {
                        eof_=true; auto state=receiver_.finish();
                        if (state==ReceiveStatus::truncated || state==ReceiveStatus::invalid) co_return fail(ReadError::protocol);
                        continue;
                    }
                    if (result->event && (result->event->kind==tls::ApplicationEventKind::fatal_alert || result->event->kind==tls::ApplicationEventKind::user_canceled)) co_return fail(ReadError::protocol);
                }
            } catch (...) { cancel(); throw; }
        }
    };
}
