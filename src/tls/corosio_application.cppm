export module nexus.tls.corosio_application;
import std;
import nexus.tls.application_io;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace nexus::tls::detail {
    enum class AsyncApplicationError { transport, state, truncated, protocol, timeout, key_update_required };
    using ApplicationDeadline = std::optional<std::chrono::steady_clock::time_point>;
    inline auto expired(ApplicationDeadline deadline) noexcept -> bool { return deadline && std::chrono::steady_clock::now() >= *deadline; }
    enum class AsyncReadKind { event, backpressure, eof };
    struct AsyncReadResult { AsyncReadKind kind; std::optional<ApplicationEvent> event; };
    // One reader owns the buffered transport suffix, including any bytes read during handshake.
    class ApplicationInput {
        std::array<std::uint8_t,4096> buffered_{};
        std::size_t offset_=0, size_=0;
        bool valid_=true;
    public:
        // Handshake drivers read at most one 4096-byte transport block. Reject a
        // larger externally supplied suffix and do not retain its allocation.
        explicit ApplicationInput(crypto::Bytes&& unread) : valid_(unread.size()<=buffered_.size()) {
            if (valid_) { size_=unread.size(); std::copy(unread.begin(),unread.end(),buffered_.begin()); }
            crypto::Bytes{}.swap(unread);
        }
        [[nodiscard]] auto valid() const noexcept -> bool { return valid_; }
        ApplicationInput(ApplicationInput const&)=delete;
        auto operator=(ApplicationInput const&) -> ApplicationInput& = delete;
        // A backpressure result means the single writer must flush pending output first.
        template<class Socket>
        auto read(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (!valid_) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
            while (true) {
                if (expired(deadline)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                if (app.input_blocked()) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
                if (offset_==size_) {
                    offset_=size_=0;
                    auto operation=socket.read_some(nex::capy::mutable_buffer(buffered_.data(),buffered_.size()));
                    auto [error,n]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
                    if (nex::capy::is_timeout(error) || (!error && expired(deadline))) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
                    if (nex::capy::is_eof(error) || (!error && !n)) {
                        if (!app.finish_input()) co_return std::unexpected(AsyncApplicationError::truncated);
                        co_return AsyncReadResult{AsyncReadKind::eof,{}};
                    }
                    if (error) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    if (n>buffered_.size()) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
                    size_=n;
                }
                auto result=app.feed(std::span{buffered_}.subspan(offset_,size_-offset_));
                if (!result) { app.cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                offset_+=result->consumed;
                if (result->event) co_return AsyncReadResult{AsyncReadKind::event,std::move(result->event)};
                if (!result->consumed) co_return AsyncReadResult{AsyncReadKind::backpressure,{}};
            }
        }
    };
    // Single writer. The owner serializes all ApplicationIo calls on one executor and keeps
    // the socket and state alive until this coroutine completes, including after cancellation.
    // The copy protects a parked write from a concurrent receive failing or changing output.
    template<class Socket>
    auto flush_application(Socket& socket, ApplicationIo& app, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
        while (!app.pending_output().empty()) {
            if (expired(deadline)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            auto pending=app.pending_output(); crypto::Bytes owned(pending.begin(),pending.end());
            auto operation=socket.write_some(nex::capy::const_buffer(owned.data(),owned.size()));
            auto [error,n]=deadline ? co_await nex::corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            if (nex::capy::is_timeout(error) || (!error && expired(deadline))) { app.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            if (error || !n || n>owned.size()) { app.cancel(); co_return std::unexpected(AsyncApplicationError::transport); }
            if (!app.written(n)) { app.cancel(); co_return std::unexpected(AsyncApplicationError::state); }
        }
        co_return std::expected<void,AsyncApplicationError>{};
    }

    // Socket and this owner must remain alive until both pending operations complete.
    // All methods and completions run on the same executor. One reader and one writer
    // may overlap; a second operation in either direction is rejected. Deadlines use
    // steady_clock and apply to the complete operation; timeout cancels both directions.
    // An unread suffix larger than 4096 bytes makes the owner inactive.
    // send() automatically writes KeyUpdate before data when the local budget is exhausted.
    // The caller keeps the input span alive until send() completes.
    template<class Socket>
    class ApplicationConnection {
        Socket& socket_;
        ApplicationIo app_;
        ApplicationInput input_;
        bool reading_=false, writing_=false, stream_writing_=false, canceled_=false;
    public:
        ApplicationConnection(Socket& socket, ApplicationRecords&& records, crypto::Bytes&& unread)
            : socket_(socket), app_(std::move(records)), input_(std::move(unread)), canceled_(!input_.valid()) {
            if (canceled_) app_.cancel();
        }
        ApplicationConnection(ApplicationConnection const&)=delete;
        auto operator=(ApplicationConnection const&) -> ApplicationConnection& = delete;
        [[nodiscard]] auto idle() const noexcept -> bool { return !reading_ && !writing_ && !stream_writing_; }
        [[nodiscard]] auto active() const noexcept -> bool { return !canceled_; }
        [[nodiscard]] auto pending_output() const noexcept -> bool { return !app_.pending_output().empty(); }
        auto cancel() noexcept -> void { if (!canceled_) { canceled_=true; app_.cancel(); socket_.cancel(); } }
        auto read(ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<AsyncReadResult,AsyncApplicationError>> {
            if (reading_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
            reading_=true; auto result=co_await input_.read(socket_,app_,deadline); reading_=false;
            if (!result || (result->event && result->event->kind==ApplicationEventKind::fatal_alert)) { canceled_=true; socket_.cancel(); }
            co_return result;
        }
        auto flush(ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
            writing_=true; auto result=co_await flush_application(socket_,app_,deadline); writing_=false;
            if (!result) { canceled_=true; socket_.cancel(); }
            co_return result;
        }
    private:
        auto send_record(std::span<std::uint8_t const> data, ApplicationDeadline deadline, bool stream) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || (stream_writing_ && !stream) || canceled_) co_return std::unexpected(AsyncApplicationError::state);
            auto result=app_.send(data);
            if (!result && result.error()!=ApplicationIoError::key_update_required) {
                if (result.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                co_return std::unexpected(AsyncApplicationError::state);
            }
            writing_=true;
            if (!result) {
                auto update=app_.request_key_update(false);
                if (!update) {
                    writing_=false;
                    if (update.error()==ApplicationIoError::record_error) { cancel(); co_return std::unexpected(AsyncApplicationError::protocol); }
                    co_return std::unexpected(AsyncApplicationError::key_update_required);
                }
                auto updated=co_await flush_application(socket_,app_,deadline);
                if (!updated) { writing_=false; canceled_=true; socket_.cancel(); co_return std::unexpected(updated.error()); }
                // A peer update received while the write was in flight can queue a response.
                while (!app_.pending_output().empty()) {
                    auto response=co_await flush_application(socket_,app_,deadline);
                    if (!response) { writing_=false; canceled_=true; socket_.cancel(); co_return std::unexpected(response.error()); }
                }
                if (canceled_ || !app_.send(data)) { writing_=false; co_return std::unexpected(AsyncApplicationError::state); }
            }
            auto written=co_await flush_application(socket_,app_,deadline); writing_=false;
            if (!written) { canceled_=true; socket_.cancel(); }
            co_return written;
        }
    public:
        auto send(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            co_return co_await send_record(data,deadline,false);
        }
        // Sends an entire byte span in bounded records. On failure a prefix may have reached
        // the peer; the caller must not retry it blindly. Input remains valid until completion.
        auto send_all(std::span<std::uint8_t const> data, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_) co_return std::unexpected(AsyncApplicationError::state);
            if (expired(deadline)) { cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            auto limit=app_.max_write_size();
            if (!limit) co_return std::unexpected(AsyncApplicationError::state);
            stream_writing_=true;
            while (!data.empty()) {
                auto count=std::min(limit,data.size());
                auto result=co_await send_record(data.first(count),deadline,true);
                if (!result) { stream_writing_=false; co_return std::unexpected(result.error()); }
                data=data.subspan(count);
            }
            stream_writing_=false;
            co_return std::expected<void,AsyncApplicationError>{};
        }
        auto key_update(bool request, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_ || !app_.request_key_update(request)) co_return std::unexpected(AsyncApplicationError::state);
            co_return co_await flush(deadline);
        }
        auto close_notify(ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<void,AsyncApplicationError>> {
            if (writing_ || stream_writing_ || canceled_ || !app_.close_notify()) co_return std::unexpected(AsyncApplicationError::state);
            co_return co_await flush(deadline);
        }
    };

    enum class AsyncStreamReadKind { data, event, backpressure, eof };
    struct AsyncStreamReadResult { AsyncStreamReadKind kind; std::size_t size=0; std::optional<ApplicationEvent> event; };
    // Byte-oriented adapter for the single reader of an ApplicationConnection. Control events
    // remain visible to the caller, which must flush requested KeyUpdate responses. Neither
    // this adapter nor its connection may be destroyed before an outstanding read completes.
    template<class Socket>
    class ApplicationStreamReader {
        ApplicationConnection<Socket>& connection_;
        crypto::Bytes buffered_;
        std::size_t offset_=0;
        bool reading_=false, closed_=false;
    public:
        explicit ApplicationStreamReader(ApplicationConnection<Socket>& connection) : connection_(connection) {}
        ApplicationStreamReader(ApplicationStreamReader const&)=delete;
        auto operator=(ApplicationStreamReader const&) -> ApplicationStreamReader& = delete;
        // The output span must remain alive until completion. An empty span is rejected.
        auto read_some(std::span<std::uint8_t> output, ApplicationDeadline deadline = {}) -> nex::capy::task<std::expected<AsyncStreamReadResult,AsyncApplicationError>> {
            if (reading_ || output.empty() || !connection_.active()) co_return std::unexpected(AsyncApplicationError::state);
            if (expired(deadline)) { connection_.cancel(); co_return std::unexpected(AsyncApplicationError::timeout); }
            reading_=true;
            while (true) {
                if (offset_<buffered_.size()) {
                    auto count=std::min(output.size(),buffered_.size()-offset_);
                    std::copy_n(buffered_.begin()+static_cast<std::ptrdiff_t>(offset_),count,output.begin());
                    offset_+=count;
                    if (offset_==buffered_.size()) { crypto::Bytes{}.swap(buffered_); offset_=0; }
                    reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::data,count,{}};
                }
                if (closed_) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
                auto result=co_await connection_.read(deadline);
                if (!result) { reading_=false; co_return std::unexpected(result.error()); }
                if (result->kind==AsyncReadKind::backpressure) { reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::backpressure,0,{}}; }
                if (result->kind==AsyncReadKind::eof) { closed_=true; reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::eof,0,{}}; }
                auto event=std::move(*result->event);
                if (event.kind==ApplicationEventKind::data) { buffered_=std::move(event.data); continue; }
                if (event.kind==ApplicationEventKind::close_notify) closed_=true;
                reading_=false; co_return AsyncStreamReadResult{AsyncStreamReadKind::event,0,std::move(event)};
            }
        }
    };
}
