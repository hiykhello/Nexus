export module anytls.session;
import std;
import anytls;
import anytls.auth;
import anytls.settings;
import anytls.padding;
import anytls.streams;
import anytls.writer;
import crypto;
import capy;
import corosio;

export namespace anytls {
    enum class SessionError { state,closed,timeout,authentication,protocol,remote,capacity };
    // The owner supplies one authenticated TLS byte stream and keeps it and
    // this session alive through all reader/stream tasks. No business proxy
    // Session, route, socket or executor is retained by this protocol layer.
    template<class Stream>
    class Session {
        Stream& stream_;
        PaddingScheme& padding_;
        Writer<Stream> writer_;
        StreamTable streams_;
        capy::async_event changed_,space_,opened_,controls_;
        std::deque<std::uint32_t> accepted_;
        std::vector<std::uint8_t> initial_;
        std::array<std::uint32_t,64> readers_{};
        std::array<std::uint32_t,64> finishes_{};
        std::size_t finish_begin_=0,finish_count_=0;
        bool client_,started_=false,closed_=false,running_=false,settings_=false;
        std::uint32_t peer_version_=0;
        std::uint64_t received_frames_=0;
        Deadline open_deadline_;
        struct RunGuard { Session& owner; ~RunGuard() { owner.running_=false; owner.cancel(); } };
        struct PartGuard { Session& owner; ~PartGuard() { owner.cancel(); } };
        struct OpenGuard { Session& owner; std::uint32_t id; bool done=false; ~OpenGuard() { if (!done) { (void)owner.streams_.release(id); if (owner.writer_.failed()) owner.cancel(); } } };
        struct ReaderGuard { std::uint32_t& slot; ~ReaderGuard() { slot=0; } };
        struct EraseInput { std::array<std::uint8_t,4096>& bytes; ~EraseInput() { crypto::cleanse(bytes); } };
        auto failure(SessionError error) noexcept -> std::unexpected<SessionError> { cancel(); return std::unexpected(error); }
        auto wait(capy::async_event& event,Deadline deadline) -> capy::task<bool> {
            auto operation=event.wait();
            auto [error]=deadline ? co_await corosio::timeout(std::move(operation),*deadline) : co_await std::move(operation);
            co_return !error && !closed_ && (!deadline || IoClock::now()<*deadline);
        }
        auto control(Frame frame) -> capy::task<bool> {
            auto const& header=frame.header;
            if (header.command==Command::settings && !client_) {
                if (settings_) co_return false;
                auto parsed=parse_settings(frame.payload,true);
                if (!parsed) co_return false;
                peer_version_=parsed->version; settings_=true;
                auto fingerprint=padding_fingerprint(padding_);
                if (!fingerprint) co_return false;
                if (parsed->padding_md5!=*fingerprint) {
                    auto raw=padding_.raw();
                    if (!co_await writer_.frame(Command::padding,0,{reinterpret_cast<std::uint8_t const*>(raw.data()),raw.size()},IoClock::now()+std::chrono::seconds(5))) co_return false;
                }
                if (peer_version_>=2) {
                    auto settings=encode_server_settings();
                    if (!co_await writer_.frame(Command::server_settings,0,settings,IoClock::now()+std::chrono::seconds(5))) co_return false;
                }
            } else if (header.command==Command::server_settings && client_) {
                auto parsed=parse_settings(frame.payload,false);
                if (!parsed) co_return false;
                peer_version_=parsed->version; changed_.set();
            } else if (header.command==Command::padding && client_) {
                auto raw=std::string_view(reinterpret_cast<char const*>(frame.payload.data()),frame.payload.size());
                auto update=PaddingScheme::parse(raw);
                if (!update) co_return false;
                padding_=std::move(*update);
            } else if (header.command==Command::heart_request) {
                if (!co_await writer_.frame(Command::heart_response,header.stream,{},IoClock::now()+std::chrono::seconds(5))) co_return false;
            } else if (header.command==Command::alert) co_return false;
            co_return true;
        }
        // Returns true if handled synchronously, false on protocol error, nullopt if async handling is needed.
        auto try_dispatch_sync(Frame const& frame) -> std::optional<bool> {
            auto const& header=frame.header;
            if (header.command==Command::push) {
                if (frame.payload.size()>streams_.max_frame_payload()) return false;
                auto pushed=streams_.push(header.stream,frame.payload);
                if (pushed==PushResult::backpressure) return std::nullopt;
                if (pushed==PushResult::queued) changed_.set();
                return !closed_;
            }
            if (header.command==Command::syn && !client_) {
                if (!settings_) return false;
                auto accepted=streams_.accept(header.stream);
                if (!accepted) return false;
                accepted_.push_back(header.stream); opened_.set();
                return !closed_;
            }
            if (header.command==Command::fin) {
                (void)streams_.finish(header.stream); changed_.set();
                return !closed_;
            }
            if (header.command==Command::syn_ack && client_) {
                (void)streams_.acknowledge(header.stream,frame.payload.empty()); changed_.set();
                return !closed_;
            }
            return std::nullopt;
        }
        auto dispatch_async(Frame frame) -> capy::task<bool> {
            auto const& header=frame.header;
            if (header.command==Command::push) {
                for (;;) {
                    space_.clear();
                    if (!co_await wait(space_,{})) co_return false;
                    auto pushed=streams_.push(header.stream,frame.payload);
                    if (pushed!=PushResult::backpressure) { if (pushed==PushResult::queued) changed_.set(); break; }
                }
            } else if (!co_await control(frame)) co_return false;
            co_return !closed_;
        }
    public:
        Session(Stream& stream,PaddingScheme& padding,bool client,StreamLimits limits={})
            : stream_(stream),padding_(padding),writer_(stream,padding,client),streams_(limits),client_(client) {}
        ~Session() { cancel(); }
        Session(Session const&)=delete;
        auto operator=(Session const&) -> Session& = delete;
        auto cancel() noexcept -> void {
            if (closed_) return;
            closed_=true; writer_.cancel(); streams_.close(); changed_.set(); space_.set(); opened_.set(); controls_.set();
        }
        auto usable() const noexcept -> bool { return started_ && !closed_ && !streams_.exhausted(); }
        auto drained() const noexcept -> bool { return !running_; }
        auto streams() const noexcept -> std::size_t { return streams_.size(); }
        auto stream_closed(std::uint32_t id) const noexcept -> bool { return !streams_.writable(id); }
        // Observe closure during an owned dial without consuming pipelined
        // bytes. Cancellation of this observer leaves the stream usable.
        auto wait_stream_closed(std::uint32_t id) -> capy::task<bool> {
            while (!closed_ && streams_.writable(id)) {
                changed_.clear();
                if (!co_await wait(changed_,{})) co_return closed_ || !streams_.writable(id);
            }
            co_return true;
        }
        auto start_client(std::span<std::uint8_t const> key,IoClock::time_point deadline,std::string_view metadata={}) -> capy::task<bool> {
            if (!client_ || started_ || closed_) co_return false;
            auto sent=co_await writer_.start(key,metadata,deadline);
            if (!sent || closed_) { cancel(); co_return false; }
            started_=true; co_return true;
        }
        auto start_server(std::span<PasswordKey const> users,IoClock::time_point deadline) -> capy::task<std::expected<std::size_t,SessionError>> {
            if (client_ || started_ || closed_) co_return std::unexpected(SessionError::state);
            AuthenticationDecoder decoder;
            std::array<std::uint8_t,4096> input{};
            EraseInput erase{input};
            for (;;) {
                auto received=co_await stream_.read(input,deadline);
                if (!received || !*received || *received>input.size() || closed_ || IoClock::now()>=deadline)
                    co_return failure(IoClock::now()>=deadline ? SessionError::timeout : SessionError::closed);
                auto fed=decoder.feed(std::span(input).first(*received));
                if (fed.status==Status::incomplete) continue;
                auto key=decoder.key();
                auto user=key ? authenticate(users,*key) : std::nullopt;
                if (fed.status!=Status::accepted || !user) co_return failure(SessionError::authentication);
                initial_.assign(input.begin()+fed.consumed,input.begin()+*received);
                started_=true; co_return *user;
            }
        }
    private:
        auto read_loop() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            FrameDecoder decoder;
            constexpr std::size_t kReadBufSize = 32768;
            auto buffer = std::make_unique_for_overwrite<std::uint8_t[]>(kReadBufSize);
            auto input=std::span<std::uint8_t const>(initial_);
            while (!closed_) {
                if (input.empty()) {
                    initial_.clear();
                    auto received=co_await stream_.read(std::span<std::uint8_t>(buffer.get(),kReadBufSize));
                    if (!received || !*received || *received>kReadBufSize) break;
                    input=std::span<std::uint8_t const>(buffer.get(),*received);
                }
                while (!input.empty() && !closed_) {
                    auto fed=decoder.feed(input); input=input.subspan(fed.consumed);
                    if (fed.status==Status::incomplete) break;
                    auto frame=decoder.frame();
                    if (fed.status!=Status::accepted || !frame) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    ++received_frames_;
                    if (open_deadline_) { open_deadline_.reset(); controls_.set(); }
                    auto sync=try_dispatch_sync(*frame);
                    bool ok=sync ? *sync : co_await dispatch_async(*frame);
                    if (!ok) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                    if (!decoder.consume()) co_return capy::results<>{std::make_error_code(std::errc::protocol_error)};
                }
            }
            co_return capy::results<>{closed_ ? std::error_code{} : std::make_error_code(std::errc::io_error)};
        }
        auto flush_controls() -> capy::task<capy::results<>> {
            PartGuard guard{*this};
            while (!closed_) {
                if (open_deadline_ && IoClock::now()>=*open_deadline_)
                    co_return capy::results<>{std::make_error_code(std::errc::timed_out)};
                if (!finish_count_) {
                    controls_.clear();
                    auto limit=open_deadline_;
                    auto operation=controls_.wait();
                    auto [error]=limit ? co_await corosio::timeout(std::move(operation),*limit) : co_await std::move(operation);
                    if (error) {
                        if (capy::is_timeout(error) && (!open_deadline_ || IoClock::now()<*open_deadline_)) continue;
                        co_return capy::results<>{error};
                    }
                    continue;
                }
                auto id=finishes_[finish_begin_];
                finish_begin_=(finish_begin_+1)%finishes_.size(); --finish_count_;
                if (!co_await writer_.frame(Command::fin,id,{},IoClock::now()+std::chrono::seconds(5)))
                    co_return capy::results<>{std::make_error_code(std::errc::io_error)};
            }
            co_return capy::results<>{};
        }
    public:
        // The reader and control writer share the session's lifetime. A
        // canceled logical stream can send FIN even while TLS reads wait
        // for another stream's data; no detached task borrows this owner.
        auto run() -> capy::task<capy::results<>> {
            if (!started_ || running_ || closed_) co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
            running_=true; RunGuard guard{*this};
            auto [error,reader,writer]=co_await capy::when_all(read_loop(),flush_controls());
            (void)reader; (void)writer; co_return capy::results<>{error};
        }
        auto open(Address const& destination,IoClock::time_point deadline) -> capy::task<std::expected<std::uint32_t,SessionError>> {
            if (!client_ || !usable() || !net::valid_proxy_address(destination)) co_return std::unexpected(SessionError::state);
            if (IoClock::now()>=deadline) co_return std::unexpected(SessionError::timeout);
            auto id=streams_.open();
            if (!id) co_return std::unexpected(SessionError::capacity);
            OpenGuard guard{*this,*id};
            auto frames_before=received_frames_;
            if (!co_await writer_.open(*id,destination,deadline) || closed_) {
                auto err=IoClock::now()>=deadline ? SessionError::timeout : SessionError::closed;
                if (writer_.failed()) co_return failure(err);
                co_return std::unexpected(err);
            }
            // Arm the reused-stream watchdog only after SYN+address was written,
            // unless a valid peer frame already arrived while writer_.open() ran.
            // It must not block initial application bytes behind SYNACK: UoT and
            // DNS handlers can need those bytes before reporting success.
            if (*id>1 && peer_version_>=2 && received_frames_==frames_before) {
                auto limit=std::min(deadline,IoClock::now()+std::chrono::seconds(3));
                if (!open_deadline_ || limit<*open_deadline_) open_deadline_=limit;
                controls_.set();
            }
            guard.done=true; co_return *id;
        }
        auto accept(Deadline deadline={}) -> capy::task<std::expected<std::uint32_t,SessionError>> {
            if (client_ || !started_) co_return std::unexpected(SessionError::state);
            while (!closed_) {
                if (!accepted_.empty()) { auto id=accepted_.front(); accepted_.pop_front(); co_return id; }
                opened_.clear();
                if (!co_await wait(opened_,deadline)) co_return std::unexpected(deadline && IoClock::now()>=*deadline ? SessionError::timeout : SessionError::closed);
            }
            co_return std::unexpected(SessionError::closed);
        }
        auto acknowledge(std::uint32_t id,bool success=true,Deadline deadline={}) -> capy::task<bool> {
            if (client_ || !streams_.writable(id) || closed_) co_return false;
            auto sent=peer_version_<2 ? (success || co_await writer_.frame(Command::fin,id,{},deadline)) :
                co_await writer_.frame(Command::syn_ack,id,success ? std::span<std::uint8_t const>{} :
                    std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>("connection failed"),17),deadline);
            if (!sent) {
                if (writer_.failed()) cancel();
                else if (!success) cancel_stream(id);
            } else if (!success) {
                (void)streams_.acknowledge(id,false); changed_.set(); space_.set();
            }
            co_return sent;
        }
        auto send(std::uint32_t id,std::span<std::uint8_t const> input,Deadline deadline={}) -> capy::task<bool> {
            if (!streams_.writable(id) || closed_) co_return false;
            auto sent=co_await writer_.data(id,input,deadline);
            if (!sent && writer_.failed()) cancel();
            co_return sent && !closed_;
        }
        auto read(std::uint32_t id,std::span<std::uint8_t> output,Deadline deadline={})
            -> capy::task<std::expected<std::size_t,SessionError>> {
            auto slot=std::ranges::find(readers_,0u);
            if (!id || slot==readers_.end() || std::ranges::find(readers_,id)!=readers_.end()) co_return std::unexpected(SessionError::state);
            *slot=id;
            ReaderGuard guard{*slot};
            while (!closed_) {
                auto read=streams_.read(id,output);
                if (read) { if (*read) space_.set(); co_return *read; }
                if (read.error()!=StreamError::backpressure) co_return std::unexpected(streams_.rejected(id) ? SessionError::remote : SessionError::closed);
                changed_.clear();
                if (!co_await wait(changed_,deadline)) co_return std::unexpected(deadline && IoClock::now()>=*deadline ? SessionError::timeout : SessionError::closed);
            }
            co_return std::unexpected(SessionError::closed);
        }
        // FIN closes the entire logical stream. It is intentionally not a
        // promise of independent TCP write-half shutdown.
        auto finish(std::uint32_t id,Deadline deadline={}) -> capy::task<bool> {
            if (closed_) co_return false;
            if (!streams_.writable(id)) co_return true;
            auto sent=co_await writer_.frame(Command::fin,id,{},deadline);
            if (sent) { (void)streams_.finish(id); changed_.set(); }
            else if (writer_.failed()) cancel();
            else cancel_stream(id);
            co_return sent;
        }
        auto cancel_stream(std::uint32_t id) noexcept -> void {
            if (closed_ || !streams_.writable(id)) return;
            (void)streams_.acknowledge(id,false); changed_.set(); space_.set();
            if (finish_count_==finishes_.size()) { cancel(); return; }
            finishes_[(finish_begin_+finish_count_)%finishes_.size()]=id; ++finish_count_; controls_.set();
        }
        auto release(std::uint32_t id) noexcept -> void { (void)streams_.release(id); space_.set(); changed_.set(); }
    };
    template<class Stream>
    class StreamChannel {
        Session<Stream>* session_;
        std::uint32_t id_;
    public:
        StreamChannel(Session<Stream>& session,std::uint32_t id) noexcept : session_(&session),id_(id) {}
        ~StreamChannel() { if (id_) { session_->cancel_stream(id_); session_->release(id_); } }
        StreamChannel(StreamChannel const&)=delete;
        auto operator=(StreamChannel const&) -> StreamChannel& = delete;
        StreamChannel(StreamChannel&& other) noexcept : session_(other.session_),id_(std::exchange(other.id_,0)) {}
        auto read(std::span<std::uint8_t> bytes,Deadline deadline={}) { return session_->read(id_,bytes,deadline); }
        auto send(std::span<std::uint8_t const> bytes,Deadline deadline={}) { return session_->send(id_,bytes,deadline); }
        auto close_output(Deadline deadline={}) { return session_->finish(id_,deadline); }
        auto cancel() noexcept -> void { session_->cancel_stream(id_); }
        auto id() const noexcept -> std::uint32_t { return id_; }
    };
}
