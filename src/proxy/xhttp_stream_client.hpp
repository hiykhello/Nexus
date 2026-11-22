#pragma once

        template<class Carrier>
        class HttpStream {
            using Worker=HttpWorker<Carrier>;
            using Pool=HttpPool<Carrier>;
            using Ticket=typename Carrier::Ticket;
            Session& session_;
            nex::corosio::io_context& context_;
            Profile const& profile_;
            TcpSocketOptions options_;
            std::shared_ptr<Worker> worker_;
            typename Pool::Lease up_,down_;
            std::optional<Ticket> upload_,download_;
            xhttp::Mode mode_;
            std::string id_;
            std::uint64_t sequence_=0;
            Clock::time_point last_post_{};
            std::stop_source stop_;
            bool stopped_=false,output_closed_=false;
            auto request(Peer const& peer,xhttp::RequestKind kind) -> std::optional<xhttp::Request> {
                auto random=entropy();
                if (!random) return {};
                return xhttp::request(profile_.transport,peer.endpoint,kind,id_,sequence_,*random,peer.secure());
            }
            auto open(typename Pool::Lease& carrier,Peer const& peer,xhttp::RequestKind kind,http2::BodyView body,Clock::time_point until)
                -> nex::capy::task<std::optional<Ticket>> {
                auto headers=request(peer,kind);
                if (!headers) co_return std::nullopt;
                co_return co_await carrier->open(*headers,peer,body,until);
            }
            auto downlink() noexcept -> typename Pool::Lease& {return mode_==xhttp::Mode::stream_one ? up_ : down_;}
            auto packet(std::span<std::uint8_t const> data,Clock::time_point until) -> nex::capy::task<bool> {
                auto start=last_post_+profile_.transport.limits.post_interval;
                if (start>Clock::now()) {
                    if (start>=until) co_return false;
                    nex::corosio::steady_timer timer(context_);
                    timer.expires_at(start);
                    auto [error]=co_await timer.wait();
                    if (error || stopped_) co_return false;
                }
                if (sequence_==std::numeric_limits<std::uint64_t>::max()) co_return false;
                if (!up_ || !up_.request()) {
                    up_.reset();
                    up_=co_await worker_->up.acquire(session_,profile_.up,profile_.bootstrap,options_,until);
                    if (!up_ || stopped_ || !up_.request()) co_return false;
                }
                auto stream=co_await open(up_,profile_.up,xhttp::RequestKind::packet,{data,true},until);
                if (!stream) co_return false;
                struct Pending {
                    Carrier& carrier;
                    Ticket stream;
                    ~Pending() {carrier.release(stream);}
                } pending{*up_.operator->(),*stream};
                last_post_=Clock::now();
                std::array<std::uint8_t,1024> reply;
                std::size_t remaining=8192;
                for (;;) {
                    auto result=co_await up_->read(*stream,reply,until);
                    if (!result || *result>remaining) co_return false;
                    if (!*result) break;
                    remaining-=*result;
                }
                ++sequence_;
                co_return true;
            }
        public:
            HttpStream(Session& session,nex::corosio::io_context& context,Profile const& profile,TcpSocketOptions const& options,
                std::shared_ptr<Worker> worker)
                :session_(session),context_(context),profile_(profile),options_(options),
                worker_(std::move(worker)),
                mode_(xhttp::select_mode(profile.transport.mode,profile.transport.endpoint.version,profile.up.reality.has_value(),profile.down.has_value())) {}
            ~HttpStream() {cancel();}
        private:
            auto start_impl(Clock::time_point until) -> nex::capy::task<bool> {
                if (mode_==xhttp::Mode::stream_one) {
                    up_=co_await worker_->up.acquire(session_,profile_.up,profile_.bootstrap,options_,until);
                    if (!up_ || stopped_ || !up_.request()) co_return false;
                    upload_=co_await open(up_,profile_.up,xhttp::RequestKind::stream,{{},false},until);
                    download_=upload_;
                    co_return upload_.has_value() && !stopped_;
                }
                std::array<std::uint8_t,16> random;
                if (!crypto::random_bytes(random)) co_return false;
                id_=xhttp::session_id(random);
                auto const& peer=profile_.down ? *profile_.down : profile_.up;
                down_=co_await worker_->down.acquire(session_,peer,profile_.bootstrap,options_,until);
                if (!down_ || stopped_ || !down_.request()) co_return false;
                download_=co_await open(down_,peer,xhttp::RequestKind::download,{},until);
                if (!download_ || stopped_) co_return false;
                if (mode_==xhttp::Mode::packet_up) co_return true;
                up_=co_await worker_->up.acquire(session_,profile_.up,profile_.bootstrap,options_,until);
                if (!up_ || stopped_ || !up_.request()) co_return false;
                upload_=co_await open(up_,profile_.up,xhttp::RequestKind::upload,{{},false},until);
                co_return upload_.has_value() && !stopped_;
            }
        public:
            auto start(Clock::time_point until) -> nex::capy::task<bool> {
                co_return co_await boost::capy::run(stop_.get_token())(start_impl(until));
            }
            auto read(std::span<std::uint8_t> output,Deadline until={})
                -> nex::capy::task<std::expected<std::size_t,IoError>> {
                if (!download_ || stopped_) co_return std::unexpected(IoError::state);
                co_return co_await downlink()->read(*download_,output,until);
            }
        private:
            auto send_impl(std::span<std::uint8_t const> input,Deadline until) -> nex::capy::task<bool> {
                if (stopped_ || output_closed_) co_return false;
                bool ok=true;
                if (upload_) ok=co_await up_->transmit(*upload_,{input,false},until);
                else while (!input.empty()) {
                    auto size=std::min(profile_.transport.limits.post_bytes,input.size());
                    auto stop=until.value_or(Clock::now()+std::chrono::milliseconds(profile_.timeout));
                    if (!co_await packet(input.first(size),stop)) {ok=false;break;}
                    input=input.subspan(size);
                }
                if (!ok) cancel();
                co_return ok;
            }
        public:
            auto send(std::span<std::uint8_t const> input,Deadline until={}) -> nex::capy::task<bool> {
                co_return co_await boost::capy::run(stop_.get_token())(send_impl(input,until));
            }
            auto close_output(Deadline until={}) -> nex::capy::task<bool> {
                if (stopped_) co_return false;
                if (output_closed_) co_return true;
                output_closed_=true;
                if (!upload_) co_return true;
                co_return co_await up_->transmit(*upload_,{{},true},until);
            }
            auto cancel() noexcept -> void {
                stopped_=true;
                stop_.request_stop();
                auto download=std::exchange(download_,{});
                auto upload=std::exchange(upload_,{});
                if (download) downlink()->release(*download);
                if (upload && upload!=download) up_->release(*upload);
            }
        };
