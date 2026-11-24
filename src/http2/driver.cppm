export module http2.driver;
import std;
import net.socket_stream;
import capy;
import corosio;

export namespace http2::detail {
    using DriverClock=std::chrono::steady_clock;
    using DriverDeadline=net::StreamDeadline;
    // One concrete protocol owner and one lower reader/writer. Policy is direct
    // compile-time state; existing application locks stay in their host.
    template<class Lower,class Protocol,class Policy>
    class Driver {
    public:
        using Failure=typename Policy::Failure;
        static constexpr std::size_t input_bytes=16640,output_bytes=16384;
    private:
        Lower& lower_;
        std::unique_ptr<Protocol> protocol_;
        capy::async_event changed_,work_;
        DriverDeadline deadline_;
        std::optional<Failure> failure_;
        [[no_unique_address]] Policy policy_;
        bool started_=false,running_=false,finished_=false,canceled_=false,drained_=false,output_closed_=false;
        struct ReaderGuard {
            Driver& owner;bool released=false;
            ~ReaderGuard(){if(!released)owner.cancel();}
        };
        struct RunGuard {
            Driver& owner;
            ~RunGuard(){owner.running_=false;if(!owner.finished_)owner.cancel();}
        };
        auto input_complete() const noexcept -> bool{return policy_.input_complete(*protocol_);}
        auto reader() -> capy::task<capy::results<>> {
            ReaderGuard guard{*this};std::array<std::uint8_t,input_bytes> input{};std::size_t discarded=0;bool peer_eof=false;
            while(!canceled_&&!finished_){
                if(input_complete())break;
                auto received=co_await lower_.read(input,deadline_);
                if(finished_||canceled_)break;
                if(input_complete()){
                    if(received){
                        if(*received>input.size()){stop(policy_.protocol_failure());break;}
                        discarded=*received;peer_eof=!*received;
                    }
                    break;
                }
                if(!received||*received>input.size()||expired(deadline_)){
                    if constexpr(requires{policy_.read_failure(received.error(),expired(deadline_));}){
                        if(!received)stop(policy_.read_failure(received.error(),expired(deadline_)));else stop(policy_.transport_failure(expired(deadline_)));
                    }else stop(policy_.transport_failure(expired(deadline_)));break;
                }
                if(!*received){
                    auto ended=protocol_->finish_input();if(!ended){stop(ended.error());break;}
                    peer_eof=true;changed_.set();wake();
                    while(!input_complete()&&!canceled_){changed_.clear();if(!co_await wait(changed_,{}))break;}
                    break;
                }
                std::span<std::uint8_t const> pending=std::span(input).first(*received);
                while(!pending.empty()){
                    auto consumed=protocol_->receive(pending);
                    if(!consumed||!*consumed||*consumed>pending.size()){
                        stop(consumed?policy_.protocol_failure():consumed.error());break;
                    }
                    pending=pending.subspan(*consumed);
                }
                if(!canceled_&&!finished_){policy_.after_receive(*this);changed_.set();wake();}
            }
            // Keep the original reader and its array. An already-pending read
            // that completes after terminal state belongs to this same cap.
            if(!canceled_&&!finished_&&input_complete()){
                while(!output_closed_&&!canceled_){changed_.clear();if(!co_await wait(changed_,{}))break;}
                if(peer_eof&&!canceled_){finished_=true;changed_.set();work_.set();}
                while(!canceled_&&!finished_){
                    auto received=co_await lower_.read(input,deadline_);
                    if(!received||*received>input.size()||expired(deadline_)){
                        if constexpr(requires{policy_.read_failure(received.error(),expired(deadline_));}){
                            if(!received)stop(policy_.read_failure(received.error(),expired(deadline_)));else stop(policy_.transport_failure(expired(deadline_)));
                        }else stop(policy_.transport_failure(expired(deadline_)));break;
                    }
                    if(!*received){finished_=true;changed_.set();work_.set();break;}
                    if(*received>65536-discarded){stop(policy_.protocol_failure());break;}
                    discarded+=*received;
                }
            }
            guard.released=true;
            co_return capy::results<>{canceled_?std::make_error_code(std::errc::io_error):std::error_code{}};
        }
        auto flush() -> capy::task<capy::results<>> {
            ReaderGuard guard{*this};std::array<std::uint8_t,output_bytes> output{};
            while(!canceled_&&!finished_){
                if(expired(deadline_)){stop(policy_.transport_failure(true));break;}
                if constexpr(requires{policy_.output_failure(*protocol_);})
                    if(auto failure=policy_.output_failure(*protocol_)){stop(*failure);break;}
                auto size=protocol_->output(output);if(!size){stop(size.error());break;}
                if(*size){
                    drained_=false;
                    if(!co_await lower_.send(std::span(output).first(*size),deadline_)||expired(deadline_)){
                        stop(policy_.transport_failure(expired(deadline_)));break;
                    }
                    if constexpr(requires{policy_.after_write(*this);})policy_.after_write(*this);
                    changed_.set();continue;
                }
                drained_=true;changed_.set();
                if(policy_.finish_after_drain(*protocol_)){
                    if constexpr(requires{policy_.before_close(*this);})policy_.before_close(*this);
                    // Kernel write completion is not peer delivery. Preserve
                    // the receiving half while FIN/close_notify and queued
                    // application records reach the peer, using one budget.
                    if(!co_await lower_.close_output(deadline_)||expired(deadline_)){
                        stop(policy_.transport_failure(expired(deadline_)));break;
                    }
                    output_closed_=true;changed_.set();
                    while(!finished_&&!canceled_){changed_.clear();if(!co_await wait(changed_,{}))break;}
                    break;
                }
                work_.clear();if(!co_await wait(work_,{}))break;
            }
            guard.released=true;
            co_return capy::results<>{canceled_?std::make_error_code(std::errc::io_error):std::error_code{}};
        }
    public:
        Driver(Lower& lower,std::unique_ptr<Protocol> protocol,DriverDeadline deadline={})
            :lower_(lower),protocol_(std::move(protocol)),deadline_(deadline){if(!protocol_)throw std::invalid_argument("HTTP2 driver requires a session");}
        Driver(Driver const&)=delete;
        auto operator=(Driver const&) -> Driver& = delete;
        ~Driver(){if constexpr(requires{Policy::host_cancels;}){if constexpr(!Policy::host_cancels)cancel();}else cancel();}
        auto protocol() noexcept -> Protocol&{return *protocol_;}
        auto protocol() const noexcept -> Protocol const&{return *protocol_;}
        auto changed() noexcept -> capy::async_event&{return changed_;}
        auto limit(DriverDeadline requested={}) const noexcept -> DriverDeadline {
            if(!deadline_)return requested;if(!requested)return deadline_;return std::min(*deadline_,*requested);
        }
        auto shorten(DriverDeadline value) noexcept -> void{deadline_=limit(value);}
        static auto expired(DriverDeadline deadline) noexcept -> bool{return deadline&&DriverClock::now()>=*deadline;}
        auto stop(Failure error) noexcept -> void {
            if(!failure_)failure_=protocol_->failure().value_or(error);
            canceled_=true;lower_.cancel();changed_.set();work_.set();
            if constexpr(requires{policy_.on_stop(*protocol_,*failure_);})policy_.on_stop(*protocol_,*failure_);
        }
        auto failed() const noexcept -> Failure{return failure_.value_or(protocol_->failure().value_or(policy_.canceled_failure()));}
        auto canceled() const noexcept -> bool{return canceled_;}
        auto finished() const noexcept -> bool{return finished_;}
        auto drained() const noexcept -> bool{return !running_;}
        auto output_drained() const noexcept -> bool{return drained_;}
        auto failure() const noexcept -> std::optional<Failure>{return failure_?failure_:protocol_->failure();}
        auto wake() noexcept -> void{drained_=false;work_.set();}
        auto cancel() noexcept -> void{
            if(!finished_&&!canceled_)stop(policy_.canceled_failure());
        }
        template<bool Clear=false,bool Local=false>
        auto wait(capy::async_event& event,DriverDeadline requested) -> capy::task<bool> {
            if constexpr(Local)if(canceled_||finished_)co_return false;
            if constexpr(Clear)event.clear();
            auto deadline=limit(requested);auto operation=event.wait();
            auto [error]=deadline?co_await corosio::timeout(std::move(operation),*deadline):co_await std::move(operation);
            if(error||expired(deadline)){
                if constexpr(!Local)stop(expired(deadline)?policy_.transport_failure(true):policy_.canceled_failure());co_return false;
            }co_return !canceled_;
        }
        // A notification waiter owns no stream. Its timeout/stop only ends
        // this wait; its caller resets/releases its own ticket if appropriate.
        auto wait_change(DriverDeadline deadline={}) {return wait<true,true>(changed_,deadline);}
        auto run() -> capy::task<capy::results<>> {
            if(started_||canceled_)co_return capy::results<>{std::make_error_code(std::errc::operation_canceled)};
            started_=running_=true;RunGuard guard{*this};
            auto [error,input,output]=co_await capy::when_all(reader(),flush());(void)input;(void)output;
            co_return capy::results<>{canceled_&&!error?std::make_error_code(std::errc::io_error):error};
        }
    };
}
