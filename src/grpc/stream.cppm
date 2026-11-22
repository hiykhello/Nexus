export module grpc.stream;
import std;
import grpc.session;
import grpc.stream_operations;
import http2.driver;
import net.socket_stream;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace grpc {
    using Clock=std::chrono::steady_clock;
    using Deadline=net::StreamDeadline;
    namespace detail {
        struct ReadFailurePolicy {
            using Error=Failure;
            static auto convert(Failure error) noexcept -> Error {return error;}
        };
        template<class ReadPolicy>
        struct DriverPolicy {
            using Failure=grpc::Failure;
            static constexpr bool host_cancels=true;
            bool peer_budget_applied=false;
            static auto canceled_failure() noexcept -> Failure{return {Error::canceled};}
            static auto transport_failure(bool timeout) noexcept -> Failure{return {timeout?Error::timeout:Error::transport};}
            static auto protocol_failure() noexcept -> Failure{return {Error::http2};}
            static auto input_complete(Session const& session) noexcept -> bool{return session.transport_ended();}
            static auto finish_after_drain(Session const& session) noexcept -> bool{return session.transport_ended();}
            template<class Driver>auto before_close(Driver& driver) noexcept -> void requires requires {ReadPolicy::close_deadline();} {
                driver.shorten(ReadPolicy::close_deadline());
            }
            template<class Driver>auto after_receive(Driver& driver) noexcept -> void{
                auto& session=driver.protocol();if(peer_budget_applied||!session.ready())return;peer_budget_applied=true;
                if(auto budget=session.peer_timeout()){
                    auto now=Clock::now();auto remaining=Clock::time_point::max()-now;
                    driver.shorten(*budget>=remaining?Clock::time_point::max():now+*budget);
                }
            }
        };
    }
    // Error conversion is selected statically inside the original read task.
    // Consumers can reuse that task without an adapting coroutine or owner.
    template<class Lower,class ReadPolicy=detail::ReadFailurePolicy>
    class Channel : public detail::StreamOperations<Channel<Lower,ReadPolicy>,ReadPolicy> {
        friend class detail::StreamOperations<Channel<Lower,ReadPolicy>,ReadPolicy>;
        using Driver=http2::detail::Driver<Lower,Session,detail::DriverPolicy<ReadPolicy>>;
        [[no_unique_address]] Driver driver_;
        bool reading_=false;
        nex::capy::async_mutex writer_;
        static auto expired(Deadline deadline) noexcept -> bool{return Driver::expired(deadline);}
        auto protocol() noexcept -> Session& {return driver_.protocol();}
        auto canceled() const noexcept -> bool{return driver_.canceled();}
        auto limit(Deadline deadline) const noexcept -> Deadline{return driver_.limit(deadline);}
        auto stop(Failure reason) noexcept -> void{driver_.stop(reason);}
        auto wake() noexcept -> void{driver_.wake();}
        auto failed() const noexcept -> Failure{return driver_.failed();}
        auto output_drained() const noexcept -> bool{return driver_.output_drained();}
        auto wait_failed(Deadline) noexcept -> void{}
        auto wait(Deadline deadline){driver_.changed().clear();return driver_.wait(driver_.changed(),deadline);}
    public:
        Channel(Lower& lower,std::unique_ptr<Session> protocol,Deadline deadline={}):driver_(lower,std::move(protocol),deadline){}
        Channel(Channel const&)=delete;
        auto operator=(Channel const&) -> Channel& = delete;
        ~Channel(){cancel();}
        auto cancel() noexcept -> void{driver_.cancel();}
        auto drained() const noexcept -> bool{return driver_.drained();}
        auto finished() const noexcept -> bool{return driver_.finished();}
        auto failure() const noexcept -> std::optional<Failure>{return driver_.failure();}
        auto transport_ended() const noexcept -> bool{return driver_.protocol().transport_ended();}
        auto remote_status() const noexcept -> std::optional<std::uint32_t>{return driver_.protocol().remote_status();}
        auto run(){return driver_.run();}
        auto retire_connection() noexcept -> std::expected<void,Failure> {
            auto result=driver_.protocol().retire_connection();
            if (!result) {driver_.stop(result.error());return result;}
            driver_.wake();return {};
        }
    };
}
