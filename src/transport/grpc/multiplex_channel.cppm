export module grpc.multiplex_channel;
import std;
import grpc.multiplex;
import grpc.session;
import grpc.stream_operations;
import grpc.stream;
import http2.driver;
import net.socket_stream;
import capy;

export namespace grpc {
    namespace detail {
        template<std::size_t Capacity,class ReadPolicy>
        struct MultiplexDriverPolicy {
            using Failure=grpc::Failure;
            static constexpr bool host_cancels=true;
            static auto canceled_failure() noexcept -> Failure{return {Error::canceled};}
            static auto transport_failure(bool timeout) noexcept -> Failure{return {timeout?Error::timeout:Error::transport};}
            static auto protocol_failure() noexcept -> Failure{return {Error::http2};}
            static auto input_complete(MultiplexSession<Capacity> const& session) noexcept -> bool{return session.transport_ended();}
            static auto finish_after_drain(MultiplexSession<Capacity> const& session) noexcept -> bool{return session.transport_ended();}
            template<class Driver>static auto before_close(Driver& driver) noexcept -> void requires requires {ReadPolicy::close_deadline();} {
                driver.shorten(ReadPolicy::close_deadline());
            }
            template<class Driver>static auto after_receive(Driver&) noexcept -> void{}
            template<class Driver>static auto after_write(Driver& driver) noexcept -> void{driver.protocol().written();}
        };
    }
    template<class Lower,std::size_t Capacity=16,class ReadPolicy=detail::ReadFailurePolicy>
    class MultiplexChannel {
        using Driver=http2::detail::Driver<Lower,MultiplexSession<Capacity>,detail::MultiplexDriverPolicy<Capacity,ReadPolicy>>;
        Driver driver_;
    public:
        class Stream : public detail::StreamOperations<Stream,ReadPolicy> {
            friend class detail::StreamOperations<Stream,ReadPolicy>;
            MultiplexChannel& connection_;
            RpcTicket ticket_;
            Deadline deadline_;
            bool reading_=false,read_end_=false,write_end_=false;
            capy::async_mutex writer_;
            struct View {
                MultiplexSession<Capacity>& session;RpcTicket ticket;
                auto ready() const noexcept -> bool{return session.ready(ticket);}
                auto local_ended() const noexcept -> bool{return session.local_ended(ticket);}
                auto queued_bytes() const noexcept -> std::size_t{return session.queued_bytes(ticket);}
                auto uncredited_bytes() const noexcept -> std::size_t{return session.uncredited_bytes(ticket);}
                auto max_payload() const noexcept -> std::size_t{return session.max_payload(ticket);}
                auto pull(std::span<std::uint8_t> bytes){return session.pull(ticket,bytes);}
                auto queue(std::span<std::uint8_t const> bytes){return session.queue(ticket,bytes);}
                auto close_output(std::uint32_t status){return session.close_output(ticket,status);}
            };
            auto protocol() noexcept -> View{return {connection_.driver_.protocol(),ticket_};}
            static auto expired(Deadline deadline) noexcept -> bool{return Driver::expired(deadline);}
            auto canceled() const noexcept -> bool{return connection_.driver_.canceled()||connection_.driver_.protocol().rpc_failure(ticket_).has_value();}
            auto limit(Deadline deadline) const noexcept -> Deadline {
                auto connection=connection_.driver_.limit(deadline);
                if(!deadline_)return connection;if(!connection)return deadline_;return std::min(*deadline_,*connection);
            }
            auto stop(Failure reason) noexcept -> void{(void)connection_.driver_.protocol().reset(ticket_,reason);connection_.driver_.wake();}
            auto wake() noexcept -> void{connection_.driver_.wake();}
            auto failed() const noexcept -> Failure{return connection_.driver_.protocol().rpc_failure(ticket_).value_or(connection_.driver_.failed());}
            auto output_drained() const noexcept -> bool{return connection_.driver_.protocol().output_drained(ticket_);}
            auto wait(Deadline deadline){return connection_.driver_.wait_change(limit(deadline));}
            auto wait_failed(Deadline deadline) noexcept -> void{stop({expired(limit(deadline))?Error::timeout:Error::canceled});}
            auto read_ended() noexcept -> void{read_end_=true;}
            auto write_ended() noexcept -> void{write_end_=true;}
        public:
            Stream(MultiplexChannel& connection,RpcTicket ticket,Deadline deadline={}) noexcept
                :connection_(connection),ticket_(ticket),deadline_(connection.driver_.limit(deadline)){
                if(auto peer=connection.driver_.protocol().peer_deadline(ticket))deadline_=deadline_?std::min(*deadline_,*peer):*peer;
            }
            Stream(Stream const&)=delete;
            auto operator=(Stream const&) -> Stream& = delete;
            ~Stream(){connection_.driver_.protocol().return_ticket(ticket_);wake();}
            auto cancel(Failure reason={Error::canceled}) noexcept -> void{if(!complete())stop(reason);}
            auto failure() const noexcept -> std::optional<Failure>{
                auto local=connection_.driver_.protocol().rpc_failure(ticket_);
                return local?local:connection_.driver_.failure();
            }
            auto complete() const noexcept -> bool{return read_end_&&write_end_&&connection_.driver_.protocol().rpc_complete(ticket_);}
            auto ticket() const noexcept -> RpcTicket{return ticket_;}
        };
        MultiplexChannel(Lower& lower,std::unique_ptr<MultiplexSession<Capacity>> session,Deadline deadline={})
            :driver_(lower,std::move(session),deadline){}
        MultiplexChannel(MultiplexChannel const&)=delete;
        auto operator=(MultiplexChannel const&) -> MultiplexChannel& = delete;
        ~MultiplexChannel(){cancel();}
        auto run(){return driver_.run();}
        auto cancel() noexcept -> void{driver_.cancel();}
        auto drained() const noexcept -> bool{return driver_.drained();}
        auto finished() const noexcept -> bool{return driver_.finished();}
        auto failure() const noexcept -> std::optional<Failure>{return driver_.failure();}
        auto transport_ended() const noexcept -> bool{return driver_.protocol().transport_ended();}
        auto open(){auto value=driver_.protocol().open();driver_.wake();return value;}
        auto available() noexcept -> bool{return !driver_.canceled()&&!driver_.finished()&&driver_.protocol().available();}
        auto accepting() const noexcept -> bool{return !driver_.canceled()&&!driver_.finished()&&driver_.protocol().accepting();}
        auto accept() noexcept -> std::optional<RpcTicket>{return driver_.protocol().accept();}
        auto wait_change(Deadline deadline={}){return driver_.wait_change(deadline);}
        auto shutdown(){auto value=driver_.protocol().shutdown();driver_.wake();return value;}
    };
}
