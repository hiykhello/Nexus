export module http2.client_channel;
import std;
export import http2.client;
import http2.driver;
import nghttp2;
import capy;

export namespace http2 {
    using ChannelDeadline=std::optional<std::chrono::steady_clock::time_point>;
    namespace detail {
        template<std::size_t Capacity>
        struct ClientDriverPolicy {
            using Failure=ClientFailure;
            static auto canceled_failure() noexcept -> Failure{return {ClientError::canceled};}
            static auto transport_failure(bool timeout) noexcept -> Failure{return {timeout?ClientError::timeout:ClientError::transport};}
            static auto protocol_failure() noexcept -> Failure{return {ClientError::http2};}
            template<class Error>static auto read_failure(Error const& error,bool timeout) noexcept -> Failure{
                if(timeout)return {ClientError::timeout};
                if constexpr(requires{error==capy::make_error_condition(capy::cond::canceled);})
                    if(error==capy::make_error_condition(capy::cond::canceled))return canceled_failure();
                if constexpr(requires{error==std::errc::operation_canceled;})if(error==std::errc::operation_canceled)return canceled_failure();
                return {ClientError::transport};
            }
            static auto input_complete(Client<Capacity> const& client) noexcept -> bool{return client.draining()&&client.all_closed()&&!client.failure();}
            static auto finish_after_drain(Client<Capacity> const& client) noexcept -> bool{return input_complete(client);}
            static auto output_failure(Client<Capacity> const& client) noexcept -> std::optional<Failure>{return client.failure();}
            static auto on_stop(Client<Capacity>& client,Failure reason) noexcept -> void{client.cancel(reason);}
            template<class Driver>static auto after_receive(Driver&) noexcept -> void{}
        };
    }
    // run() owns the only lower reader/writer. Application tasks use synchronous
    // ticket operations between awaits, then await a shared change notification.
    template<class Lower,std::size_t Capacity=16>
    class ClientChannel {
        using Driver=detail::Driver<Lower,Client<Capacity>,detail::ClientDriverPolicy<Capacity>>;
        Driver driver_;
        template<class Result>auto changed(Result result){driver_.wake();return result;}
    public:
        // The caller reserves these lower plaintext buffers in its shared
        // transport budget, alongside this object and coroutine overhead.
        static constexpr std::size_t transport_buffer_bytes=Driver::input_bytes+Driver::output_bytes;
        ClientChannel(Lower& lower,std::unique_ptr<Client<Capacity>> client,ChannelDeadline deadline={})
            :driver_(lower,std::move(client),deadline){}
        ClientChannel(ClientChannel const&)=delete;
        auto operator=(ClientChannel const&) -> ClientChannel& = delete;
        auto run(){return driver_.run();}
        auto wait_change(ChannelDeadline deadline={}){return driver_.wait_change(deadline);}
        auto notify_waiters() noexcept -> void {driver_.changed().set();}
        auto cancel() noexcept -> void{driver_.cancel();}
        auto finished() const noexcept -> bool{return driver_.finished();}
        auto drained() const noexcept -> bool{return driver_.drained();}
        auto failure() const noexcept -> std::optional<ClientFailure>{return driver_.failure();}
        auto goaway() const noexcept -> std::optional<Goaway>{return driver_.protocol().goaway();}
        auto submit(std::span<FieldView const> fields,BodyView body={}) {
            auto result=driver_.protocol().submit(fields,body);
            if (result || driver_.protocol().failure()) driver_.wake();
            return result;
        }
        auto provide(StreamTicket ticket,BodyView body){auto result=driver_.protocol().provide(ticket,body);if(!result||*result)driver_.wake();return result;}
        auto consume(StreamTicket ticket,std::size_t count){auto result=driver_.protocol().consume(ticket,count);if(count||!result)driver_.wake();return result;}
        auto reset(StreamTicket ticket,std::uint32_t code=nghttp2::NGHTTP2_CANCEL){return changed(driver_.protocol().reset(ticket,code));}
        auto release(StreamTicket ticket){return changed(driver_.protocol().release(ticket));}
        auto shutdown(){return changed(driver_.protocol().shutdown());}
        auto tx_consumed(StreamTicket ticket){return driver_.protocol().tx_consumed(ticket);}
        auto response(StreamTicket ticket){return driver_.protocol().response(ticket);}
        auto peek(StreamTicket ticket){return driver_.protocol().peek(ticket);}
    };
}
