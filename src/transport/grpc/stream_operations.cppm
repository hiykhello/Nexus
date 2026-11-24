export module grpc.stream_operations;
import std;
import grpc.session;
import net.socket_stream;
import capy;
import corosio;

export namespace grpc::detail {
    using Deadline=net::StreamDeadline;
    template<class Host,class ReadPolicy>
    class StreamOperations {
        auto host() noexcept -> Host& {return static_cast<Host&>(*this);}
        struct OperationGuard{StreamOperations& owner;bool released=false;~OperationGuard(){if(!released)owner.host().cancel();}};
        struct ReaderGuard{bool& reading;~ReaderGuard(){reading=false;}};
        auto wait_output(bool closing,Deadline deadline) -> capy::task<bool> {
            while(!host().canceled()){
                if(host().output_drained()&&!host().protocol().queued_bytes()&&(!closing||host().protocol().local_ended()))co_return true;
                if(!co_await host().wait(deadline)){host().wait_failed(deadline);break;}
            }co_return false;
        }
    public:
        auto accept(Deadline deadline={}) -> capy::task<std::expected<void,Failure>> {
            OperationGuard guard{*this};
            while(!host().canceled()){
                if(Host::expired(host().limit(deadline))){host().stop({Error::timeout});break;}
                if(host().protocol().ready()){guard.released=true;co_return std::expected<void,Failure>{};}
                if(!co_await host().wait(deadline)){host().wait_failed(deadline);break;}
            }co_return std::unexpected(host().failed());
        }
        auto read(std::span<std::uint8_t> output,Deadline deadline={}) -> capy::task<std::expected<std::size_t,typename ReadPolicy::Error>> {
            if(host().reading_)co_return std::unexpected(ReadPolicy::convert(Failure{Error::state}));
            OperationGuard guard{*this};host().reading_=true;ReaderGuard reader_guard{host().reading_};
            while(!host().canceled()){
                if(Host::expired(host().limit(deadline))){host().stop({Error::timeout});break;}
                auto uncredited=host().protocol().uncredited_bytes();auto pulled=host().protocol().pull(output);
                if(!pulled){host().stop(pulled.error());break;}
                if(host().protocol().uncredited_bytes()<uncredited)host().wake();
                if(pulled->size||pulled->eof||output.empty()){
                    if constexpr(requires{host().read_ended();})if(pulled->eof)host().read_ended();
                    guard.released=true;co_return pulled->size;
                }
                if(!co_await host().wait(deadline)){host().wait_failed(deadline);break;}
            }co_return std::unexpected(ReadPolicy::convert(host().failed()));
        }
        auto send(std::span<std::uint8_t const> input,Deadline deadline={}) -> capy::task<bool> {
            OperationGuard guard{*this};auto absolute=host().limit(deadline);auto operation=host().writer_.scoped_lock();
            auto [error,lock]=absolute?co_await corosio::timeout(std::move(operation),*absolute):co_await std::move(operation);
            if(error||host().canceled()||Host::expired(absolute)){host().stop({Host::expired(absolute)?Error::timeout:Error::canceled});co_return false;}
            while(!input.empty()){
                auto limit=host().protocol().max_payload();
                if(!limit){host().stop({Error::limit});co_return false;}
                auto size=std::min(input.size(),limit);auto queued=host().protocol().queue(input.first(size));
                if(!queued){host().stop(queued.error());co_return false;}
                host().wake();if(!co_await wait_output(false,deadline))co_return false;if(*queued)input=input.subspan(size);
            }guard.released=true;co_return true;
        }
        auto close_output(Deadline deadline={},std::uint32_t status=0) -> capy::task<bool> {
            OperationGuard guard{*this};auto absolute=host().limit(deadline);auto operation=host().writer_.scoped_lock();
            auto [error,lock]=absolute?co_await corosio::timeout(std::move(operation),*absolute):co_await std::move(operation);
            if(error||host().canceled()||Host::expired(absolute)){host().stop({Host::expired(absolute)?Error::timeout:Error::canceled});co_return false;}
            auto closed=host().protocol().close_output(status);if(!closed){host().stop(closed.error());co_return false;}
            host().wake();if(!co_await wait_output(true,deadline))co_return false;
            if constexpr(requires{host().write_ended();})host().write_ended();
            guard.released=true;co_return true;
        }
    };
}
