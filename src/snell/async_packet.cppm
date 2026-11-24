export module snell.async_packet;
import std;
import snell.record;
import snell.packet;
import snell.async_record;
import capy;
export namespace snell {
    // A session operates after request/accept and an authenticated tunnel reply.
    // The caller owns peer validation, forwarding, salt replay and lifetime.
    template<class Channel> class AsyncPacket {
        Channel& channel_;bool client_,reading_=false,writing_=false,closed_=false;
    public:
        AsyncPacket(Channel& channel,bool client):channel_(channel),client_(client){}
        AsyncPacket(AsyncPacket const&)=delete;auto operator=(AsyncPacket const&) -> AsyncPacket& =delete;
        auto cancel() noexcept -> void {closed_=true;channel_.cancel();}
        auto send(Packet const& packet,View padding,Deadline deadline)->capy::task<std::expected<void,IoError>> {
            if(closed_ || writing_)co_return std::unexpected(IoError::state);
            auto frame=encode_packet(packet,client_);if(!frame)co_return std::unexpected(IoError::record);
            writing_=true;struct Guard{AsyncPacket& p;bool done=false;~Guard(){p.writing_=false;if(!done)p.cancel();}} guard{*this};
            auto result=co_await channel_.send(*frame,padding,deadline);if(!result){cancel();co_return std::unexpected(result.error());}
            guard.done=true;co_return std::expected<void,IoError>{};
        }
        auto receive(Deadline deadline)->capy::task<std::expected<Packet,IoError>> {
            if(closed_ || reading_)co_return std::unexpected(IoError::state);
            reading_=true;struct Guard{AsyncPacket& p;bool done=false;~Guard(){p.reading_=false;if(!done)p.cancel();}} guard{*this};
            auto record=co_await channel_.receive(deadline);if(!record)co_return std::unexpected(record.error());
            if(record->empty())co_return std::unexpected(IoError::truncated);
            auto packet=parse_packet(*record,!client_);if(!packet)co_return std::unexpected(IoError::record);
            guard.done=true;co_return std::move(*packet);
        }
    };
}
