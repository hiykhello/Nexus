export module snell.server_reply;
import std;
import crypto;
import snell.record;
import snell.kdf;
import snell.cipher;
import snell.async_record;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
export namespace snell {
    // Invoke only after destination/UDP association has been admitted. Returned
    // writer retains nonce state after the acknowledgement record.
    template<class Socket>
    auto server_reply(Socket& socket,View psk,Deadline deadline)->nex::capy::task<std::expected<Record<Cipher>,IoError>> {
        struct Guard {Socket& s;bool done=false;~Guard(){if(!done)s.cancel();}} guard{socket};
        if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
        std::array<std::uint8_t,16> salt{};std::array<std::uint8_t,1> choice{};
        if(!crypto::random_bytes(salt)||!crypto::random_bytes(choice))co_return std::unexpected(IoError::record);
        auto key=Key::derive(psk,salt);if(!key)co_return std::unexpected(IoError::record);
        Record<Cipher> writer{Cipher(std::move(*key))};Bytes padding(256+choice[0]);
        if(!crypto::random_bytes(padding))co_return std::unexpected(IoError::record);
        auto frame=writer.encode(Bytes{0},padding);if(!frame)co_return std::unexpected(IoError::record);
        Bytes wire(salt.begin(),salt.end());wire.insert(wire.end(),frame->begin(),frame->end());std::size_t off=0;
        while(off<wire.size()){
            if(std::chrono::steady_clock::now()>=deadline)co_return std::unexpected(IoError::timeout);
            auto op=socket.write_some(nex::capy::const_buffer(wire.data()+off,wire.size()-off));
            auto [ec,n]=co_await nex::corosio::timeout(std::move(op),deadline);
            if(nex::capy::is_timeout(ec)||(!ec && std::chrono::steady_clock::now()>=deadline))co_return std::unexpected(IoError::timeout);
            if(ec||!n||n>wire.size()-off)co_return std::unexpected(IoError::transport);off+=n;
        }
        guard.done=true;co_return std::move(writer);
    }
}
