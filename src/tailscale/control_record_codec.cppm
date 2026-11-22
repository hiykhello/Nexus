export module tailscale.control_record_codec;
import std;
import tailscale.control;
import net.framed_stream;

export namespace tailscale::control {
    class RecordCodec {
        Records records_;
    public:
        using Error=control::Error;
        static constexpr std::size_t max_wire=max_record_wire,max_plaintext=max_record_plaintext,header_size=record_header_size;
        auto install(TransportKeys&& keys) noexcept -> std::expected<void,Error> {return records_.install(std::move(keys));}
        auto inspect(std::span<std::uint8_t const> header) const noexcept -> std::expected<std::size_t,Error> {
            if (header.size()!=record_header_size || header[0]!=4) return std::unexpected(Error::framing);
            auto size=(std::size_t(header[1])<<8)|header[2];
            if (size<16 || size>max_record_ciphertext) return std::unexpected(Error::framing);
            return record_header_size+size;
        }
        auto open(std::span<std::uint8_t> wire) noexcept -> std::expected<net::PlainRegion,Error> {
            auto result=records_.open_to(wire.subspan(record_header_size),wire);
            if (!result) return std::unexpected(result.error());return net::PlainRegion{record_header_size,*result};
        }
        auto seal(std::span<std::uint8_t> wire,std::span<std::uint8_t const> plain) noexcept -> std::expected<std::size_t,Error> {return records_.seal_to(wire,plain);}
        auto sent() noexcept -> std::expected<void,Error> {return records_.sent();}
        auto fail_send() noexcept -> void {records_.fail_send();}
        auto fail_receive() noexcept -> void {records_.fail_receive();}
        auto cancel() noexcept -> void {records_.cancel();}
        auto send_alive() const noexcept -> bool {return records_.send_alive();}
        auto receive_alive() const noexcept -> bool {return records_.receive_alive();}
        auto send_pending() const noexcept -> bool {return records_.send_pending();}
    };
}
