export module quic.retry_packet;
import std;
import crypto;
import crypto.aead_context;
import quic.packet_protection;
import ngtcp2;

export namespace quic {
    // Native ngtcp2 remains the only QUIC Retry packet serializer. This
    // concrete integrity slot shares the existing packet encryption callback
    // and the unique RFC9001 fixed-key initializer with the client verifier.
    class RetryPacketWriter {
        crypto::AeadContext integrity_;
        static auto overlaps(std::span<std::uint8_t> output,std::span<std::uint8_t const> input) noexcept -> bool {
            if(output.empty() || input.empty())return false;
            auto a=reinterpret_cast<std::uintptr_t>(output.data()),b=reinterpret_cast<std::uintptr_t>(input.data());
            return a<=b ? b-a<output.size() : a-b<input.size();
        }
    public:
        RetryPacketWriter()=default;
        RetryPacketWriter(RetryPacketWriter const&)=delete;
        auto operator=(RetryPacketWriter const&) -> RetryPacketWriter& = delete;
        auto initialize() noexcept -> std::expected<void,int> {
            auto error=initialize_retry_cipher(integrity_);
            return error ? std::expected<void,int>(std::unexpected(error)) : std::expected<void,int>{};
        }
        auto clear() noexcept -> void {integrity_.clear();}
        auto valid() const noexcept -> bool {return integrity_.valid();}
        auto write(std::span<std::uint8_t> output,std::span<std::uint8_t const> destination,std::span<std::uint8_t const> source,
            std::span<std::uint8_t const> original,std::span<std::uint8_t const> token,std::uint32_t version=1) noexcept -> std::expected<std::size_t,int> {
            namespace n = ::ngtcp2;
            // The bounded token keeps even maximal CIDs below the minimum
            // 1200-byte QUIC path size; no Retry output needs UDP fragmentation.
            if(!integrity_.valid() || version!=1 || destination.size()>20 || source.size()<8 || source.size()>20 || original.size()<8 || original.size()>20 ||
                crypto::constant_time_equal(source,original) || token.empty() || token.size()>1024 || overlaps(output,token))
                return std::unexpected(n::err_invalid_argument);
            n::ngtcp2_cid dcid{},scid{},odcid{};
            n::ngtcp2_cid_init(&dcid,destination.data(),destination.size());n::ngtcp2_cid_init(&scid,source.data(),source.size());n::ngtcp2_cid_init(&odcid,original.data(),original.size());
            n::ngtcp2_crypto_aead aead{nullptr,16};n::ngtcp2_crypto_aead_ctx context{&integrity_};
            auto size=n::ngtcp2_pkt_write_retry(output.data(),output.size(),version,&dcid,&scid,&odcid,token.data(),token.size(),PacketProtection<>::encrypt,&aead,&context);
            return size<0 ? std::expected<std::size_t,int>(std::unexpected(static_cast<int>(size))) : std::expected<std::size_t,int>(static_cast<std::size_t>(size));
        }
    };
}
