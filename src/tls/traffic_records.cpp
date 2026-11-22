module tls.traffic_records;
import tls.handshake_secrets;
import std;

namespace tls {
    auto traffic_records(std::uint16_t suite,std::span<std::uint8_t const> client,
        std::span<std::uint8_t const> server,bool server_role) -> std::expected<TrafficRecords,crypto::Error> {
        auto spec=cipher_spec(suite); if (!spec) return std::unexpected(spec.error());
        auto ck=expand_label(spec->hash,client,"key",{},spec->key_bytes),ci=expand_label(spec->hash,client,"iv",{},12);
        auto sk=expand_label(spec->hash,server,"key",{},spec->key_bytes),si=expand_label(spec->hash,server,"iv",{},12);
        if (!ck || !ci || !sk || !si) return std::unexpected(crypto::Error::backend_failure);
        // Keep the original client/server backend construction order.
        auto first=RecordLayer::create(server_role ? RecordDirection::receive : RecordDirection::send,spec->algorithm,ck->view(),ci->view());
        auto second=RecordLayer::create(server_role ? RecordDirection::send : RecordDirection::receive,spec->algorithm,sk->view(),si->view());
        if (!first || !second) return std::unexpected(crypto::Error::backend_failure);
        if (server_role) return TrafficRecords{std::move(*second),std::move(*first)};
        return TrafficRecords{std::move(*first),std::move(*second)};
    }
}
