export module tls.traffic_records;
export import tls.record;
import tls.handshake_secrets;
import std;

export namespace tls {
    struct TrafficRecords { RecordLayer write,read; };
    // TCP record adaptation only. QUIC never constructs these record objects.
    [[nodiscard]] auto traffic_records(std::uint16_t suite,std::span<std::uint8_t const> client,
        std::span<std::uint8_t const> server,bool server_role) -> std::expected<TrafficRecords,crypto::Error>;
}
