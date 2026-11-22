module tls.server_flight;
import tls.handshake;
import tls.server_hello;
import tls.traffic_records;
import std;
namespace tls {
    ServerFlight::ServerFlight(RawServerFlight&& raw,RecordLayer&& read,ApplicationRecords&& application,std::vector<crypto::Bytes>&& records) noexcept
        : raw_(std::move(raw)),read_(std::move(read)),application_(std::move(application)),records_(std::move(records)) {}
    ServerFlight::ServerFlight(ServerFlight&& other) noexcept
        : raw_(std::move(other.raw_)),read_(std::move(other.read_)),application_(std::move(other.application_)),records_(std::move(other.records_)),decoder_(std::move(other.decoder_)) {}
    auto ServerFlight::operator=(ServerFlight&& other) noexcept -> ServerFlight& {
        if (this!=&other) { raw_=std::move(other.raw_); read_=std::move(other.read_); application_=std::move(other.application_); records_=std::move(other.records_); decoder_=std::move(other.decoder_); } return *this;
    }
    auto ServerFlight::release_record(std::size_t index) noexcept -> void { if (index<records_.size()) crypto::Bytes{}.swap(records_[index]); }
    auto ServerFlight::release_records() noexcept -> void { std::vector<crypto::Bytes>{}.swap(records_); }


    auto ServerFlight::take_application_records() -> std::expected<ApplicationRecords,ServerFlightError> {
        if (!raw_.complete() || !application_) return std::unexpected(ServerFlightError::invalid_state);
        auto result=std::move(*application_); application_.reset(); return result;
    }
}
