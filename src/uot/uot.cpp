module uot;
import std;
import net.datagram_frame;

namespace uot {
    auto encode_request(Request const& request) -> std::expected<std::vector<std::uint8_t>,Status> {
        if (!net::valid_proxy_address(request.destination)) return std::unexpected(Status::invalid_address);
        std::vector<std::uint8_t> output;
        output.reserve(5+request.destination.length);
        output.push_back(request.connected ? 1 : 0);
        (void)net::append_proxy_address(output,request.destination,net::AddressWire::socks);
        return output;
    }
    auto parse_request(std::span<std::uint8_t const> input) noexcept -> RequestResult {
        if (input.empty()) return {};
        auto parsed=net::parse_proxy_address(input.subspan(1),net::AddressWire::socks);
        if (parsed.status!=Status::accepted) return {parsed.status};
        return {Status::accepted,1+parsed.consumed,{input[0]!=0,parsed.address}};
    }
    auto RequestDecoder::feed(std::span<std::uint8_t const> bytes) noexcept -> FeedResult {
        if (status_!=Status::incomplete) return {status_,0};
        std::size_t consumed=0;
        while (consumed<bytes.size()) {
            input_[size_++]=bytes[consumed++];
            auto parsed=parse_request(std::span(input_).first(size_));
            if (parsed.status==Status::accepted) { request_=parsed.request; status_=Status::accepted; return {status_,consumed}; }
            if (parsed.status!=Status::incomplete) { status_=parsed.status; return {status_,consumed}; }
            if (size_==input_.size()) { status_=Status::too_large; return {status_,consumed}; }
        }
        return {status_,consumed};
    }
    auto RequestDecoder::request() const noexcept -> std::optional<Request> { return status_==Status::accepted ? std::optional{request_} : std::nullopt; }
    auto RequestDecoder::close() noexcept -> void { status_=Status::closed; }
}
