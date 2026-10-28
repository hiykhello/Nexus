module nexus.vless;
import std;

namespace nexus::vless {
    auto parse_user_id(std::string_view text) -> std::optional<std::array<std::uint8_t,16>> {
        if (text.size()!=36) return {};
        auto hex=[](char c) -> int {
            if (c>='0' && c<='9') return c-'0';
            if (c>='a' && c<='f') return c-'a'+10;
            if (c>='A' && c<='F') return c-'A'+10;
            return -1;
        };
        std::array<std::uint8_t,16> result{};
        std::size_t offset=0;
        for (auto& byte : result) {
            if (offset==8 || offset==13 || offset==18 || offset==23) {
                if (text[offset++]!='-') return {};
            }
            auto high=hex(text[offset++]), low=hex(text[offset++]);
            if (high<0 || low<0) return {};
            byte=static_cast<std::uint8_t>((high<<4)|low);
        }
        return result;
    }
    namespace {
        auto valid_address(AddressKind kind,std::span<std::uint8_t const> address) -> bool {
            if (kind==AddressKind::ipv4) return address.size()==4;
            if (kind==AddressKind::ipv6) return address.size()==16;
            if (kind!=AddressKind::domain || address.empty() || address.size()>255) return false;
            return std::ranges::all_of(address,[](auto c) { return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='.' || c=='-' || c=='_'; });
        }
    }
    auto encode_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError> {
        if (!request.port) return std::unexpected(EncodeError::invalid_port);
        if (!valid_address(request.kind,request.address)) return std::unexpected(EncodeError::invalid_address);
        std::vector<std::uint8_t> out; out.reserve(22+request.address.size()+(request.kind==AddressKind::domain));
        out.push_back(0); out.insert(out.end(),request.user.begin(),request.user.end());
        out.push_back(0); out.push_back(1); out.push_back(static_cast<std::uint8_t>(request.port>>8)); out.push_back(static_cast<std::uint8_t>(request.port));
        out.push_back(static_cast<std::uint8_t>(request.kind));
        if (request.kind==AddressKind::domain) out.push_back(static_cast<std::uint8_t>(request.address.size()));
        out.insert(out.end(),request.address.begin(),request.address.end()); return out;
    }
    auto parse_tcp_request(std::span<std::uint8_t const> input) -> RequestResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<18) return {};
        if (input[17]!=0) return {HeaderStatus::unsupported};
        if (input.size()<19) return {};
        if (input[18]!=1) return {HeaderStatus::unsupported};
        if (input.size()<22) return {};
        auto port=static_cast<std::uint16_t>((std::uint16_t{input[19]}<<8)|input[20]);
        if (!port) return {HeaderStatus::malformed};
        auto kind=static_cast<AddressKind>(input[21]); std::size_t start=22, length=0;
        if (kind==AddressKind::ipv4) length=4;
        else if (kind==AddressKind::ipv6) length=16;
        else if (kind==AddressKind::domain) { if (input.size()<23) return {}; length=input[22]; start=23; if (!length) return {HeaderStatus::malformed}; }
        else return {HeaderStatus::unsupported};
        if (input.size()-start<length) return {};
        auto address=input.subspan(start,length);
        if (!valid_address(kind,address)) return {HeaderStatus::malformed};
        TcpRequest request; std::copy_n(input.begin()+1,16,request.user.begin());
        request.kind=kind; request.port=port; request.address.assign(address.begin(),address.end());
        return {HeaderStatus::accepted,start+length,std::move(request)};
    }
    auto parse_response(std::span<std::uint8_t const> input) -> ResponseResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<2) return {};
        if (input[1]!=0) return {HeaderStatus::unsupported};
        return {HeaderStatus::accepted,2};
    }
    auto encode_response() noexcept -> std::array<std::uint8_t,2> { return {0,0}; }
    ServerHandshake::ServerHandshake(std::vector<UserId> users) : users_(std::move(users)) {}
    auto ServerHandshake::create(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string> {
        if (users.empty() || users.size()>64) return std::unexpected("VLESS requires 1..64 users");
        for (std::size_t i=0;i<users.size();++i)
            for (std::size_t j=0;j<i;++j)
                if (users[i]==users[j]) return std::unexpected("duplicate VLESS user");
        return ServerHandshake(std::vector<UserId>(users.begin(),users.end()));
    }
    auto ServerHandshake::feed(std::span<std::uint8_t const> bytes) -> ServerStep {
        if (status_!=ServerStatus::reading) return {status_,0};
        std::size_t consumed=0;
        while (consumed<bytes.size()) {
            header_[length_++]=bytes[consumed++];
            auto parsed=parse_tcp_request(std::span(header_).first(length_));
            if (parsed.status==HeaderStatus::accepted) {
                unsigned any=0;
                for (auto const& user : users_) {
                    unsigned different=0;
                    for (std::size_t i=0;i<user.size();++i) different |= user[i]^parsed.request->user[i];
                    any |= static_cast<unsigned>(different==0);
                }
                if (!any) status_=ServerStatus::rejected;
                else { request_=std::move(parsed.request); status_=ServerStatus::dialing; }
                return {status_,consumed};
            }
            if (parsed.status!=HeaderStatus::incomplete || length_==header_.size()) {
                status_=ServerStatus::rejected;
                return {status_,consumed};
            }
        }
        return {status_,consumed};
    }
    auto ServerHandshake::request() const noexcept -> TcpRequest const* {
        return request_ ? &*request_ : nullptr;
    }
    auto ServerHandshake::complete_dial(bool connected) -> std::optional<std::array<std::uint8_t,2>> {
        if (status_!=ServerStatus::dialing) return {};
        status_=connected ? ServerStatus::established : ServerStatus::rejected;
        if (!connected) { request_.reset(); return {}; }
        return encode_response();
    }
}
