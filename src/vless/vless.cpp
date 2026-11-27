module vless;
import std;

namespace vless {
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
    static auto encode_target_request(TcpRequest const& request,TargetCommand command)
        -> std::expected<std::vector<std::uint8_t>,EncodeError> {
        if (!request.port && !(command==TargetCommand::udp && request.kind==AddressKind::domain &&
            std::ranges::equal(request.address,packetaddr_domain))) return std::unexpected(EncodeError::invalid_port);
        if (!valid_address(request.kind,request.address)) return std::unexpected(EncodeError::invalid_address);
        std::vector<std::uint8_t> out; out.reserve(22+request.address.size()+(request.kind==AddressKind::domain));
        out.push_back(0); out.insert(out.end(),request.user.begin(),request.user.end());
        out.push_back(0); out.push_back(static_cast<std::uint8_t>(command)); out.push_back(static_cast<std::uint8_t>(request.port>>8)); out.push_back(static_cast<std::uint8_t>(request.port));
        out.push_back(static_cast<std::uint8_t>(request.kind));
        if (request.kind==AddressKind::domain) out.push_back(static_cast<std::uint8_t>(request.address.size()));
        out.insert(out.end(),request.address.begin(),request.address.end()); return out;
    }
    auto encode_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError> {
        return encode_target_request(request,TargetCommand::tcp);
    }
    auto encode_udp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError> {
        return encode_target_request(request,TargetCommand::udp);
    }
    static auto parse_target_request(std::span<std::uint8_t const> input,bool allow_udp) -> RequestResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<18) return {};
        if (input[17]!=0) return {HeaderStatus::unsupported};
        if (input.size()<19) return {};
        auto command=static_cast<TargetCommand>(input[18]);
        if (command!=TargetCommand::tcp && !(allow_udp && command==TargetCommand::udp))
            return {HeaderStatus::unsupported};
        if (input.size()<22) return {};
        auto port=static_cast<std::uint16_t>((std::uint16_t{input[19]}<<8)|input[20]);
        if (!port && command==TargetCommand::tcp) return {HeaderStatus::malformed};
        auto kind=static_cast<AddressKind>(input[21]); std::size_t start=22, length=0;
        if (kind==AddressKind::ipv4) length=4;
        else if (kind==AddressKind::ipv6) length=16;
        else if (kind==AddressKind::domain) { if (input.size()<23) return {}; length=input[22]; start=23; if (!length) return {HeaderStatus::malformed}; }
        else return {HeaderStatus::unsupported};
        if (input.size()-start<length) return {};
        auto address=input.subspan(start,length);
        if (!valid_address(kind,address)) return {HeaderStatus::malformed};
        if (!port && !(command==TargetCommand::udp && kind==AddressKind::domain &&
            std::ranges::equal(address,packetaddr_domain))) return {HeaderStatus::malformed};
        TcpRequest request; std::copy_n(input.begin()+1,16,request.user.begin());
        request.command=command; request.kind=kind; request.port=port;
        request.address.assign(address.begin(),address.end());
        return {HeaderStatus::accepted,start+length,std::move(request)};
    }
    auto parse_tcp_request(std::span<std::uint8_t const> input) -> RequestResult {
        return parse_target_request(input,false);
    }
    auto encode_vision_tcp_request(TcpRequest const& request) -> std::expected<std::vector<std::uint8_t>,EncodeError> {
        auto result=encode_tcp_request(request);
        if (!result) return result;
        constexpr std::string_view flow="xtls-rprx-vision";
        (*result)[17]=static_cast<std::uint8_t>(flow.size()+2);
        result->insert(result->begin()+18,{0x0a,static_cast<std::uint8_t>(flow.size())});
        result->insert(result->begin()+20,flow.begin(),flow.end());
        return result;
    }
    auto parse_vision_tcp_request(std::span<std::uint8_t const> input) -> RequestResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<18) return {};
        auto length=std::size_t{input[17]};
        if (input.size()-18<length) return {};
        auto addon=input.subspan(18,length);
        std::size_t pos=0; std::string_view flow;
        auto varint=[&](std::uint64_t& value) {
            value=0;
            for (unsigned i=0;i<10;++i) {
                if (pos==addon.size()) return false;
                auto byte=addon[pos++];
                if (i==9 && byte>1) return false;
                value|=static_cast<std::uint64_t>(byte & 0x7f)<<(7*i);
                if (!(byte & 0x80)) return true;
            }
            return false;
        };
        while (pos<addon.size()) {
            std::uint64_t key=0,value=0;
            if (!varint(key) || !key || (key>>3)>0x1fffffff) return {HeaderStatus::malformed};
            auto field=key>>3, wire=key&7;
            if (!field || ((field==1 || field==2) && wire!=2)) return {HeaderStatus::malformed};
            if (wire==0) { if (!varint(value)) return {HeaderStatus::malformed}; }
            else if (wire==1 || wire==5) {
                auto count=wire==1 ? 8u : 4u;
                if (addon.size()-pos<count) return {HeaderStatus::malformed};
                pos+=count;
            } else if (wire==2) {
                if (!varint(value) || value>addon.size()-pos) return {HeaderStatus::malformed};
                if (field==1) flow=std::string_view(reinterpret_cast<char const*>(addon.data()+pos),static_cast<std::size_t>(value));
                pos+=static_cast<std::size_t>(value);
            } else return {HeaderStatus::unsupported};
        }
        if (flow!="xtls-rprx-vision") return {HeaderStatus::unsupported};
        // The existing bounded TCP parser is reused without relaxing the
        // ordinary handshake's rejection of unimplemented flow semantics.
        std::array<std::uint8_t,278> plain{};
        std::copy_n(input.begin(),17,plain.begin());
        auto copied=std::min(input.size()-18-length,plain.size()-18);
        std::copy_n(input.begin()+18+length,copied,plain.begin()+18);
        auto parsed=parse_tcp_request(std::span(plain).first(18+copied));
        if (parsed.status==HeaderStatus::accepted) parsed.consumed+=length;
        return parsed;
    }
    auto encode_mux_request(std::array<std::uint8_t,16> const& user,bool vision) -> std::vector<std::uint8_t> {
        std::vector<std::uint8_t> result; result.reserve(37); result.push_back(0); result.insert(result.end(),user.begin(),user.end());
        if (vision) {
            constexpr std::string_view flow="xtls-rprx-vision";
            result.push_back(flow.size()+2); result.push_back(0x0a); result.push_back(flow.size());
            result.insert(result.end(),flow.begin(),flow.end());
        } else result.push_back(0);
        result.push_back(3); return result;
    }
    auto parse_mux_request(std::span<std::uint8_t const> input,bool vision) -> MuxRequestResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<18) return {};
        auto length=std::size_t{input[17]};
        if (input.size()<19+length) return {};
        if (input[18+length]!=3) return {HeaderStatus::unsupported};
        if (!vision && length) return {HeaderStatus::unsupported};
        if (vision) {
            // Reuse the bounded Vision addon validator with a synthetic valid
            // TCP destination; it never consumes bytes from the caller's tail.
            std::array<std::uint8_t,281> synthetic{};
            std::copy_n(input.begin(),18+length,synthetic.begin());
            auto pos=18+length; synthetic[pos++]=1; synthetic[pos++]=0; synthetic[pos++]=1;
            synthetic[pos++]=1; synthetic[pos++]=127; synthetic[pos++]=0; synthetic[pos++]=0; synthetic[pos++]=1;
            auto checked=parse_vision_tcp_request(std::span(synthetic).first(pos));
            if (checked.status!=HeaderStatus::accepted) return {checked.status};
        }
        std::array<std::uint8_t,16> user{}; std::copy_n(input.begin()+1,16,user.begin());
        return {HeaderStatus::accepted,19+length,user};
    }
    auto parse_response(std::span<std::uint8_t const> input) -> ResponseResult {
        if (input.empty()) return {};
        if (input[0]!=0) return {HeaderStatus::unsupported};
        if (input.size()<2) return {};
        if (input[1]!=0) return {HeaderStatus::unsupported};
        return {HeaderStatus::accepted,2};
    }
    auto encode_response() noexcept -> std::array<std::uint8_t,2> { return {0,0}; }
    namespace {
        auto splitmix64(std::uint64_t x) noexcept -> std::uint64_t {
            x += 0x9e3779b97f4a7c15ULL;
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
            x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
            return x ^ (x >> 31);
        }
        auto hash_user_id(UserId const& id, std::uint64_t seed) noexcept -> std::uint64_t {
            std::uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, id.data(), 8);
            std::memcpy(&hi, id.data() + 8, 8);
            return splitmix64(lo ^ seed) ^ splitmix64(hi ^ (seed * 0x9e3779b97f4a7c15ULL + 1u));
        }
        auto ct_equal_uuid(UserId const& a, UserId const& b) noexcept -> bool {
            unsigned diff = 0;
            for (std::size_t i = 0; i < 16; ++i) diff |= static_cast<unsigned>(a[i] ^ b[i]);
            return diff == 0;
        }
        auto make_table_seed() noexcept -> std::uint64_t {
            std::uint64_t seed = static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
            try {
                std::random_device rd;
                seed ^= (static_cast<std::uint64_t>(rd()) << 32) | static_cast<std::uint64_t>(rd());
            } catch (...) {}
            return splitmix64(seed);
        }
    }
    auto UserTable::create(std::span<UserId const> users)
        -> std::expected<std::shared_ptr<UserTable const>,std::string> {
        if (users.empty() || users.size() > max_users)
            return std::unexpected("VLESS requires 1..65535 users");
        std::size_t cap = 4;
        while (cap < users.size() * 2) cap <<= 1;
        auto const seed = make_table_seed();
        std::vector<std::uint32_t> buckets(cap, kEmpty);
        std::size_t const mask = cap - 1;
        for (std::size_t i = 0; i < users.size(); ++i) {
            auto slot = static_cast<std::size_t>(hash_user_id(users[i], seed)) & mask;
            while (buckets[slot] != kEmpty) {
                if (ct_equal_uuid(users[buckets[slot]], users[i]))
                    return std::unexpected("duplicate VLESS user");
                slot = (slot + 1) & mask;
            }
            buckets[slot] = static_cast<std::uint32_t>(i);
        }
        return std::shared_ptr<UserTable const>(
            new UserTable(std::vector<UserId>(users.begin(), users.end()), std::move(buckets), seed));
    }
    auto UserTable::find(UserId const& identity) const noexcept -> std::optional<std::size_t> {
        if (buckets_.empty()) return std::nullopt;
        std::size_t const mask = buckets_.size() - 1;
        auto slot = static_cast<std::size_t>(hash_user_id(identity, seed_)) & mask;
        while (buckets_[slot] != kEmpty) {
            auto const idx = buckets_[slot];
            if (ct_equal_uuid(users_[idx], identity)) return idx;
            slot = (slot + 1) & mask;
        }
        return std::nullopt;
    }
    ServerHandshake::ServerHandshake(std::shared_ptr<UserTable const> users, bool vision) noexcept
        : users_(std::move(users)), vision_(vision) {}
    auto ServerHandshake::create(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string> {
        auto table = UserTable::create(users);
        if (!table) return std::unexpected(std::move(table.error()));
        return ServerHandshake(std::move(*table), false);
    }
    auto ServerHandshake::create_shared(std::shared_ptr<UserTable const> users) -> std::expected<ServerHandshake,std::string> {
        if (!users || users->size() == 0) return std::unexpected("VLESS requires 1..65535 users");
        return ServerHandshake(std::move(users), false);
    }
    auto ServerHandshake::create_vision(std::span<UserId const> users) -> std::expected<ServerHandshake,std::string> {
        auto result=create(users);
        if (result) result->vision_=true;
        return result;
    }
    auto ServerHandshake::create_vision_shared(std::shared_ptr<UserTable const> users) -> std::expected<ServerHandshake,std::string> {
        if (!users || users->size() == 0) return std::unexpected("VLESS requires 1..65535 users");
        return ServerHandshake(std::move(users), true);
    }
    auto ServerHandshake::allow_mux() noexcept -> bool {
        if (status_!=ServerStatus::reading || length_) return false;
        mux_allowed_=true; return true;
    }
    auto ServerHandshake::allow_udp() noexcept -> bool {
        if (vision_ || status_!=ServerStatus::reading || length_) return false;
        udp_allowed_=true; return true;
    }
    auto ServerHandshake::feed(std::span<std::uint8_t const> bytes) -> ServerStep {
        if (status_!=ServerStatus::reading) return {status_,0};
        std::size_t consumed=0;
        while (consumed<bytes.size()) {
            header_[length_++]=bytes[consumed++];
            auto prefix=std::span(header_).first(length_);
            auto parsed=vision_ ? parse_vision_tcp_request(prefix) : parse_target_request(prefix,udp_allowed_);
            MuxRequestResult mux;
            if (mux_allowed_) mux=parse_mux_request(prefix,vision_);
            else mux.status=HeaderStatus::unsupported;
            if (parsed.status==HeaderStatus::accepted || mux.status==HeaderStatus::accepted) {
                auto const& identity=parsed.status==HeaderStatus::accepted ? parsed.request->user : *mux.user;
                if (!users_ || !users_->find(identity)) status_=ServerStatus::rejected;
                else {
                    if (parsed.status==HeaderStatus::accepted) request_=std::move(parsed.request);
                    else mux_user_=identity;
                    status_=ServerStatus::dialing;
                }
                return {status_,consumed};
            }
            if ((parsed.status!=HeaderStatus::incomplete && mux.status!=HeaderStatus::incomplete) || length_==header_.size()) {
                status_=ServerStatus::rejected;
                return {status_,consumed};
            }
        }
        return {status_,consumed};
    }
    auto ServerHandshake::request() const noexcept -> TcpRequest const* {
        return request_ ? &*request_ : nullptr;
    }
    auto ServerHandshake::mux_user() const noexcept -> UserId const* {
        return mux_user_ ? &*mux_user_ : nullptr;
    }
    auto ServerHandshake::complete_dial(bool connected) -> std::optional<std::array<std::uint8_t,2>> {
        if (status_!=ServerStatus::dialing) return {};
        status_=connected ? ServerStatus::established : ServerStatus::rejected;
        if (!connected) { request_.reset(); mux_user_.reset(); return {}; }
        return encode_response();
    }
}
