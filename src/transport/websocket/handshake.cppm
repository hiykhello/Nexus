export module websocket.handshake;
import std;
import encoding.base64;
import httpupgrade;
import http.header;
import http.connect;
import net.socket_stream;
import crypto;
import capy;

export namespace websocket {
    using Clock=std::chrono::steady_clock;
    using Violation=httpupgrade::Status;
    using UpgradeFailure=httpupgrade::Status;
    struct UpgradeReady {
        std::size_t prefetched=0;
        std::vector<std::uint8_t> early_data;
    };

    namespace detail {
        inline auto base64(std::span<std::uint8_t const> bytes) -> std::string {
            constexpr std::string_view alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string result;
            result.reserve((bytes.size()+2)/3*4);
            for (std::size_t index=0;index<bytes.size();index+=3) {
                bool middle=index+1<bytes.size(),last=index+2<bytes.size();
                std::uint32_t bits=std::uint32_t(bytes[index])<<16;
                if (middle) bits|=std::uint32_t(bytes[index+1])<<8;
                if (last) bits|=bytes[index+2];
                result.push_back(alphabet[bits>>18]);
                result.push_back(alphabet[(bits>>12)&63]);
                result.push_back(middle ? alphabet[(bits>>6)&63] : '=');
                result.push_back(last ? alphabet[bits&63] : '=');
            }
            return result;
        }

        inline auto decode_base64url(std::string_view input,std::size_t max_bytes)
            -> std::optional<std::vector<std::uint8_t>> {
            if (input.empty()) return std::vector<std::uint8_t>{};
            std::size_t pad=0;
            while (!input.empty() && input.back()=='=') {
                if (++pad>2) return {};
                input.remove_suffix(1);
            }
            if (input.empty() || (input.size()%4)==1) return {};
            auto const expected=(input.size()*3)/4;
            if (expected>max_bytes) return {};
            std::vector<std::uint8_t> out;
            out.reserve(expected);
            std::uint32_t acc=0;
            int bits=0;
            for (char c:input) {
                int v=-1;
                if (c>='A' && c<='Z') v=c-'A';
                else if (c>='a' && c<='z') v=c-'a'+26;
                else if (c>='0' && c<='9') v=c-'0'+52;
                else if (c=='-') v=62;
                else if (c=='_') v=63;
                else return {};
                acc=(acc<<6)|static_cast<std::uint32_t>(v);
                bits+=6;
                if (bits>=8) {
                    bits-=8;
                    out.push_back(static_cast<std::uint8_t>((acc>>bits)&0xffu));
                }
            }
            if (bits>=6 || (bits>0 && (acc&((1u<<bits)-1u))!=0)) return {};
            return out;
        }

        inline auto proof(std::string_view key) -> std::optional<std::string> {
            constexpr std::string_view guid="258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
            std::array<char,24+guid.size()> input;
            if (key.size()!=24) return {};
            std::ranges::copy(key,input.begin());
            std::ranges::copy(guid,input.begin()+24);
            std::array<std::uint8_t,20> hash;
            unsigned length=0;
            if (!boringssl::EVP_Digest(input.data(),input.size(),hash.data(),&length,
                boringssl::EVP_sha1(),nullptr) || length!=hash.size()) return {};
            return base64(hash);
        }

        struct ValidationResult {
            std::string_view token;
            std::optional<std::string_view> early_header_value;
        };

        inline auto validation(std::string_view wire,bool client,std::string_view expected,
            std::string_view early_header_name={}) -> std::optional<ValidationResult> {
            using httpupgrade::detail::equal_ci;
            std::optional<std::string_view> token;
            std::optional<std::string_view> early_val;
            bool version=false;
            std::string_view remaining=http::inspect_header(wire).field_lines;
            std::size_t count=0;
            for (;;) {
                auto entry=httpupgrade::detail::next_ws_header(remaining,count,client ? std::string_view{} : early_header_name);
                if (entry.status==http::HeaderFieldStatus::end) break;
                if (entry.status!=http::HeaderFieldStatus::field) return {};
                auto [name,value]=entry.field;
                if (equal_ci(name,client ? "sec-websocket-accept" : "sec-websocket-key")) {
                    if (token) return {};
                    token=value;
                } else if (!client && equal_ci(name,"sec-websocket-version")) {
                    if (version || value!="13") return {};
                    version=true;
                } else if (!client && !early_header_name.empty() && equal_ci(name,early_header_name)) {
                    if (early_val) return {};
                    early_val=value;
                } else if (client && name.size()>=14 && equal_ci(name.substr(0,14),"sec-websocket-")) {
                    return {};
                }
            }
            if (!token) return {};
            if (client) return *token==expected ? std::optional<ValidationResult>{{*token,{}}} : std::nullopt;
            std::array<std::uint8_t,16> decoded;
            if (!version || !encoding::decode_base64_exact({token->data(),token->size()},decoded)) return {};
            return ValidationResult{*token,early_val};
        }

        template<class Stream>
        auto write_upgrade(Stream& stream,httpupgrade::Profile const& profile,std::string_view fields,
            Clock::time_point deadline) -> capy::task<bool> {
            auto base=profile.wire();
            if (base.size()+fields.size()>http::max_header_bytes) co_return false;
            std::string request(base.substr(0,base.size()-2));
            request.append(fields);
            request+="\r\n";
            co_return co_await stream.send({reinterpret_cast<std::uint8_t const*>(request.data()),request.size()},deadline);
        }
    }

    template<class Stream>
    auto upgrade_early(Stream& stream,httpupgrade::Profile const& profile,Clock::time_point deadline,
        std::span<std::uint8_t const> client_early={})
        -> capy::task<std::expected<UpgradeReady,UpgradeFailure>> {
        struct Guard { Stream& stream; bool accepted=false; ~Guard() {if (!accepted) stream.cancel();} } guard{stream};
        auto client=profile.is_client();
        std::optional<std::string> expected;
        if (client) {
            std::array<std::uint8_t,16> random;
            if (!crypto::random_bytes(random)) co_return std::unexpected(Violation::closed);
            auto key=detail::base64(random);
            expected=detail::proof(key);
            auto fields="Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: "+key+"\r\n";
            if (!client_early.empty()) {
                auto const hdr=profile.effective_early_data_header();
                auto encoded=encoding::encode_base64url(client_early,false);
                fields.append(hdr);
                fields.append(": ");
                fields.append(encoded);
                fields.append("\r\n");
            }
            if (!expected || !co_await detail::write_upgrade(stream,profile,fields,deadline))
                co_return std::unexpected(Violation::closed);
        }
        http::HeaderBoundary boundary;
        std::array<std::uint8_t,4096> packet;
        std::string header;
        std::size_t consumed=0;
        for (;;) {
            auto state=boundary.inspect(header);
            if (state==http::HeaderBoundaryStatus::complete) {
                auto parsed=client ? httpupgrade::parse_response(header,true) : httpupgrade::parse_request(header,profile,true);
                if (parsed.status!=Violation::accepted) co_return std::unexpected(parsed.status);
                consumed=parsed.consumed;
                break;
            }
            if (state==http::HeaderBoundaryStatus::too_large) co_return std::unexpected(Violation::too_large);
            auto size=co_await stream.read(packet,deadline);
            if (!size || !*size || *size>packet.size()) co_return std::unexpected(Violation::truncated);
            header.append(reinterpret_cast<char const*>(packet.data()),*size);
        }
        auto const early_hdr=profile.effective_early_data_header();
        auto validated=detail::validation(header,client,expected ? std::string_view(*expected) : std::string_view{},early_hdr);
        if (!validated) co_return std::unexpected(Violation::upgrade);
        std::vector<std::uint8_t> server_early;
        if (!client) {
            if (validated->early_header_value && !validated->early_header_value->empty()) {
                bool const explicit_cfg=profile.max_early_data()>0 || !profile.early_data_header_name().empty();
                std::size_t const cap=profile.max_early_data()>0 ? profile.max_early_data() : httpupgrade::max_ws_early_data_bytes;
                auto decoded=detail::decode_base64url(*validated->early_header_value,cap);
                if (!decoded) {
                    if (explicit_cfg) co_return std::unexpected(Violation::upgrade);
                } else {
                    server_early=std::move(*decoded);
                }
            }
            auto accept=detail::proof(validated->token);
            if (!accept) co_return std::unexpected(Violation::upgrade);
            auto fields="Sec-WebSocket-Accept: "+*accept+"\r\n";
            if (!co_await detail::write_upgrade(stream,profile,fields,deadline)) co_return std::unexpected(Violation::closed);
        }
        auto data=reinterpret_cast<std::uint8_t const*>(header.data());
        if (!stream.prepend_owned(std::vector<std::uint8_t>(data+consumed,data+header.size())))
            co_return std::unexpected(Violation::closed);
        guard.accepted=true;
        co_return UpgradeReady{header.size()-consumed,std::move(server_early)};
    }

    template<class Stream>
    auto upgrade(Stream& stream,httpupgrade::Profile const& profile,Clock::time_point deadline)
        -> capy::task<std::expected<std::size_t,UpgradeFailure>> {
        auto ready=co_await upgrade_early(stream,profile,deadline);
        if (!ready) co_return std::unexpected(ready.error());
        co_return ready->prefetched;
    }
}
