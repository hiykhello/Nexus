module nexus.tls.client_session_handshake;
import std;
namespace nexus::tls {
    auto make_client_hello(std::optional<std::string_view> server_name, std::span<std::string_view const> alpn,
        std::span<std::uint16_t const> groups) -> std::expected<ClientHello,ClientHelloConfigError> {
        auto dns=[](std::string_view name) {
            if (name.empty() || name.size()>253) return false;
            bool only_numeric=true; std::size_t start=0;
            for (std::size_t i=0;i<=name.size();++i) {
                if (i==name.size() || name[i]=='.') {
                    auto label=name.substr(start,i-start);
                    if (label.empty() || label.size()>63 || label.front()=='-' || label.back()=='-') return false;
                    start=i+1; continue;
                }
                unsigned char c=name[i];
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
                if (!(c>='0' && c<='9')) only_numeric=false;
            }
            return !only_numeric;
        };
        if (server_name && !dns(*server_name)) return std::unexpected(ClientHelloConfigError::invalid_server_name);
        if (groups.empty() || groups.size()>2) return std::unexpected(ClientHelloConfigError::invalid_group);
        crypto::Bytes group_data{0,static_cast<std::uint8_t>(groups.size()*2)};
        for (std::size_t i=0;i<groups.size();++i) {
            auto group=groups[i];
            if ((group!=0x001d && group!=x25519_mlkem768_group) || std::find(groups.begin(),groups.begin()+static_cast<std::ptrdiff_t>(i),group)!=groups.begin()+static_cast<std::ptrdiff_t>(i)) return std::unexpected(ClientHelloConfigError::invalid_group);
            group_data.push_back(static_cast<std::uint8_t>(group>>8)); group_data.push_back(static_cast<std::uint8_t>(group));
        }
        crypto::Bytes protocols; for (std::size_t i=0;i<alpn.size();++i) {
            auto id=alpn[i]; if (id.empty() || id.size()>255 || protocols.size()+id.size()+1>15000 || std::find(alpn.begin(),alpn.begin()+static_cast<std::ptrdiff_t>(i),id)!=alpn.begin()+static_cast<std::ptrdiff_t>(i)) return std::unexpected(ClientHelloConfigError::invalid_alpn);
            protocols.push_back(static_cast<std::uint8_t>(id.size())); protocols.insert(protocols.end(),id.begin(),id.end());
        }
        ClientHello hello; if (!crypto::random_bytes(hello.random)) return std::unexpected(ClientHelloConfigError::random_error);
        hello.cipher_suites={0x1301,0x1302,0x1303}; hello.compression_methods={0};
        if (server_name) {
            auto size=server_name->size(); crypto::Bytes data{static_cast<std::uint8_t>((size+3)>>8),static_cast<std::uint8_t>(size+3),0,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
            data.insert(data.end(),server_name->begin(),server_name->end()); hello.extensions.push_back({0,std::move(data)});
        }
        hello.extensions.push_back({43,{2,3,4}}); hello.extensions.push_back({10,std::move(group_data)});
        hello.extensions.push_back({51,{0,0}}); hello.extensions.push_back({13,{0,6,8,4,4,3,8,7}});
        if (!protocols.empty()) {
            crypto::Bytes data{static_cast<std::uint8_t>(protocols.size()>>8),static_cast<std::uint8_t>(protocols.size())};
            data.insert(data.end(),protocols.begin(),protocols.end()); hello.extensions.push_back({16,std::move(data)});
        }
        return hello;
    }
    ClientSessionHandshake::ClientSessionHandshake(ClientHelloDriver&& hello, std::vector<crypto::Bytes>&& anchors, crypto::Bytes&& name, PeerNameKind kind, std::int64_t time) noexcept
        : hello_(std::move(hello)), anchors_(std::move(anchors)), name_(std::move(name)), kind_(kind), time_(time) {}
    ClientSessionHandshake::ClientSessionHandshake(ClientSessionHandshake&& o) noexcept : state_(o.state_), hello_(std::move(o.hello_)), handshake_(std::move(o.handshake_)), anchors_(std::move(o.anchors_)), name_(std::move(o.name_)), kind_(o.kind_), time_(o.time_) { o.state_=State::failed; }
    auto ClientSessionHandshake::operator=(ClientSessionHandshake&& o) noexcept -> ClientSessionHandshake& {
        if (this!=&o) { state_=o.state_; hello_=std::move(o.hello_); handshake_=std::move(o.handshake_); anchors_=std::move(o.anchors_); name_=std::move(o.name_); kind_=o.kind_; time_=o.time_; o.state_=State::failed; } return *this;
    }
    auto ClientSessionHandshake::create(ClientTlsConfig config) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError> {
        if (config.trust_anchors.empty()) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        std::vector<std::span<std::uint8_t const>> views; for (auto const& anchor:config.trust_anchors) views.emplace_back(anchor);
        return create(std::move(config.hello),config.initial_group,views,config.peer_name_kind,config.peer_name,config.verification_time);
    }
    auto ClientSessionHandshake::create(ClientHello hello, std::uint16_t group, std::span<std::span<std::uint8_t const> const> anchors, PeerNameKind kind, std::span<std::uint8_t const> name, std::int64_t time) -> std::expected<ClientSessionHandshake,ClientSessionHandshakeError> {
        if (anchors.empty() || anchors.size()>1024 || name.empty() || name.size()>253 || (kind!=PeerNameKind::dns && kind!=PeerNameKind::ip) || (kind==PeerNameKind::ip && name.size()!=4 && name.size()!=16)) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        if (kind==PeerNameKind::dns && std::ranges::any_of(name,[](auto c) { return c<=0x20 || c>=0x7f; }))
            return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        std::size_t total=0; std::vector<crypto::Bytes> copies;
        for (auto cert:anchors) { if (cert.empty() || cert.size()>1048576 || cert.size()>4194304-total) return std::unexpected(ClientSessionHandshakeError::invalid_configuration); total+=cert.size(); copies.emplace_back(cert.begin(),cert.end()); }
        auto driver=ClientHelloDriver::create(std::move(hello),group); if (!driver) return std::unexpected(ClientSessionHandshakeError::invalid_configuration);
        return ClientSessionHandshake(std::move(*driver),std::move(copies),crypto::Bytes(name.begin(),name.end()),kind,time);
    }
    auto ClientSessionHandshake::initial_record() const -> std::expected<crypto::Bytes,ClientSessionHandshakeError> {
        if (state_!=State::initial) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        auto out=hello_.initial_record(); if (!out) return std::unexpected(ClientSessionHandshakeError::protocol_error); return std::move(*out);
    }
    auto ClientSessionHandshake::sent() -> std::expected<void,ClientSessionHandshakeError> {
        if (state_==State::initial) { if (!hello_.initial_sent()) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); } state_=State::hello; return {}; }
        if (state_==State::retry_write) { if (!hello_.retry_sent()) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); } state_=State::hello; return {}; }
        if (state_==State::finished_write) { state_=State::complete; return {}; }
        return std::unexpected(ClientSessionHandshakeError::invalid_state);
    }
    auto ClientSessionHandshake::feed(std::span<std::uint8_t const> input) -> std::expected<ClientSessionHandshakeFeed,ClientSessionHandshakeError> {
        if (state_==State::hello) {
            auto result=hello_.feed(input); if (!result) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); }
            ClientSessionHandshakeFeed out{result->consumed,std::move(result->outbound)};
            if (out.outbound) state_=State::retry_write;
            if (result->server_hello) {
                std::vector<std::span<std::uint8_t const>> anchors; for (auto const& a:anchors_) anchors.emplace_back(a);
                auto handshake=hello_.take_handshake(anchors,kind_,name_,time_); if (!handshake) { state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error); }
                handshake_=std::move(*handshake); state_=State::encrypted;
            }
            return out;
        }
        if (state_==State::encrypted) {
            auto result=handshake_->feed(input); if (!result) { state_=State::failed; return std::unexpected(result.error()==ClientHandshakeError::authentication_failed ? ClientSessionHandshakeError::authentication_failed : ClientSessionHandshakeError::protocol_error); }
            ClientSessionHandshakeFeed out{result->consumed,std::move(result->client_finished_record)}; if (out.outbound) state_=State::finished_write; return out;
        }
        return std::unexpected(ClientSessionHandshakeError::invalid_state);
    }
    auto ClientSessionHandshake::finish_input() -> std::expected<void,ClientSessionHandshakeError> {
        if (state_==State::complete || state_==State::failed) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        state_=State::failed; return std::unexpected(ClientSessionHandshakeError::protocol_error);
    }
    auto ClientSessionHandshake::negotiated() const noexcept -> EncryptedExtensions const* { return state_==State::complete && handshake_ ? handshake_->negotiated() : nullptr; }
    auto ClientSessionHandshake::take_application_records() -> std::expected<ApplicationRecords,ClientSessionHandshakeError> {
        if (state_!=State::complete || !handshake_) return std::unexpected(ClientSessionHandshakeError::invalid_state);
        auto records=handshake_->take_application_records(); if (!records) return std::unexpected(ClientSessionHandshakeError::invalid_state); return std::move(*records);
    }
}
