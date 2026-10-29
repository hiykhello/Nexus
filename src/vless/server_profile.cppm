export module nexus.vless.server_profile;
import std;
import nexus.vless;
import nexus.rulefile;
import nexus.tls.server_handshake_io;
export import nexus.memory.budget;
export namespace nexus::vless {
    // Immutable startup snapshot. Each session obtains its own handshake state
    // and a retained key reference; the snapshot outlives calls to these methods.
    class ServerProfile {
        tls::ServerCredential credential_;
        std::vector<UserId> users_;
        ServerProfile(tls::ServerCredential&& credential,std::vector<UserId>&& users)
            : credential_(std::move(credential)),users_(std::move(users)) {}
    public:
        ServerProfile(ServerProfile const&)=delete;
        auto operator=(ServerProfile const&) -> ServerProfile& = delete;
        ServerProfile(ServerProfile&&)=default;
        auto operator=(ServerProfile&&) -> ServerProfile& = default;
        [[nodiscard]] static auto create(std::span<std::uint8_t const> certificate,
            std::span<std::uint8_t const> private_key,std::span<UserId const> users)
            -> std::expected<ServerProfile,std::string> {
            if (!ServerHandshake::create(users)) return std::unexpected("invalid VLESS users");
            auto credential=tls::ServerCredential::create(certificate,private_key);
            if (!credential) return std::unexpected("invalid or mismatched TLS credential");
            return ServerProfile(std::move(*credential),std::vector<UserId>(users.begin(),users.end()));
        }
        // File contents are snapshotted before any listener starts. Certificate
        // and key are DER or PEM; the PEM certificate file may include a leaf-first chain.
        [[nodiscard]] static auto load(std::string_view certificate_path,std::string_view key_path,
            std::span<std::string const> user_paths) -> std::expected<ServerProfile,std::string> {
            if (certificate_path.empty() || certificate_path.front()!='/' || certificate_path.find('\0')!=certificate_path.npos)
                return std::unexpected("certificate path must be absolute");
            if (user_paths.empty() || user_paths.size()>64) return std::unexpected("invalid VLESS users");
            auto certificate=rulefile::read_regular_file(certificate_path);
            if (!certificate) return std::unexpected("certificate file: " + certificate.error());
            auto key=rulefile::read_private_file(key_path);
            if (!key) return std::unexpected("private key file: " + key.error());
            std::vector<UserId> users; users.reserve(user_paths.size());
            for (auto const& path:user_paths) {
                auto content=rulefile::read_private_file(path);
                if (!content) return std::unexpected("UUID file: " + content.error());
                auto bytes=content->bytes();
                if (!bytes.empty() && bytes.back()=='\n') bytes=bytes.first(bytes.size()-1);
                auto user=parse_user_id(std::string_view(bytes.data(),bytes.size()));
                if (!user) return std::unexpected("UUID file must contain a canonical UUID");
                users.push_back(*user);
            }
            auto bytes=[](std::span<char const> input) {
                return std::span(reinterpret_cast<std::uint8_t const*>(input.data()),input.size());
            };
            if (!ServerHandshake::create(users)) return std::unexpected("invalid VLESS users");
            auto credential=tls::ServerCredential::create_file_contents(bytes(std::span{certificate->data(),certificate->size()}),bytes(key->bytes()));
            if (!credential) return std::unexpected("invalid or mismatched TLS credential");
            return ServerProfile(std::move(*credential),std::move(users));
        }
        [[nodiscard]] auto tls_handshake(std::uint64_t now,std::uint64_t deadline,std::shared_ptr<memory::Budget> budget={}) const
            -> std::expected<tls::ServerHandshakeIo,std::string> {
            auto credential=credential_.clone();
            if (!credential) return std::unexpected("cannot retain TLS credential");
            auto handshake=tls::ServerHandshakeIo::create(std::move(*credential),now,deadline,{},tls::ServerCredential::max_certificate_list_size,std::move(budget));
            if (!handshake) return std::unexpected(handshake.error()==tls::ServerHandshakeIoError::budget_exceeded ? "TLS handshake budget exceeded" : "invalid TLS handshake options");
            return std::move(*handshake);
        }
        [[nodiscard]] auto vless_handshake() const -> std::expected<ServerHandshake,std::string> {
            return ServerHandshake::create(users_);
        }
    };
}
