export module reality.server_profile;
import std;
import reality.server_auth;
import reality.auth;
import reality.server_credential;
import tls.server_handshake_io;
import tls.certificate_verify;
import rulefile;

export namespace reality {
    // Immutable per-listener snapshot. Sessions borrow it until their tasks drain.
    class ServerProfile {
        crypto::X25519Private private_key_;
        tls::ServerCredential template_credential_;
        std::vector<std::string> names_;
        std::vector<std::array<std::uint8_t,8>> ids_;
        std::uint64_t max_time_difference_;
        std::shared_ptr<ReplayCache> replay_cache_{std::make_shared<ReplayCache>()};
        ServerProfile(crypto::X25519Private&& private_key,tls::ServerCredential&& credential,
                      std::vector<std::string>&& names,
                      std::vector<std::array<std::uint8_t,8>>&& ids,std::uint64_t skew)
            : private_key_(std::move(private_key)),template_credential_(std::move(credential)),
              names_(std::move(names)),ids_(std::move(ids)),max_time_difference_(skew) {}
        static auto bytes(std::span<char const> data) noexcept -> std::span<std::uint8_t const> {
            return {reinterpret_cast<std::uint8_t const*>(data.data()),data.size()};
        }
    public:
        static constexpr std::size_t max_certificate_size=16384;
        ServerProfile(ServerProfile const&)=delete;
        auto operator=(ServerProfile const&) -> ServerProfile& = delete;
        ServerProfile(ServerProfile&&)=default;
        auto operator=(ServerProfile&&) -> ServerProfile& = delete;
        // The X25519 secret file contains 64 hexadecimal digits, optionally
        // followed by one newline. An optional certificate and matching key are DER;
        // omitting both generates a per-listener in-memory Ed25519 credential.
        [[nodiscard]] static auto load(std::string_view secret_path,std::string_view certificate_path,
            std::string_view signing_key_path,std::span<std::string const> names,
            std::span<std::array<std::uint8_t,8> const> ids,std::uint64_t max_time_difference)
            -> std::expected<ServerProfile,std::string> {
            if (names.empty() || names.size()>64 || ids.empty() || ids.size()>64)
                return std::unexpected("Reality requires 1..64 server names and short IDs");
            for (auto const& name:names) if (name.empty() || name.size()>253 || name.find('\0')!=name.npos)
                return std::unexpected("invalid Reality server name");
            auto secret=rulefile::read_private_file(secret_path);
            if (!secret) return std::unexpected("Reality private key: "+secret.error());
            auto text=secret->bytes(); if (!text.empty() && text.back()=='\n') text=text.first(text.size()-1);
            if (text.size()!=64) return std::unexpected("Reality private key must be 64 hexadecimal digits");
            std::array<std::uint8_t,32> raw{};
            struct Wipe { std::array<std::uint8_t,32>& data; ~Wipe() { crypto::cleanse(data); } } wipe{raw};
            auto hex=[](char c) -> int { if (c>='0' && c<='9') return c-'0'; if (c>='a' && c<='f') return c-'a'+10; if (c>='A' && c<='F') return c-'A'+10; return -1; };
            for (std::size_t i=0;i<raw.size();++i) {
                auto a=hex(text[2*i]),b=hex(text[2*i+1]); if (a<0 || b<0) return std::unexpected("invalid Reality private key hex");
                raw[i]=static_cast<std::uint8_t>((a<<4)|b);
            }
            auto key=crypto::X25519Private::from_bytes(raw); if (!key || !key->public_key()) return std::unexpected("invalid Reality private key");
            std::optional<tls::ServerCredential> credential;
            if (certificate_path.empty() && signing_key_path.empty()) {
                auto generated=tls::ServerCredential::generate_ed25519();
                if (!generated) return std::unexpected("cannot generate Reality signing credential");
                credential.emplace(std::move(*generated));
            } else {
                if (certificate_path.empty() || signing_key_path.empty()) return std::unexpected("Reality certificate and signing key must be provided together");
                auto certificate=rulefile::read_regular_file(certificate_path);
                if (!certificate) return std::unexpected("Reality certificate: "+certificate.error());
                if (certificate->empty() || certificate->size()>max_certificate_size) return std::unexpected("invalid Reality certificate size");
                auto signing_key=rulefile::read_private_file(signing_key_path);
                if (!signing_key) return std::unexpected("Reality signing key: "+signing_key.error());
                auto cert=bytes(std::span{certificate->data(),certificate->size()});
                auto fields=tls::ed25519_certificate_fields(cert);
                auto parsed=tls::ServerCredential::create(cert,bytes(signing_key->bytes()));
                if (!fields || cert.size()<67 || cert[cert.size()-67]!=3 || cert[cert.size()-66]!=65 || cert[cert.size()-65]!=0 ||
                    !std::ranges::equal(cert.last(64),fields->signature) || !parsed || parsed->scheme()!=0x0807)
                    return std::unexpected("invalid or mismatched Reality Ed25519 credential");
                credential.emplace(std::move(*parsed));
            }
            return ServerProfile(std::move(*key),std::move(*credential),std::vector<std::string>(names.begin(),names.end()),
                                 std::vector<std::array<std::uint8_t,8>>(ids.begin(),ids.end()),max_time_difference);
        }
        [[nodiscard]] auto private_key() const noexcept -> crypto::X25519Private const& { return private_key_; }
        [[nodiscard]] auto policy() const noexcept -> ServerPolicy { return {names_,ids_,{},{},max_time_difference_,replay_cache_.get()}; }
        // Only call after authenticating the exact ClientHello. The additional
        // reservation covers logical certificate copies during credential creation;
        // allocator capacity and crypto internals are not included.
        [[nodiscard]] auto handshake(AuthKey const& auth,std::uint64_t now,std::uint64_t deadline,
                                     std::shared_ptr<memory::Budget> budget={},std::string_view required_alpn={}) const
            -> std::expected<tls::ServerHandshakeIo,std::string> {
            std::optional<memory::Budget::Reservation> certificate_reservation;
            if (budget) {
                certificate_reservation=memory::Budget::reserve(budget,4*template_credential_.certificate().size()+4096);
                if (!certificate_reservation) return std::unexpected("Reality handshake budget exceeded");
            }
            auto credential=make_server_credential(auth,template_credential_);
            if (!credential) return std::unexpected("cannot create Reality credential");
            if (certificate_reservation) (void)certificate_reservation->shrink(credential->certificate().size());
            auto handshake=tls::ServerHandshakeIo::create(std::move(*credential),now,deadline,required_alpn,
                tls::ServerCredential::max_certificate_list_size,std::move(budget),std::move(certificate_reservation));
            if (!handshake || !handshake->enable_authenticated_ed25519()) return std::unexpected("cannot create Reality handshake");
            return std::move(*handshake);
        }
    };
}
