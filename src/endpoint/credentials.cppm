export module endpoint.credentials;
import std;
import endpoint.config;
import encoding.base64_key;
import rulefile;
import net.udp_socket;
import crypto;
import wireguard;
import wireguard.crypto;

export namespace endpoint {
    struct PreparedPeer {
        wireguard::Key public_key{};
        wireguard::SecretKey preshared_key;
        std::optional<net::UdpEndpoint> selected;
    };
    struct Prepared {
        wireguard::SecretKey private_key;
        std::array<PreparedPeer,32> peers;
        std::size_t count=0;
        Prepared()=default;
        Prepared(Prepared const&)=delete;
        auto operator=(Prepared const&) -> Prepared& = delete;
        Prepared(Prepared&&)=default;
        auto operator=(Prepared&&) -> Prepared& = default;
    };
    struct NeverCancel { constexpr auto operator()() const noexcept -> bool { return false; } };
    template<class Cancel=NeverCancel>
    [[nodiscard]] auto prepare_credentials(Wireguard const& config,std::chrono::steady_clock::time_point deadline,Cancel cancel={}) -> std::expected<Prepared,std::string> {
        auto budget=[&]() -> std::expected<void,std::string> {
            static_assert(noexcept(cancel()));
            if (cancel()) return std::unexpected("endpoint startup canceled");
            if (std::chrono::steady_clock::now()>=deadline) return std::unexpected("endpoint startup deadline expired");
            return {};
        };
        auto checked=budget(); if (!checked) return std::unexpected(checked.error());
        if (config.peers.empty() || config.peers.size()>32) return std::unexpected("invalid peer capacity");
        Prepared result;
        {
            auto file=rulefile::read_private_file(config.private_key_file);
            if (!file) return std::unexpected("private key: "+file.error());
            if (!encoding::decode_key(file->bytes(),result.private_key.writable())) return std::unexpected("private key requires canonical base64 for exactly 32 bytes");
        }
        auto identity=crypto::X25519Private::from_bytes(result.private_key.view());
        if (!identity) return std::unexpected("cannot initialize private key");
        auto local_public=identity->public_key(); if (!local_public) return std::unexpected("cannot derive local public key");
        for (std::size_t i=0;i<config.peers.size();++i) {
            checked=budget(); if (!checked) return std::unexpected(checked.error());
            auto const& peer=config.peers[i]; auto& prepared=result.peers[i];
            {
                auto file=rulefile::read_regular_file(peer.public_key_file);
                if (!file) return std::unexpected("peer "+peer.name+" public key: "+file.error());
                if (!encoding::decode_key(std::span(file->data(),file->size()),prepared.public_key)) return std::unexpected("peer "+peer.name+" public key requires canonical base64 for exactly 32 bytes");
            }
            if (prepared.public_key==*local_public) return std::unexpected("peer "+peer.name+" is the local identity");
            for (std::size_t j=0;j<i;++j) if (prepared.public_key==result.peers[j].public_key) return std::unexpected("duplicate peer public identity");
            auto agreed=identity->agree(prepared.public_key); if (!agreed) return std::unexpected("peer "+peer.name+" has an invalid public identity");
            if (peer.preshared_key_file) {
                auto file=rulefile::read_private_file(*peer.preshared_key_file);
                if (!file) return std::unexpected("peer "+peer.name+" preshared key: "+file.error());
                if (!encoding::decode_key(file->bytes(),prepared.preshared_key.writable())) return std::unexpected("peer "+peer.name+" preshared key requires canonical base64 for exactly 32 bytes");
            }
            if (peer.server) prepared.selected=peer.server->numeric;
            ++result.count;
        }
        checked=budget(); if (!checked) return std::unexpected(checked.error());
        return result;
    }
}
