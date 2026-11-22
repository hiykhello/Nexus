module tailscale.derp_server;
import std;
import tailscale.box;

namespace tailscale::derp {
    auto DerpRelayServer::create(crypto::X25519Private server_key, std::size_t max_peers)
        -> std::expected<DerpRelayServer, std::string> {
        auto pub = server_key.public_key();
        if (!pub) return std::unexpected("invalid DERP server X25519 key");
        return DerpRelayServer(std::move(server_key), *pub, max_peers);
    }

    auto DerpRelayServer::generate(std::size_t max_peers) -> std::expected<DerpRelayServer, std::string> {
        auto key = crypto::X25519Private::generate();
        if (!key) return std::unexpected("failed to generate DERP server key");
        return create(std::move(*key), max_peers);
    }

    auto DerpRelayServer::accept_connection(std::uint64_t connection_id) -> std::expected<OutboundFrame, std::string> {
        auto frame = encode_server_key(server_public_);
        if (!frame) return std::unexpected("failed to encode DERP server_key");
        return OutboundFrame{connection_id, std::move(*frame)};
    }

    auto DerpRelayServer::handle_frame(std::uint64_t connection_id, Frame frame, std::uint64_t now_ms)
        -> std::expected<std::vector<OutboundFrame>, std::string> {
        std::vector<OutboundFrame> out;
        auto by_conn = [&](PeerSession const& p) { return p.connection_id == connection_id; };

        if (frame.type == Type::client_info) {
            auto env = parse_client_info(frame);
            if (!env) return std::unexpected("malformed DERP client_info");
            auto shared = box::SharedKey::derive(server_key_, env->node);
            if (!shared) return std::unexpected("invalid DERP peer public key");
            std::vector<std::uint8_t> plain(env->sealed.ciphertext.size());
            auto len = shared->open_to(plain, env->sealed.nonce, env->sealed.ciphertext);
            if (!len) return std::unexpected("DERP client_info authentication failed");

            std::erase_if(peers_, [&](PeerSession const& p) {
                return p.connection_id == connection_id || p.node == env->node;
            });
            if (peers_.size() >= max_peers_) return std::unexpected("DERP relay peer limit reached");
            peers_.push_back({connection_id, env->node, false, now_ms});
            stats_.connected_peers = peers_.size();

            Nonce ack_nonce{};
            if (!crypto::random_bytes(ack_nonce)) return std::unexpected("RNG failure");
            constexpr std::string_view kServerInfo = "{\"version\":2}";
            std::vector<std::uint8_t> sealed_ack(kServerInfo.size() + box::tag_size);
            auto slen = shared->seal_to(sealed_ack, ack_nonce,
                std::span(reinterpret_cast<std::uint8_t const*>(kServerInfo.data()), kServerInfo.size()));
            if (!slen) return std::unexpected("failed to seal DERP server_info");
            sealed_ack.resize(*slen);
            auto ack = encode_server_info(ack_nonce, sealed_ack);
            if (!ack) return std::unexpected("failed to encode DERP server_info");
            out.push_back({connection_id, std::move(*ack)});
            return out;
        }

        auto sender_it = std::ranges::find_if(peers_, by_conn);
        if (sender_it == peers_.end()) return std::unexpected("unregistered DERP peer");
        sender_it->last_seen_ms = now_ms;

        if (frame.type == Type::send_packet) {
            auto pkt = parse_packet(frame, Type::send_packet);
            if (!pkt) return std::unexpected("malformed DERP send_packet");
            auto dst = std::ranges::find(peers_, pkt->peer, &PeerSession::node);
            if (dst == peers_.end()) {
                ++stats_.packets_dropped;
                return out;
            }
            auto recv = encode_packet(Type::recv_packet, sender_it->node, pkt->bytes);
            if (!recv) return std::unexpected("failed to encode DERP recv_packet");
            ++stats_.packets_forwarded;
            out.push_back({dst->connection_id, std::move(*recv)});
            return out;
        }

        if (frame.type == Type::note_preferred) {
            auto pref = parse_note_preferred(frame);
            if (!pref) return std::unexpected("malformed DERP note_preferred");
            sender_it->preferred = *pref;
            return out;
        }

        if (frame.type == Type::ping) {
            auto token = parse_ping(frame, Type::ping);
            if (!token) return std::unexpected("malformed DERP ping");
            auto pong = encode_ping(Type::pong, *token);
            if (!pong) return std::unexpected("failed to encode DERP pong");
            ++stats_.pings_replied;
            out.push_back({connection_id, std::move(*pong)});
            return out;
        }

        if (frame.type == Type::keep_alive) return out;
        return out;
    }

    auto DerpRelayServer::disconnect(std::uint64_t connection_id) -> std::vector<OutboundFrame> {
        std::vector<OutboundFrame> out;
        auto it = std::ranges::find(peers_, connection_id, &PeerSession::connection_id);
        if (it == peers_.end()) return out;
        Key gone = it->node;
        peers_.erase(it);
        stats_.connected_peers = peers_.size();
        if (auto msg = encode_peer_gone(gone, 1)) {
            for (auto const& peer : peers_) out.push_back({peer.connection_id, *msg});
        }
        return out;
    }

    auto DerpRelayServer::has_peer(Key const& node) const noexcept -> bool {
        return std::ranges::any_of(peers_, [&](PeerSession const& p) { return p.node == node; });
    }
}
