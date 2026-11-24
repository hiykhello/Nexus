module tailscale.derp_server;
import std;
import glaze;
import tailscale.box;
import tailscale.derp_info;

namespace tailscale::derp {
    namespace detail {
        struct JsonClientInfo {
            std::int64_t version = 0;
        };
    }

    namespace {
        struct ReadOptions : glaze::opts {
            bool validate_trailing_whitespace = true;
            bool validate_skipped = true;
        };
        inline constexpr auto kClientInfoOpts = [] {
            ReadOptions result;
            result.null_terminated = false;
            result.error_on_unknown_keys = false;
            return result;
        }();
        auto valid_client_info(std::span<std::uint8_t const> plain) -> bool {
            if (plain.empty() || plain.size() > max_info_plaintext) return false;
            auto text = std::string_view(reinterpret_cast<char const*>(plain.data()), plain.size());
            detail::JsonClientInfo info{};
            if (glaze::read<kClientInfoOpts>(info, text)) return false;
            return info.version == static_cast<std::int64_t>(protocol_version);
        }
    }

    auto DerpRelayServer::create(crypto::X25519Private server_key, std::size_t max_peers)
        -> std::expected<DerpRelayServer, std::string> {
        if (max_peers == 0) return std::unexpected("DERP relay max_peers must be positive");
        auto pub = server_key.public_key();
        if (!pub) return std::unexpected("invalid DERP server X25519 key");
        return DerpRelayServer(std::move(server_key), *pub, max_peers);
    }

    auto DerpRelayServer::generate(std::size_t max_peers) -> std::expected<DerpRelayServer, std::string> {
        if (max_peers == 0) return std::unexpected("DERP relay max_peers must be positive");
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
            if (!env || env->sealed.ciphertext.size() > max_info_plaintext + box::tag_size)
                return std::unexpected("malformed DERP client_info");
            auto shared = box::SharedKey::derive(server_key_, env->node);
            if (!shared) return std::unexpected("invalid DERP peer public key");
            std::vector<std::uint8_t> plain(env->sealed.ciphertext.size() - box::tag_size);
            struct CleanseGuard {
                std::vector<std::uint8_t>& bytes;
                ~CleanseGuard() { crypto::cleanse(bytes); }
            } cleanse_plain{plain};
            auto len = shared->open_to(plain, env->sealed.nonce, env->sealed.ciphertext);
            if (!len) return std::unexpected("DERP client_info authentication failed");
            if (!valid_client_info(std::span(plain).first(*len)))
                return std::unexpected("invalid DERP client_info payload");

            std::size_t replaced = 0;
            std::optional<std::uint64_t> evicted_conn;
            std::optional<Key> replaced_node;
            std::vector<std::uint64_t> replaced_senders;
            for (auto const& p : peers_) {
                if (p.connection_id == connection_id || p.node == env->node) {
                    ++replaced;
                    if (p.connection_id != connection_id && p.node == env->node) evicted_conn = p.connection_id;
                    if (p.connection_id == connection_id && p.node != env->node) {
                        replaced_node = p.node;
                        replaced_senders = p.senders;
                    }
                }
            }
            if (peers_.size() - replaced >= max_peers_) return std::unexpected("DERP relay peer limit reached");

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

            std::optional<OutboundFrame> evicted_notice;
            if (evicted_conn) {
                constexpr std::string_view kDuplicate = "duplicate";
                auto health = encode_frame(Type::health,
                    {reinterpret_cast<std::uint8_t const*>(kDuplicate.data()), kDuplicate.size()});
                if (!health) return std::unexpected("failed to encode DERP health");
                evicted_notice = OutboundFrame{*evicted_conn, std::move(*health), true};
            }
            std::optional<std::vector<std::uint8_t>> replaced_gone;
            if (replaced_node) {
                auto gone = encode_peer_gone(*replaced_node, 1);
                if (!gone) return std::unexpected("failed to encode DERP peer_gone");
                replaced_gone = std::move(*gone);
            }

            std::vector<std::uint64_t> inherited_senders;
            for (auto const& p : peers_) {
                if (p.node == env->node) {
                    for (auto cid : p.senders) {
                        if (cid != connection_id && (!evicted_conn || cid != *evicted_conn) &&
                            std::ranges::find(inherited_senders, cid) == inherited_senders.end())
                            inherited_senders.push_back(cid);
                    }
                }
            }
            if (!replaced) peers_.reserve(peers_.size() + 1);
            std::erase_if(peers_, [&](PeerSession const& p) {
                return p.connection_id == connection_id || p.node == env->node;
            });
            if (evicted_conn) {
                for (auto& p : peers_) std::erase(p.senders, *evicted_conn);
            }
            peers_.push_back({connection_id, env->node, false, false, now_ms, std::move(inherited_senders)});
            stats_.connected_peers = peers_.size();

            if (evicted_notice) out.push_back(std::move(*evicted_notice));
            if (replaced_gone) {
                for (auto const& peer : peers_) {
                    if (peer.connection_id == connection_id) continue;
                    if (peer.watcher || std::ranges::find(replaced_senders, peer.connection_id) != replaced_senders.end())
                        out.push_back({peer.connection_id, *replaced_gone});
                }
            }
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
            if (dst->connection_id != connection_id &&
                std::ranges::find(dst->senders, connection_id) == dst->senders.end())
                dst->senders.push_back(connection_id);
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
        auto notifiers = std::move(it->senders);
        peers_.erase(it);
        stats_.connected_peers = peers_.size();
        bool any_target = false;
        for (auto& peer : peers_) {
            std::erase(peer.senders, connection_id);
            any_target |= peer.watcher || std::ranges::find(notifiers, peer.connection_id) != notifiers.end();
        }
        if (any_target) {
            if (auto msg = encode_peer_gone(gone, 1)) {
                for (auto const& peer : peers_) {
                    if (peer.watcher || std::ranges::find(notifiers, peer.connection_id) != notifiers.end())
                        out.push_back({peer.connection_id, *msg});
                }
            }
        }
        return out;
    }

    auto DerpRelayServer::has_peer(Key const& node) const noexcept -> bool {
        return std::ranges::any_of(peers_, [&](PeerSession const& p) { return p.node == node; });
    }
}
