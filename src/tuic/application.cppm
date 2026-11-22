export module tuic.application;
import std;
import containers.byte_ring;
import crypto;
import tuic.wire;
export import tuic.transport_options;
import quic.connection;
import nexus.thirdparty.ngtcp2;

namespace tuic::detail {
#include "stream_output.hpp"
}

export namespace tuic {
    struct UserCredential {
        std::array<std::uint8_t, 16> uuid{};
        std::string password;
        std::string name;
    };


    struct StreamHandle {
        std::uint16_t slot = 0;
        std::uint64_t generation = 0;
        auto operator==(StreamHandle const&) const noexcept -> bool = default;
    };

    struct IncomingUdpPacket {
        std::uint16_t assoc_id = 0;
        TargetAddress destination{};
        std::vector<std::uint8_t> payload;
        bool over_stream = false;
    };

    template<class Tls, class Hooks, std::size_t Streams = 64, std::size_t Window = 32768>
    class Application {
        static_assert(Streams && Streams <= 65535 && Window >= 4096);
    public:
        using Transport = quic::Connection<Tls, Application>;
        static constexpr std::size_t max_datagram_queue = 64;

        enum class Phase : std::uint8_t { header, ready, closed };

        struct StreamState {
            std::int64_t id = -1;
            std::uint64_t generation = 0;
            bool uni = false, local = false;
            Phase phase = Phase::ready;
            std::vector<std::uint8_t> rx;
            detail::StreamOutput<Window*2> tx;
            bool local_fin = false, fin_queued = false, peer_fin = false, reset_flag = false;
            bool accepted_connect = false, pending_connect = false, uni_done = false;
            TargetAddress target{};
        };

    private:
        Tls& tls_;
        Hooks& hooks_;
        Transport* transport_ = nullptr;
        bool server_ = false;
        std::array<std::uint8_t, 16> client_uuid_{};
        std::string client_password_;
        std::span<UserCredential const> server_users_;
        std::array<std::optional<StreamState>, Streams> streams_{};
        std::deque<std::vector<std::uint8_t>> datagrams_{};
        std::uint16_t next_pkt_id_ = 1;
        std::uint64_t next_gen_ = 1;
        std::uint64_t time_ = 0;
        std::size_t cursor_ = 0;
        bool handshake_ = false, authenticated_ = false, auth_failed_ = false, auth_flushed_ = false, stopping_ = false, joined_ = false;
        std::int64_t auth_stream_id_ = -1;
        std::deque<std::vector<std::uint8_t>> early_datagrams_{};
        std::optional<std::size_t> auth_user_;
        std::uint16_t max_udp_payload_ = 1200;
        UdpDefragmenter defrag_{};

        auto signal() noexcept -> void { static_assert(noexcept(hooks_.changed())); hooks_.changed(); }

        auto credit(std::int64_t id, std::size_t n) -> int {
            if (!transport_ || !transport_->active() || !n) return 0;
            auto err = nex::ngtcp2::ngtcp2_conn_extend_max_stream_offset(transport_->native(), id, n);
            if (!err) nex::ngtcp2::ngtcp2_conn_extend_max_offset(transport_->native(), n);
            return err;
        }

        auto find(std::int64_t id) noexcept -> StreamState* {
            for (auto& s : streams_) if (s && s->id == id) return &*s;
            return nullptr;
        }

        auto get(StreamHandle h) noexcept -> StreamState* {
            return (h.slot < Streams && streams_[h.slot] && streams_[h.slot]->generation == h.generation) ? &*streams_[h.slot] : nullptr;
        }
        auto get(StreamHandle h) const noexcept -> StreamState const* {
            return (h.slot < Streams && streams_[h.slot] && streams_[h.slot]->generation == h.generation) ? &*streams_[h.slot] : nullptr;
        }

        auto allocate_slot(std::int64_t id, bool uni, bool local, Phase phase) noexcept -> std::optional<StreamHandle> {
            if (!next_gen_) return {};
            for (std::size_t i = 0; i < Streams; ++i) {
                if (!streams_[i]) {
                    auto gen = next_gen_++;
                    streams_[i].emplace(StreamState{id, gen, uni, local, phase});
                    return StreamHandle{static_cast<std::uint16_t>(i), gen};
                }
            }
            return {};
        }

#include "stream_input.hpp"

        auto process_packet_wire(std::span<std::uint8_t const> wire, bool over_stream) -> int {
            if (!authenticated_) {
                if (server_ && !auth_failed_ && early_datagrams_.size() < 4 && wire.size() <= 2048)
                    early_datagrams_.emplace_back(wire.begin(), wire.end());
                return 0;
            }
            auto parsed = decode_packet(wire);
            if (!parsed) return nex::ngtcp2::err_callback_failure;
            auto ready = defrag_.feed(*parsed);
            if (!ready) return nex::ngtcp2::err_callback_failure;
            if (*ready) {
                hooks_.udp_packet(IncomingUdpPacket{
                    (*ready)->assoc_id, std::move((*ready)->destination), std::move((*ready)->payload), over_stream});
                signal();
            }
            return 0;
        }

        auto flush_stream(std::span<std::uint8_t> out, std::uint64_t now, nex::ngtcp2::ngtcp2_path* path)
            -> std::expected<std::size_t, int> {
            for (std::size_t step = 0; step < Streams; ++step) {
                auto idx = (cursor_ + step) % Streams;
                auto& opt = streams_[idx];
                if (!opt) continue;
                auto& s = *opt;
                auto pending=s.tx.pending();
                auto need_fin=s.local_fin && !s.fin_queued && !pending;
                if (!pending && !need_fin) continue;
                auto segments=s.tx.view();
                std::array<nex::ngtcp2::ngtcp2_vec,2> vectors{};
                std::size_t count=0;
                for (auto bytes : segments)
                    if (!bytes.empty()) vectors[count++]={const_cast<std::uint8_t*>(bytes.data()),bytes.size()};
                auto send_fin=s.local_fin;
                auto nwritten=transport_->write_stream(out,path,nullptr,s.id,std::span(vectors).first(count),send_fin,now);
                if (!nwritten) {
                    if (nwritten.error() == nex::ngtcp2::err_stream_data_blocked) continue;
                    return std::unexpected(nwritten.error());
                }
                if (nwritten->stream_bytes>0) s.tx.submit(static_cast<std::size_t>(nwritten->stream_bytes));
                if (send_fin && !s.tx.pending() && (nwritten->stream_bytes>=0 || need_fin)) {
                    s.fin_queued = true;
                    if (!server_ && s.id == auth_stream_id_) auth_flushed_ = true;
                }
                if (nwritten->packet_bytes) {
                    cursor_ = (idx + 1) % Streams;
                    signal();
                    return nwritten->packet_bytes;
                }
            }
            return 0;
        }

    public:
        Application(Tls& tls, Hooks& hooks, std::array<std::uint8_t, 16> uuid, std::string password)
            : tls_(tls), hooks_(hooks), server_(false), client_uuid_(uuid), client_password_(std::move(password)) {}

        Application(Tls& tls, Hooks& hooks, std::span<UserCredential const> users)
            : tls_(tls), hooks_(hooks), server_(true), server_users_(users) {}

        Application(Application const&) = delete;
        auto operator=(Application const&) -> Application& = delete;

        auto attach(Transport& t) noexcept -> void { transport_ = &t; }
        auto time(std::uint64_t now) noexcept -> void { time_ = now; }
        auto request_stop() noexcept -> void {
            if (std::exchange(stopping_,true)) return;
            hooks_.transport_closed();
            signal();
        }
        auto stopping() const noexcept -> bool { return stopping_; }
        auto joined() noexcept -> void { joined_ = true; }
        auto drain() noexcept -> void {}
        auto authenticated() const noexcept -> bool { return authenticated_; }
        auto auth_failed() const noexcept -> bool { return auth_failed_; }
        auto auth_user() const noexcept -> std::optional<std::size_t> { return auth_user_; }
        auto max_udp_payload() const noexcept -> std::uint16_t { return max_udp_payload_; }

        auto handshake_complete(Transport& t) -> int {
            if (stopping_ || &t != transport_ || !tls_.complete()) return nex::ngtcp2::err_callback_failure;
            auto* peer = nex::ngtcp2::ngtcp2_conn_get_remote_transport_params2(t.native());
            if (peer && peer->max_datagram_frame_size > 16)
                max_udp_payload_ = static_cast<std::uint16_t>(std::min<std::uint64_t>(peer->max_datagram_frame_size - 16, 1400));
            handshake_ = true;
            if (!server_) {
                auto exp = tls_.exporter_master();
                if (!exp) return nex::ngtcp2::err_callback_failure;
                auto token = derive_auth_token(exp->hash, exp->secret, client_uuid_, client_password_);
                if (!token) return nex::ngtcp2::err_callback_failure;
                auto wire = encode_authenticate(Authenticate{client_uuid_, *token});
                std::int64_t id = -1;
                if (nex::ngtcp2::ngtcp2_conn_open_uni_stream(t.native(), &id, nullptr)) return nex::ngtcp2::err_callback_failure;
                auto slot = allocate_slot(id, true, true, Phase::ready);
                if (!slot) return nex::ngtcp2::err_callback_failure;
                auto* s = get(*slot);
                if (!s->tx.append(wire)) return nex::ngtcp2::err_callback_failure;
                s->local_fin = true;
                auth_stream_id_ = id;
                authenticated_ = true;
            }
            signal();
            return 0;
        }

        auto handshake_confirmed(Transport&) -> int { return 0; }

        auto open_connect(TargetAddress const& target) -> std::expected<StreamHandle, int> {
            if (server_ || !handshake_ || !authenticated_ || stopping_ || !transport_ || !transport_->active())
                return std::unexpected(nex::ngtcp2::err_callback_failure);
            auto hdr = encode_connect(target);
            if (!hdr) return std::unexpected(nex::ngtcp2::err_invalid_argument);
            std::int64_t id = -1;
            if (auto err = nex::ngtcp2::ngtcp2_conn_open_bidi_stream(transport_->native(), &id, nullptr))
                return std::unexpected(err);
            auto slot = allocate_slot(id, false, true, Phase::ready);
            if (!slot) {
                nex::ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0x100);
                return std::unexpected(nex::ngtcp2::err_nomem);
            }
            auto* s = get(*slot);
            if (!s->tx.append(*hdr)) {
                release_stream(*slot);
                return std::unexpected(nex::ngtcp2::err_invalid_argument);
            }
            signal();
            return *slot;
        }

        auto send_stream(StreamHandle h, std::span<std::uint8_t const> bytes, bool fin = false) -> bool {
            auto* s = get(h);
            if (!s || stopping_ || s->reset_flag || s->local_fin) return false;
            if (!s->tx.append(bytes)) return false;
            if (fin) s->local_fin = true;
            signal();
            return true;
        }

        auto has_readable(StreamHandle h) const noexcept -> bool { auto const* s = get(h); return s && (!s->rx.empty() || s->peer_fin || s->reset_flag); }
        auto stream_eof(StreamHandle h) const noexcept -> bool { auto const* s = get(h); return !s || (s->rx.empty() && s->peer_fin); }
        auto stream_failed(StreamHandle h) const noexcept -> bool { auto const* s = get(h); return !s || s->reset_flag; }
        auto writable(StreamHandle h, std::size_t pending_bytes = 1) const noexcept -> bool {
            auto const* s = get(h);
            return s && !stopping_ && !s->reset_flag && !s->local_fin && s->tx.available(pending_bytes);
        }
        auto close_stream_write(StreamHandle h) -> bool {
            auto* s = get(h); if (!s) return false; s->local_fin = true; signal(); return true;
        }

        auto release_stream(StreamHandle h) noexcept -> void {
            auto* s = get(h); if (!s) return;
            if (transport_ && transport_->active() && s->phase != Phase::closed)
                nex::ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, s->id, 0);
            streams_[h.slot].reset(); signal();
        }
        auto read_stream(StreamHandle h, std::span<std::uint8_t> out) -> std::expected<std::size_t, bool> {
            auto* s = get(h); if (!s) return std::unexpected(false);
            if (!s->rx.empty()) {
                auto n = std::min(out.size(), s->rx.size());
                std::copy_n(s->rx.begin(), n, out.begin());
                s->rx.erase(s->rx.begin(), s->rx.begin() + static_cast<std::ptrdiff_t>(n));
                if (auto err = credit(s->id, n)) return std::unexpected(true);
                return n;
            }
            if (s->reset_flag) return std::unexpected(true);
            return std::size_t{0};
        }

        auto send_udp(std::uint16_t assoc_id, TargetAddress const& addr, std::span<std::uint8_t const> payload, bool over_stream) -> bool {
            if (!authenticated_ || stopping_ || !transport_ || !transport_->active()) return false;
            auto pkt_id = next_pkt_id_++;
            auto limit = over_stream ? std::uint16_t{1200} : max_udp_payload_;
            auto frags = fragment_udp_packet(assoc_id, pkt_id, addr, payload, limit);
            if (!frags) return false;
            if (over_stream) {
                for (auto& f : *frags) {
                    std::int64_t id = -1;
                    if (nex::ngtcp2::ngtcp2_conn_open_uni_stream(transport_->native(), &id, nullptr)) return false;
                    auto slot = allocate_slot(id, true, true, Phase::ready);
                    if (!slot) {
                        nex::ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0x100);
                        return false;
                    }
                    auto* s = get(*slot);
                    if (!s->tx.append(f)) {
                        release_stream(*slot);
                        return false;
                    }
                    s->local_fin = true;
                }
            } else {
                if (datagrams_.size() + frags->size() > max_datagram_queue) return false;
                for (auto& f : *frags) datagrams_.push_back(std::move(f));
            }
            signal();
            return true;
        }

        auto send_dissociate(std::uint16_t assoc_id) -> bool {
            if (server_ || !authenticated_ || stopping_ || !transport_ || !transport_->active()) return false;
            std::int64_t id = -1;
            if (nex::ngtcp2::ngtcp2_conn_open_uni_stream(transport_->native(), &id, nullptr)) return false;
            auto slot = allocate_slot(id, true, true, Phase::ready);
            if (!slot) return false;
            auto* s = get(*slot);
            auto wire = encode_dissociate(assoc_id);
            if (!s->tx.append(wire)) {
                release_stream(*slot);
                return false;
            }
            s->local_fin = true;
            signal();
            return true;
        }

        auto send_heartbeat() -> bool {
            if (!authenticated_ || stopping_ || datagrams_.size() >= max_datagram_queue) return false;
            auto hb = encode_heartbeat();
            datagrams_.emplace_back(hb.begin(), hb.end());
            signal();
            return true;
        }

        auto stream_data(Transport&, std::uint32_t flags, std::int64_t id, std::uint64_t, std::span<std::uint8_t const> bytes, void*) -> int {
            if (stopping_ || !handshake_ || auth_failed_) return nex::ngtcp2::err_callback_failure;
            bool fin = (flags & nex::ngtcp2::stream_data_flag_fin) != 0;
            bool uni = (id & 2) != 0;
            auto* s = find(id);
            if (!s) {
                bool peer_initiated = server_ ? ((id & 1) == 0) : ((id & 1) == 1);
                if (!peer_initiated) return nex::ngtcp2::err_callback_failure;
                auto h = allocate_slot(id, uni, false, uni ? Phase::ready : Phase::header);
                if (!h) return nex::ngtcp2::err_callback_failure;
                s = get(*h);
            }
            if (s->rx.size() + bytes.size() > Window * 2) return nex::ngtcp2::err_callback_failure;
            if (uni) {
                if (s->uni_done) {
                    if (!bytes.empty()) return nex::ngtcp2::err_callback_failure;
                    if (fin) for (auto& entry : streams_) if (entry && &*entry == s) { entry.reset(); break; }
                    return 0;
                }
                s->rx.insert(s->rx.end(), bytes.begin(), bytes.end());
                if (auto err = credit(id, bytes.size())) return err;
                bool fixed_ready = s->rx.size() >= 2 && s->rx[0] == version &&
                    ((s->rx[1] == static_cast<std::uint8_t>(Command::authenticate) && s->rx.size() >= 50) ||
                     (s->rx[1] == static_cast<std::uint8_t>(Command::dissociate) && s->rx.size() >= 4));
                if (fixed_ready || fin) {
                    auto err = handle_uni_complete(*s);
                    s->uni_done = true;
                    if (fin) for (auto& entry : streams_) if (entry && &*entry == s) { entry.reset(); break; }
                    return err;
                }
                return 0;
            }
            s->rx.insert(s->rx.end(), bytes.begin(), bytes.end());
            if (s->phase == Phase::header) {
                auto parsed = decode_connect(s->rx);
                if (!parsed) {
                    if (parsed.error() == WireError::incomplete && !fin) return 0;
                    return nex::ngtcp2::err_callback_failure;
                }
                if (auto err = credit(id, parsed->second)) return err;
                s->target = std::move(parsed->first);
                s->rx.erase(s->rx.begin(), s->rx.begin() + static_cast<std::ptrdiff_t>(parsed->second));
                s->phase = Phase::ready;
                if (!authenticated_) s->pending_connect = true;
                else if (!s->accepted_connect) {
                    s->accepted_connect = true;
                    StreamHandle h{};
                    for (std::size_t i = 0; i < Streams; ++i)
                        if (streams_[i] && &*streams_[i] == s) { h = {static_cast<std::uint16_t>(i), s->generation}; break; }
                    hooks_.connect_stream(h, s->target);
                }
            }
            if (fin) s->peer_fin = true;
            signal();
            return 0;
        }

        auto stream_acked(Transport&,std::int64_t id,std::uint64_t offset,std::uint64_t size,void*) -> int {
            auto* s=find(id);
            if (!s) return 0;
            if (!s->tx.acknowledge(offset,size)) return nex::ngtcp2::err_callback_failure;
            if (s->uni && s->local && s->fin_queued && s->tx.empty()) {
                for (auto& entry : streams_) if (entry && &*entry == s) { entry.reset(); break; }
            }
            signal();
            return 0;
        }

        auto stream_close(Transport&, std::uint32_t, std::int64_t id, std::uint64_t, std::uint64_t, void*) -> int {
            if (auto* s = find(id)) { s->peer_fin = true; s->phase = Phase::closed; }
            signal();
            return 0;
        }
        auto stream_reset(Transport&, std::int64_t id, std::uint64_t, std::uint64_t, void*) -> int {
            if (auto* s = find(id)) s->reset_flag = true; signal(); return 0;
        }
        auto stop_sending(Transport&, std::int64_t id, std::uint64_t, void*) -> int {
            if (auto* s = find(id)) s->reset_flag = true; signal(); return 0;
        }
        auto stream_limit(Transport&, std::int64_t, std::uint64_t, void*) -> int { signal(); return 0; }
        auto stream_limit(Transport&, bool, std::uint64_t) -> int { signal(); return 0; }
        auto datagram(Transport&, std::span<std::uint8_t const> bytes) -> int {
            if (stopping_ || !handshake_ || bytes.size() < 2 || bytes[0] != version) return nex::ngtcp2::err_callback_failure;
            if (bytes[1] == static_cast<std::uint8_t>(Command::heartbeat))
                return decode_heartbeat(bytes) ? 0 : nex::ngtcp2::err_callback_failure;
            if (bytes[1] == static_cast<std::uint8_t>(Command::packet)) return process_packet_wire(bytes, false);
            return nex::ngtcp2::err_callback_failure;
        }
        auto connection_closed(Transport&, int) noexcept -> void { request_stop(); tls_.cancel(); }
        auto add_connection_id(Transport&, nex::ngtcp2::ngtcp2_cid const& id, nex::ngtcp2::ngtcp2_stateless_reset_token const& tok) -> int {
            if constexpr (requires { hooks_.add_connection_id(id, tok); }) return hooks_.add_connection_id(id, tok); else return 0;
        }
        auto remove_connection_id(Transport&, nex::ngtcp2::ngtcp2_cid const& id) -> int {
            if constexpr (requires { hooks_.remove_connection_id(id); }) return hooks_.remove_connection_id(id); else return 0;
        }

        auto output(std::span<std::uint8_t> out, std::uint64_t now, nex::ngtcp2::ngtcp2_path* path = nullptr)
            -> std::expected<std::size_t, int> {
            time_ = now;
            if (stopping_ || !transport_) return std::unexpected(nex::ngtcp2::err_callback_failure);
            if (!server_ && !auth_flushed_) {
                auto first_stream = flush_stream(out, now, path);
                if (!first_stream || *first_stream) return first_stream;
            }
            while (!datagrams_.empty()) {
                auto const& d = datagrams_.front();
                nex::ngtcp2::ngtcp2_vec vec{const_cast<std::uint8_t*>(d.data()), d.size()};
                auto res = transport_->write_datagram(out, path, nullptr, 0, std::span(&vec, 1), now);
                if (!res) return std::unexpected(res.error());
                if (res->accepted) datagrams_.pop_front();
                else if (!res->packet_bytes) break;
                if (res->packet_bytes) return res->packet_bytes;
            }
            auto stream_bytes = flush_stream(out, now, path);
            if (!stream_bytes) return std::unexpected(stream_bytes.error());
            if (*stream_bytes) return *stream_bytes;
            return transport_->write_packet(out, path, nullptr, now);
        }
    };
}
