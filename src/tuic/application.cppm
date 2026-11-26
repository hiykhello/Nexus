export module tuic.application;
import std;
import containers.byte_ring;
import crypto;
import tuic.wire;
export import tuic.transport_options;
import quic.connection;
import ngtcp2;
export import tuic.stream_output;
import tuic.stream_input;
import tuic.early_data;

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
            bool accepted_connect = false, pending_connect = false, uni_done = false, released = false, needs_reopen = false;
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
        std::uint64_t next_gen_ = 1, time_ = 0;
        std::size_t cursor_ = 0;
        bool handshake_ = false, authenticated_ = false, auth_failed_ = false, auth_flushed_ = false, stopping_ = false, joined_ = false, issue_tickets_ = false;
        std::int64_t auth_stream_id_ = -1;
        std::deque<std::vector<std::uint8_t>> early_datagrams_{};
        detail::EarlyDataState early_{};
        std::optional<std::size_t> auth_user_;
        std::uint16_t max_udp_payload_ = 0;
        UdpDefragmenter defrag_{};
        auto update_max_udp_payload() noexcept -> void {
            if (!transport_ || !transport_->active()) return;
            auto* peer = ngtcp2::ngtcp2_conn_get_remote_transport_params2(transport_->native());
            max_udp_payload_ = (peer && peer->max_datagram_frame_size > 16)
                ? static_cast<std::uint16_t>(std::min<std::uint64_t>(peer->max_datagram_frame_size - 16, 1136)) : std::uint16_t{0};
        }
        auto datagram_budget(std::size_t out_size) const noexcept -> std::size_t {
            if (!max_udp_payload_ || !transport_ || !transport_->active()) return 0;
            auto limit = std::min(out_size, ngtcp2::ngtcp2_conn_get_path_max_tx_udp_payload_size2(transport_->native()));
            return limit > 64 ? std::min<std::size_t>(max_udp_payload_, limit - 64) : 0;
        }

        auto signal() noexcept -> void { static_assert(noexcept(hooks_.changed())); hooks_.changed(); }

        auto credit(std::int64_t id, std::size_t n) -> int {
            if (!transport_ || !transport_->active() || !n) return 0;
            auto err = ngtcp2::ngtcp2_conn_extend_max_stream_offset(transport_->native(), id, n);
            if (!err) ngtcp2::ngtcp2_conn_extend_max_offset(transport_->native(), n);
            return err;
        }
        auto find(std::int64_t id) noexcept -> StreamState* { for (auto& s : streams_) if (s && s->id == id) return &*s; return nullptr; }
        auto get(StreamHandle h) noexcept -> StreamState* {
            return (h.slot < Streams && streams_[h.slot] && !streams_[h.slot]->released && streams_[h.slot]->generation == h.generation) ? &*streams_[h.slot] : nullptr;
        }
        auto get(StreamHandle h) const noexcept -> StreamState const* {
            return (h.slot < Streams && streams_[h.slot] && !streams_[h.slot]->released && streams_[h.slot]->generation == h.generation) ? &*streams_[h.slot] : nullptr;
        }
        auto allocate_slot(std::int64_t id, bool uni, bool local, Phase phase) noexcept -> std::optional<StreamHandle> {
            if (!next_gen_) return {};
            for (std::size_t i = 0; i < Streams; ++i) if (!streams_[i]) {
                auto gen = next_gen_++; streams_[i].emplace(StreamState{id, gen, uni, local, phase});
                return StreamHandle{static_cast<std::uint16_t>(i), gen};
            }
            return {};
        }
        auto free_slot(std::optional<StreamState>& slot) noexcept -> void {
            if (!slot) return;
            bool const peer = !slot->local, uni = slot->uni; slot.reset();
            if (peer && transport_ && transport_->active()) {
                if (uni) ngtcp2::ngtcp2_conn_extend_max_streams_uni(transport_->native(), 1);
                else ngtcp2::ngtcp2_conn_extend_max_streams_bidi(transport_->native(), 1);
            }
        }
        friend struct detail::UniInput;
        auto handle_uni_complete(StreamState& s) -> int { return detail::UniInput::handle_complete(*this, s); }

        auto process_packet_wire(std::span<std::uint8_t const> wire, bool over_stream) -> int {
            if (!authenticated_) {
                if (server_ && !auth_failed_ && early_datagrams_.size() < 16 && wire.size() <= 2048)
                    early_datagrams_.emplace_back(wire.begin(), wire.end());
                return 0;
            }
            auto parsed = decode_packet(wire);
            if (!parsed) return ngtcp2::err_callback_failure;
            auto ready = defrag_.feed(*parsed, time_);
            if (!ready) {
                auto e = ready.error();
                return (e == WireError::duplicate || e == WireError::conflict || e == WireError::too_large) ? 0 : ngtcp2::err_callback_failure;
            }
            if (*ready) {
                hooks_.udp_packet(IncomingUdpPacket{(*ready)->assoc_id, std::move((*ready)->destination), std::move((*ready)->payload), over_stream});
                signal();
            }
            return 0;
        }

        auto flush_stream(std::span<std::uint8_t> out, std::uint64_t now, ngtcp2::ngtcp2_path* path)
            -> std::expected<std::size_t, int> {
            for (std::size_t step = 0; step < Streams; ++step) {
                auto idx = (cursor_ + step) % Streams;
                auto& opt = streams_[idx];
                if (!opt || opt->released || opt->needs_reopen || opt->id < 0) continue;
                auto& s = *opt;
                auto pending=s.tx.pending();
                auto need_fin=s.local_fin && !s.fin_queued && !pending;
                if (!pending && !need_fin) continue;
                auto segments=s.tx.view();
                std::array<ngtcp2::ngtcp2_vec,2> vectors{};
                std::size_t count=0;
                for (auto bytes : segments)
                    if (!bytes.empty()) vectors[count++]={const_cast<std::uint8_t*>(bytes.data()),bytes.size()};
                auto send_fin=s.local_fin;
                auto nwritten=transport_->write_stream(out,path,nullptr,s.id,std::span(vectors).first(count),send_fin,now);
                if (!nwritten) {
                    if (nwritten.error() == ngtcp2::err_stream_data_blocked) continue;
                    return std::unexpected(nwritten.error());
                }
                if (nwritten->stream_bytes>0) s.tx.submit(static_cast<std::size_t>(nwritten->stream_bytes));
                if (send_fin && !s.tx.pending() && nwritten->stream_bytes>=0) {
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
        auto ready_for_traffic(bool zero_rtt) const noexcept -> bool { return authenticated_ || (!server_ && zero_rtt && early_.client_can_send()); }
        auto early_offered() const noexcept -> bool { return early_.offered; }
        auto early_accepted() const noexcept -> bool { return early_.accepted || early_.server_early_accepted; }
        auto early_rejected() const noexcept -> bool { return early_.rejected; }
        auto set_issue_tickets(bool enable) noexcept -> void { issue_tickets_ = enable; }
        auto allow_early_data() noexcept -> void { update_max_udp_payload(); early_.allow_client(); signal(); }
        auto accept_early_data() noexcept -> void { early_.accept_client(); signal(); }
        auto reject_early_data() -> void { early_.reject_client(streams_, datagrams_); signal(); }
        auto accept_server_early_data() noexcept -> void { early_.accept_server(); }
        auto auth_failed() const noexcept -> bool { return auth_failed_; }
        auto auth_user() const noexcept -> std::optional<std::size_t> { return auth_user_; }
        auto max_udp_payload() const noexcept -> std::uint16_t { return max_udp_payload_; }

        auto open_uni_write(std::span<std::uint8_t const> wire, std::int64_t* out_id = nullptr) -> bool {
            std::int64_t id = -1;
            if (ngtcp2::ngtcp2_conn_open_uni_stream(transport_->native(), &id, nullptr)) return false;
            auto slot = allocate_slot(id, true, true, Phase::ready);
            if (!slot) { ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0x100); return false; }
            auto* s = get(*slot);
            if (!s->tx.append(wire)) { release_stream(*slot); return false; }
            s->local_fin = true;
            if (out_id) *out_id = id;
            return true;
        }
        auto handshake_complete(Transport& t) -> int {
            if (stopping_ || &t != transport_ || !tls_.complete()) return ngtcp2::err_callback_failure;
            update_max_udp_payload(); handshake_ = true;
            if (!server_) {
                auto exp = tls_.exporter_master();
                if (!exp) return ngtcp2::err_callback_failure;
                auto token = derive_auth_token(exp->hash, exp->secret, client_uuid_, client_password_);
                if (!token) return ngtcp2::err_callback_failure;
                auto wire = encode_authenticate(Authenticate{client_uuid_, *token});
                if (!open_uni_write(wire, &auth_stream_id_)) return ngtcp2::err_callback_failure;
                authenticated_ = true;
                if (auto err = early_.reopen_rejected_streams(t.native(), streams_)) return err;
            } else {
                if constexpr (requires { tls_.issue_early_ticket(t, 86400u, 2u); }) {
                    if (issue_tickets_) (void)tls_.issue_early_ticket(t, 86400u, 2u);
                }
            }
            signal(); return 0;
        }

        auto handshake_confirmed(Transport&) -> int { return 0; }

        auto open_connect(TargetAddress const& target) -> std::expected<StreamHandle, int> {
            bool const can_early = !server_ && early_.client_can_send();
            if (server_ || (!authenticated_ && !can_early) || stopping_ || !transport_ || !transport_->active())
                return std::unexpected(ngtcp2::err_callback_failure);
            auto hdr = encode_connect(target);
            if (!hdr) return std::unexpected(ngtcp2::err_invalid_argument);
            std::int64_t id = -1;
            if (auto err = ngtcp2::ngtcp2_conn_open_bidi_stream(transport_->native(), &id, nullptr)) return std::unexpected(err);
            auto slot = allocate_slot(id, false, true, Phase::ready);
            if (!slot) { ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0x100); return std::unexpected(ngtcp2::err_nomem); }
            auto* s = get(*slot);
            if (!s->tx.append(*hdr)) { release_stream(*slot); return std::unexpected(ngtcp2::err_invalid_argument); }
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
            s->released = true; s->rx.clear();
            if (s->phase == Phase::closed || s->id < 0 || !transport_ || !transport_->active()) {
                free_slot(streams_[h.slot]); signal(); return;
            }
            auto err = ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, s->id, 0);
            if (streams_[h.slot] && streams_[h.slot]->generation == h.generation) {
                if (err == 0 && (streams_[h.slot]->phase == Phase::closed || streams_[h.slot]->tx.empty()))
                    free_slot(streams_[h.slot]);
            }
            signal();
        }
        auto read_stream(StreamHandle h, std::span<std::uint8_t> out) -> std::expected<std::size_t, bool> {
            auto* s = get(h); if (!s) return std::unexpected(false);
            if (!s->rx.empty()) {
                auto n = std::min(out.size(), s->rx.size());
                std::copy_n(s->rx.begin(), n, out.begin());
                s->rx.erase(s->rx.begin(), s->rx.begin() + static_cast<std::ptrdiff_t>(n));
                if (s->id >= 0) { if (auto err = credit(s->id, n)) return std::unexpected(true); }
                return n;
            }
            if (s->reset_flag) return std::unexpected(true);
            return std::size_t{0};
        }

        auto send_udp(std::uint16_t assoc_id, TargetAddress const& addr, std::span<std::uint8_t const> payload, bool over_stream) -> bool {
            bool const can_early = !server_ && early_.client_can_send();
            if ((!authenticated_ && !can_early) || stopping_ || !transport_ || !transport_->active() || (!over_stream && !max_udp_payload_)) return false;
            auto frags = fragment_udp_packet(assoc_id, next_pkt_id_++, addr, payload, over_stream ? std::uint16_t{1200} : max_udp_payload_);
            if (!frags) return false;
            if (over_stream) {
                for (auto& f : *frags) if (!open_uni_write(f)) return false;
            } else {
                if (datagrams_.size() + frags->size() > max_datagram_queue) return false;
                for (auto& f : *frags) datagrams_.push_back(std::move(f));
            }
            signal(); return true;
        }
        auto send_dissociate(std::uint16_t assoc_id) -> bool {
            if (server_ || !authenticated_ || stopping_ || !transport_ || !transport_->active()) return false;
            auto wire = encode_dissociate(assoc_id);
            if (!open_uni_write(wire)) return false;
            signal(); return true;
        }
        auto send_heartbeat() -> bool {
            if (!authenticated_ || stopping_ || !max_udp_payload_ || datagrams_.size() >= max_datagram_queue) return false;
            auto hb = encode_heartbeat(); datagrams_.emplace_back(hb.begin(), hb.end()); signal(); return true;
        }

        auto early_stream_data(Transport& t, std::uint32_t flags, std::int64_t id, std::uint64_t off, std::span<std::uint8_t const> bytes, void* p) -> int {
            return (!server_ || !early_.server_early_accepted) ? ngtcp2::err_callback_failure : stream_data_impl(t, flags, id, off, bytes, p, true);
        }
        auto stream_data(Transport& t, std::uint32_t flags, std::int64_t id, std::uint64_t off, std::span<std::uint8_t const> bytes, void* p) -> int {
            return stream_data_impl(t, flags, id, off, bytes, p, false);
        }
        auto stream_data_impl(Transport&, std::uint32_t flags, std::int64_t id, std::uint64_t, std::span<std::uint8_t const> bytes, void*, bool is_early) -> int {
            if (stopping_ || (!handshake_ && !is_early) || auth_failed_) return ngtcp2::err_callback_failure;
            bool fin = (flags & ngtcp2::stream_data_flag_fin) != 0;
            bool uni = (id & 2) != 0;
            auto* s = find(id);
            if (!s) {
                bool peer_initiated = server_ ? ((id & 1) == 0) : ((id & 1) == 1);
                if (!peer_initiated) return ngtcp2::err_callback_failure;
                auto h = allocate_slot(id, uni, false, uni ? Phase::ready : Phase::header);
                if (!h) return ngtcp2::err_callback_failure;
                s = get(*h);
            }
            if (s->rx.size() + bytes.size() > Window * 2) return ngtcp2::err_callback_failure;
            if (uni) {
                if (s->uni_done) {
                    if (!bytes.empty()) return ngtcp2::err_callback_failure;
                    if (fin) for (auto& entry : streams_) if (entry && &*entry == s) { free_slot(entry); break; }
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
                    if (fin) for (auto& entry : streams_) if (entry && &*entry == s) { free_slot(entry); break; }
                    return err;
                }
                return 0;
            }
            s->rx.insert(s->rx.end(), bytes.begin(), bytes.end());
            if (s->phase == Phase::header) {
                auto parsed = decode_connect(s->rx);
                if (!parsed) {
                    if (parsed.error() == WireError::incomplete && !fin) return 0;
                    return ngtcp2::err_callback_failure;
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
            if (!s->tx.acknowledge(offset,size)) return ngtcp2::err_callback_failure;
            if (s->uni && s->local && s->fin_queued && s->tx.empty()) {
                for (auto& entry : streams_) if (entry && &*entry == s) { entry.reset(); break; }
            }
            signal();
            return 0;
        }

        auto stream_close(Transport&, std::uint32_t, std::int64_t id, std::uint64_t, std::uint64_t, void*) -> int {
            if (!server_ && !handshake_ && early_.client_can_send()) return 0;
            for (auto& entry : streams_) if (entry && entry->id == id) {
                entry->peer_fin = true; entry->phase = Phase::closed;
                if (entry->uni || entry->released || (!entry->local && !entry->accepted_connect)) free_slot(entry);
                break;
            }
            signal(); return 0;
        }
        auto stream_reset(Transport&, std::int64_t id, std::uint64_t, std::uint64_t, void*) -> int {
            for (auto& entry : streams_) if (entry && entry->id == id) {
                entry->reset_flag = true;
                if (entry->uni && !entry->local && entry->tx.empty()) { entry->phase = Phase::closed; free_slot(entry); }
                else if (!entry->local && !entry->uni && !entry->accepted_connect) {
                    entry->pending_connect = false;
                    if (transport_ && transport_->active()) (void)ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0);
                }
                break;
            }
            signal(); return 0;
        }
        auto stop_sending(Transport&, std::int64_t id, std::uint64_t, void*) -> int {
            for (std::size_t i = 0; i < Streams; ++i) if (auto& entry = streams_[i]; entry && entry->id == id) {
                entry->reset_flag = true;
                if (entry->uni && entry->local) {
                    auto gen = entry->generation;
                    if (transport_ && transport_->active()) (void)ngtcp2::ngtcp2_conn_shutdown_stream_write(transport_->native(), 0, id, 0);
                    if (streams_[i] && streams_[i]->generation == gen && (streams_[i]->phase == Phase::closed || streams_[i]->tx.empty())) streams_[i].reset();
                } else if (!entry->local && !entry->uni && !entry->accepted_connect) {
                    entry->pending_connect = false;
                    if (transport_ && transport_->active()) (void)ngtcp2::ngtcp2_conn_shutdown_stream(transport_->native(), 0, id, 0);
                }
                break;
            }
            signal(); return 0;
        }
        auto stream_limit(Transport&, std::int64_t, std::uint64_t, void*) -> int { signal(); return 0; }
        auto stream_limit(Transport&, bool, std::uint64_t) -> int { signal(); return 0; }
        auto early_datagram(Transport& t, std::span<std::uint8_t const> bytes) -> int {
            return (!server_ || !early_.server_early_accepted) ? ngtcp2::err_callback_failure : datagram_impl(t, bytes, true);
        }
        auto datagram(Transport& t, std::span<std::uint8_t const> bytes) -> int { return datagram_impl(t, bytes, false); }
        auto datagram_impl(Transport&, std::span<std::uint8_t const> bytes, bool is_early) -> int {
            if (stopping_ || (!handshake_ && !is_early) || bytes.size() < 2 || bytes[0] != version) return ngtcp2::err_callback_failure;
            if (bytes[1] == static_cast<std::uint8_t>(Command::heartbeat)) return decode_heartbeat(bytes) ? 0 : ngtcp2::err_callback_failure;
            if (bytes[1] == static_cast<std::uint8_t>(Command::packet)) return process_packet_wire(bytes, false);
            return ngtcp2::err_callback_failure;
        }
        auto connection_closed(Transport&, int) noexcept -> void {
            for (auto& entry : streams_) if (entry) { entry->phase = Phase::closed; entry->reset_flag = true;
                if (entry->uni || entry->released || (!entry->local && !entry->accepted_connect)) entry.reset(); }
            request_stop(); tls_.cancel();
        }
        auto add_connection_id(Transport&, ngtcp2::ngtcp2_cid const& id, ngtcp2::ngtcp2_stateless_reset_token const& tok) -> int {
            if constexpr (requires { hooks_.add_connection_id(id, tok); }) return hooks_.add_connection_id(id, tok); else return 0;
        }
        auto remove_connection_id(Transport&, ngtcp2::ngtcp2_cid const& id) -> int {
            if constexpr (requires { hooks_.remove_connection_id(id); }) return hooks_.remove_connection_id(id); else return 0;
        }
        auto output(std::span<std::uint8_t> out, std::uint64_t now, ngtcp2::ngtcp2_path* path = nullptr) -> std::expected<std::size_t, int> {
            time_ = now;
            if (stopping_ || !transport_) return std::unexpected(ngtcp2::err_callback_failure);
            bool const client_early = !server_ && !handshake_ && early_.client_can_send();
            if (!server_ && handshake_ && !auth_flushed_) {
                auto first_stream = flush_stream(out, now, path);
                if (!first_stream || *first_stream) return first_stream;
            }
            if (authenticated_ || client_early) {
                auto budget = datagram_budget(out.size());
                while (!datagrams_.empty()) {
                    auto& d = datagrams_.front();
                    if (!budget || d.size() > budget) { datagrams_.pop_front(); continue; }
                    ngtcp2::ngtcp2_vec vec{d.data(), d.size()};
                    auto res = transport_->write_datagram(out, path, nullptr, 0, std::span(&vec, 1), now);
                    if (!res) return std::unexpected(res.error());
                    if (res->accepted) {
                        if (client_early) early_.record_client_datagram(std::move(d));
                        datagrams_.pop_front();
                    } else if (!res->packet_bytes) break;
                    if (res->packet_bytes) return res->packet_bytes;
                }
                auto stream_bytes = flush_stream(out, now, path);
                if (!stream_bytes) return std::unexpected(stream_bytes.error());
                if (*stream_bytes) return *stream_bytes;
            }
            return transport_->write_packet(out, path, nullptr, now);
        }
    };
}
