// TUIC unidirectional control/packet stream handler module.
export module tuic.stream_input;
import std;
import crypto;
import tuic.wire;
import ngtcp2;

export namespace tuic::detail {
    // Non-owning flat open-addressing UUID hash index for O(1), zero-allocation TUIC auth.
    class UserIndex {
        static constexpr std::uint32_t kEmpty = 0xffffffffu;
        std::vector<std::uint32_t> buckets_;
        std::uint64_t seed_ = 0;

        static auto splitmix64(std::uint64_t x) noexcept -> std::uint64_t {
            x += 0x9e3779b97f4a7c15ULL;
            x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
            x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
            return x ^ (x >> 31);
        }
        static auto hash_uuid(std::array<std::uint8_t, 16> const& u, std::uint64_t seed) noexcept -> std::uint64_t {
            std::uint64_t lo = 0, hi = 0;
            std::memcpy(&lo, u.data(), 8);
            std::memcpy(&hi, u.data() + 8, 8);
            return splitmix64(lo ^ seed) ^ splitmix64(hi ^ (seed * 0x9e3779b97f4a7c15ULL + 1u));
        }
    public:
        UserIndex() = default;
        template<class User>
        explicit UserIndex(std::span<User const> users) {
            if (users.empty()) return;
            seed_ = 0x517cc1b727220a95ULL;
            (void)crypto::random_bytes(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&seed_), sizeof(seed_)));
            std::size_t cap = 4;
            while (cap < users.size() * 2) cap <<= 1;
            buckets_.assign(cap, kEmpty);
            std::size_t const mask = cap - 1;
            for (std::size_t i = 0; i < users.size(); ++i) {
                auto slot = static_cast<std::size_t>(hash_uuid(users[i].uuid, seed_)) & mask;
                while (buckets_[slot] != kEmpty) slot = (slot + 1) & mask;
                buckets_[slot] = static_cast<std::uint32_t>(i);
            }
        }
        template<class User>
        [[nodiscard]] auto find(std::span<User const> users, std::array<std::uint8_t, 16> const& uuid) const noexcept
            -> std::optional<std::size_t> {
            if (buckets_.empty() || users.empty()) return std::nullopt;
            std::size_t const mask = buckets_.size() - 1;
            auto slot = static_cast<std::size_t>(hash_uuid(uuid, seed_)) & mask;
            while (buckets_[slot] != kEmpty) {
                auto const idx = buckets_[slot];
                if (idx < users.size() && crypto::constant_time_equal(users[idx].uuid, uuid)) return idx;
                slot = (slot + 1) & mask;
            }
            return std::nullopt;
        }
    };

    struct UniInput {
        template<class App, class StreamState>
        static auto handle_complete(App& app, StreamState& s) -> int {
            if (s.rx.size() < 2 || s.rx[0] != version) return ngtcp2::err_callback_failure;
            auto cmd = s.rx[1];
            if (cmd == static_cast<std::uint8_t>(Command::authenticate)) {
                if (!app.server_ || app.authenticated_) return 0;
                auto auth = decode_authenticate(s.rx);
                if (!auth) return ngtcp2::err_callback_failure;
                auto exp = app.tls_.exporter_master();
                if (!exp) return ngtcp2::err_callback_failure;
                std::optional<std::size_t> matched;
                if (app.server_user_index_) {
                    matched = app.server_user_index_->find(app.server_users_, auth->uuid);
                } else {
                    for (std::size_t i = 0; i < app.server_users_.size(); ++i)
                        if (crypto::constant_time_equal(app.server_users_[i].uuid, auth->uuid)) matched = i;
                }
                if (matched) {
                    auto const i = *matched;
                    auto expected = derive_auth_token(exp->hash, exp->secret, auth->uuid, app.server_users_[i].password);
                    if (!expected || !crypto::constant_time_equal(*expected, auth->token)) {
                        app.auth_failed_ = true;
                        return ngtcp2::err_callback_failure;
                    }
                    if constexpr (requires { app.hooks_.admit_authenticated(i); }) {
                        if (!app.hooks_.admit_authenticated(i)) {
                            app.auth_failed_ = true;
                            return ngtcp2::err_callback_failure;
                        }
                    }
                    app.auth_user_ = i;
                    app.authenticated_ = true;
                    app.hooks_.authenticated(i);
                    for (std::size_t idx = 0; idx < app.streams_.size(); ++idx) {
                        if (auto& st = app.streams_[idx]; st && st->pending_connect) {
                            st->pending_connect = false;
                            if (st->reset_flag || st->phase == App::Phase::closed) continue;
                            st->accepted_connect = true;
                            app.hooks_.connect_stream({static_cast<std::uint16_t>(idx), st->generation}, st->target);
                        }
                    }
                    while (!app.early_datagrams_.empty()) {
                        auto pkt = std::move(app.early_datagrams_.front());
                        app.early_datagrams_.pop_front();
                        if (auto err = app.process_packet_wire(pkt, false)) return err;
                    }
                    while (!app.early_.server_early_uni_packets.empty()) {
                        auto pkt = std::move(app.early_.server_early_uni_packets.front());
                        app.early_.server_early_uni_packets.pop_front();
                        if (auto err = app.process_packet_wire(pkt, true)) return err;
                    }
                    app.signal();
                    return 0;
                }
                app.auth_failed_ = true;
                app.early_datagrams_.clear();
                app.early_.server_early_uni_packets.clear();
                return ngtcp2::err_callback_failure;
            }
            if (!app.authenticated_) {
                if (app.server_ && !app.auth_failed_ && cmd == static_cast<std::uint8_t>(Command::packet)) {
                    (void)app.early_.buffer_server_uni_packet(s.rx);
                    return 0;
                }
                return ngtcp2::err_callback_failure;
            }
            if (cmd == static_cast<std::uint8_t>(Command::dissociate)) {
                auto dissoc = decode_dissociate(s.rx);
                if (!dissoc) return ngtcp2::err_callback_failure;
                app.defrag_.clear_association(*dissoc);
                app.hooks_.udp_dissociate(*dissoc);
                app.signal();
                return 0;
            }
            if (cmd == static_cast<std::uint8_t>(Command::packet)) {
                return app.process_packet_wire(s.rx, true);
            }
            return ngtcp2::err_callback_failure;
        }
    };
}
