// TUIC unidirectional control/packet stream handler module.
export module tuic.stream_input;
import std;
import crypto;
import tuic.wire;
import ngtcp2;

export namespace tuic::detail {
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
                for (std::size_t i = 0; i < app.server_users_.size(); ++i) {
                    if (app.server_users_[i].uuid != auth->uuid) continue;
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
                    app.signal();
                    return 0;
                }
                app.auth_failed_ = true;
                app.early_datagrams_.clear();
                return ngtcp2::err_callback_failure;
            }
            if (!app.authenticated_) return ngtcp2::err_callback_failure;
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
