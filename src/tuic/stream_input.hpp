// Included in the TUIC application template.
#pragma once
        auto handle_uni_complete(StreamState& s) -> int {
            if (s.rx.size() < 2 || s.rx[0] != version) return nex::ngtcp2::err_callback_failure;
            auto cmd = s.rx[1];
            if (cmd == static_cast<std::uint8_t>(Command::authenticate)) {
                if (!server_ || authenticated_) return 0;
                auto auth = decode_authenticate(s.rx);
                if (!auth) return nex::ngtcp2::err_callback_failure;
                auto exp = tls_.exporter_master();
                if (!exp) return nex::ngtcp2::err_callback_failure;
                for (std::size_t i = 0; i < server_users_.size(); ++i) {
                    if (server_users_[i].uuid != auth->uuid) continue;
                    auto expected = derive_auth_token(exp->hash, exp->secret, auth->uuid, server_users_[i].password);
                    if (!expected || !crypto::constant_time_equal(*expected, auth->token)) {
                        auth_failed_ = true;
                        return nex::ngtcp2::err_callback_failure;
                    }
                    if constexpr (requires {hooks_.admit_authenticated(i);}) {
                        if (!hooks_.admit_authenticated(i)) {
                            auth_failed_=true;
                            return nex::ngtcp2::err_callback_failure;
                        }
                    }
                    auth_user_ = i;
                    authenticated_ = true;
                    hooks_.authenticated(i);
                    for (std::size_t idx = 0; idx < Streams; ++idx) {
                        if (auto& st = streams_[idx]; st && st->pending_connect) {
                            st->pending_connect = false;
                            st->accepted_connect = true;
                            hooks_.connect_stream(StreamHandle{static_cast<std::uint16_t>(idx), st->generation}, st->target);
                        }
                    }
                    while (!early_datagrams_.empty()) {
                        auto pkt = std::move(early_datagrams_.front());
                        early_datagrams_.pop_front();
                        if (auto err = process_packet_wire(pkt, false)) return err;
                    }
                    signal();
                    return 0;
                }
                auth_failed_ = true;
                early_datagrams_.clear();
                return nex::ngtcp2::err_callback_failure;
            }
            if (!authenticated_) return nex::ngtcp2::err_callback_failure;
            if (cmd == static_cast<std::uint8_t>(Command::dissociate)) {
                auto dissoc = decode_dissociate(s.rx);
                if (!dissoc) return nex::ngtcp2::err_callback_failure;
                defrag_.clear_association(*dissoc);
                hooks_.udp_dissociate(*dissoc);
                signal();
                return 0;
            }
            if (cmd == static_cast<std::uint8_t>(Command::packet)) {
                return process_packet_wire(s.rx, true);
            }
            return nex::ngtcp2::err_callback_failure;
        }
