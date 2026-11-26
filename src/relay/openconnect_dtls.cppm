// OpenConnect DTLS 1.2/1.3 UDP transport + automatic CSTP fallback helper.
module;
#include <boost/corosio/endpoint.hpp>

export module relay:openconnect_dtls;
import std;
import platform.socket_options;
import net.udp_socket;
import openconnect.types;
import openconnect.cstp;
import openconnect.dtls;
import :types;

export namespace relay::oc_detail {
    inline auto oc_now_ms() noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count());
    }

    inline auto trim_crlf(std::string& s) noexcept -> void {
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    }

    inline auto parse_content_length(std::string_view hdrs) -> std::optional<std::size_t> {
        std::size_t pos = 0;
        while (pos < hdrs.size()) {
            auto nl = hdrs.find('\n', pos);
            auto line = (nl == hdrs.npos) ? hdrs.substr(pos) : hdrs.substr(pos, nl - pos);
            pos = (nl == hdrs.npos) ? hdrs.size() : nl + 1;
            if (auto colon = line.find(':'); colon != line.npos) {
                auto k = line.substr(0, colon);
                bool match = k.size() == 14 && [&] {
                    constexpr std::string_view cl = "content-length";
                    for (std::size_t i = 0; i < 14; ++i) {
                        unsigned char c = static_cast<unsigned char>(k[i]);
                        if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c - 'A' + 'a');
                        if (c != static_cast<unsigned char>(cl[i])) return false;
                    }
                    return true;
                }();
                if (match) {
                    auto v = line.substr(colon + 1);
                    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                    while (!v.empty() && (v.back() == ' ' || v.back() == '\t' || v.back() == '\r')) v.remove_suffix(1);
                    std::size_t len = 0;
                    auto [end, ec] = std::from_chars(v.data(), v.data() + v.size(), len);
                    if (ec == std::errc{} && end == v.data() + v.size()) return len;
                }
            }
        }
        return std::nullopt;
    }

    inline auto decode_session_id(std::string_view text) -> std::vector<std::uint8_t> {
        if (text.size() >= 2 && (text.size() % 2) == 0) {
            std::vector<std::uint8_t> hex;
            hex.reserve(text.size() / 2);
            bool all_hex = true;
            for (std::size_t i = 0; i < text.size(); i += 2) {
                unsigned v = 0;
                auto [end, ec] = std::from_chars(text.data() + i, text.data() + i + 2, v, 16);
                if (ec != std::errc{} || end != text.data() + i + 2) { all_hex = false; break; }
                hex.push_back(static_cast<std::uint8_t>(v));
            }
            if (all_hex && !hex.empty()) return hex;
        }
        return std::vector<std::uint8_t>(text.begin(), text.end());
    }

    struct DtlsChannel {
        net::UdpSocket udp;
        net::UdpEndpoint target{};
        openconnect::DtlsTransport dtls;
        openconnect::DtlsFallbackController fallback;
        bool enabled = false;
        bool allow_fallback = true;
        bool failed_hard = false;

        [[nodiscard]] auto established() const noexcept -> bool {
            return enabled && dtls.established();
        }

        auto start(net::UdpEndpoint const& peer, openconnect::AuthResult const& parsed,
                   std::array<std::uint8_t, 48> const& secret, platform::SocketBinding const& binding,
                   bool allow_fb, std::uint64_t now_ms, Clock::time_point dl) -> bool {
            close();
            if (!peer.family || !peer.port || parsed.dtls_session_id.empty()) return false;
            allow_fallback = allow_fb;
            failed_hard = false;
            target = peer;
            if (parsed.dtls_port) target.port = parsed.dtls_port;

            net::UdpEndpoint local{6, {}, binding.udp_bind_port.value_or(0)};
            if (target.family == 4 && binding.inet4_bind_address) {
                local.family = 4;
                std::ranges::copy(*binding.inet4_bind_address, local.address.begin());
            } else if (target.family == 6 && binding.inet6_bind_address) {
                local.address = *binding.inet6_bind_address;
            }
            if (!udp.open(false, binding.network_namespace)) return false;
            if (binding.configured() && platform::apply_socket_binding(udp.native_handle(), binding, true, dl)) {
                udp.close();
                return false;
            }
            if (!udp.bind(local)) { udp.close(); return false; }

            openconnect::DtlsConfig cfg{};
            cfg.version = (parsed.dtls_version == openconnect::DtlsVersion::dtls1_3)
                ? openconnect::DtlsVersion::dtls1_3 : openconnect::DtlsVersion::dtls1_2;
            cfg.cipher = openconnect::parse_dtls_cipher_name(parsed.dtls_cipher);
            cfg.server_role = false;
            cfg.session_id = decode_session_id(parsed.dtls_session_id);
            cfg.master_secret = secret;
            cfg.mtu = parsed.dtls_mtu ? parsed.dtls_mtu : parsed.mtu;
            if (!dtls.init(cfg)) { udp.close(); return false; }

            auto ch = dtls.build_client_hello();
            if (!ch || !udp.send(target, *ch)) { close(); return false; }

            auto dpd_ms = static_cast<std::uint64_t>(parsed.dtls_dpd_s ? parsed.dtls_dpd_s : parsed.dpd_s) * 1000u;
            fallback = openconnect::DtlsFallbackController(5000, dpd_ms ? dpd_ms : 30000u);
            fallback.begin_handshake(now_ms);
            enabled = true;
            return true;
        }

        auto send_data(std::span<std::uint8_t const> ip_pkt, openconnect::Session& sess) -> bool {
            if (!established()) return false;
            auto dg = dtls.seal_tunnel_frame(openconnect::CstpType::data, ip_pkt);
            if (!dg || !udp.send(target, *dg)) {
                if (fallback.on_transport_error(sess) == openconnect::FallbackAction::fallback_to_cstp) {
                    failed_hard = !allow_fallback;
                    close();
                }
                return false;
            }
            return true;
        }

        template<class OnData>
        auto poll_once(openconnect::Session& sess, std::uint64_t now_ms, OnData&& on_data) -> bool {
            if (!enabled) return false;
            std::array<std::uint8_t, 4096> buf{};
            bool moved = false;
            for (unsigned i = 0; i < 32 && enabled; ++i) {
                auto r = udp.receive(buf);
                if (!r) {
                    if (fallback.on_transport_error(sess) == openconnect::FallbackAction::fallback_to_cstp) {
                        failed_hard = !allow_fallback;
                        close();
                    }
                    break;
                }
                if (!*r) break;
                if (!(*r)->valid || (*r)->source != target) continue;
                moved = true;
                auto dg = std::span(buf).first((*r)->size);
                if (!dtls.established()) {
                    auto out = dtls.on_handshake_datagram(dg);
                    if (!out) {
                        if (fallback.on_transport_error(sess) == openconnect::FallbackAction::fallback_to_cstp) {
                            failed_hard = !allow_fallback;
                            close();
                        }
                        continue;
                    }
                    for (auto const& pkt : *out) (void)udp.send(target, pkt);
                    if (dtls.established()) fallback.on_established(now_ms);
                } else {
                    auto frame = dtls.open_tunnel_frame(dg);
                    if (!frame) {
                        if (fallback.on_transport_error(sess) == openconnect::FallbackAction::fallback_to_cstp) {
                            failed_hard = !allow_fallback;
                            close();
                        }
                        continue;
                    }
                    if (frame->type == openconnect::CstpType::data) {
                        fallback.on_rx_valid(now_ms);
                        on_data(frame->payload);
                    } else if (frame->type == openconnect::CstpType::dpd_req) {
                        fallback.on_rx_valid(now_ms);
                        if (auto resp = dtls.seal_tunnel_frame(openconnect::CstpType::dpd_resp, frame->payload))
                            (void)udp.send(target, *resp);
                    } else if (frame->type == openconnect::CstpType::dpd_resp) {
                        fallback.on_dpd_response(now_ms);
                    } else if (frame->type == openconnect::CstpType::keepalive) {
                        fallback.on_rx_valid(now_ms);
                    } else if (frame->type == openconnect::CstpType::disconnect) {
                        sess.fallback_to_cstp();
                        failed_hard = !allow_fallback;
                        close();
                    }
                }
            }
            if (enabled) {
                auto act = fallback.poll(now_ms, sess);
                if (act == openconnect::FallbackAction::send_dpd_req && dtls.established()) {
                    if (auto req = dtls.seal_tunnel_frame(openconnect::CstpType::dpd_req, {}))
                        (void)udp.send(target, *req);
                } else if (act == openconnect::FallbackAction::fallback_to_cstp) {
                    failed_hard = !allow_fallback;
                    close();
                }
            }
            return moved;
        }

        auto close() noexcept -> void {
            enabled = false;
            dtls.reset();
            udp.close();
        }
    };
}
