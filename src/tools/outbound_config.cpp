module;
#include <string.h>
module cli.outbounds;
import std;
import utility;
import config;
import cli.dns_transports;
import dns.corosio_query;
import relay;
import rulefile;
import state.core;
import encoding.base64_key;
import cli.tailscale_outbound;

namespace cli {
    namespace {
        struct SecretKey {
            std::array<std::uint8_t,32> bytes{};
            ~SecretKey() { utility::secure_zero(bytes.data(),bytes.size()); }
        };
    }

    auto configure_outbounds(relay::Server& server,config::Config const& config,std::span<DnsProtection const> protection) -> std::expected<void,std::string> {
        using ::encoding::decode_key;
        if (config.dns) {
            relay::DnsRouting routing;
            routing.final=config.dns->final;
            for (auto const& view:config.dns->views) routing.view_finals.push_back(view.final);
            routing.disable_cache=config.dns->disable_cache;
            routing.independent_cache=config.dns->independent_cache;
            routing.edns=config.dns->edns;
            routing.optimistic_cache_seconds=config.dns->optimistic_cache_seconds;
            switch (config.dns->strategy) {
                case config::DnsStrategy::automatic: break;
                case config::DnsStrategy::prefer_ipv4: routing.strategy=relay::DnsStrategy::prefer_ipv4; break;
                case config::DnsStrategy::prefer_ipv6: routing.strategy=relay::DnsStrategy::prefer_ipv6; break;
                case config::DnsStrategy::ipv4_only: routing.strategy=relay::DnsStrategy::ipv4_only; break;
                case config::DnsStrategy::ipv6_only: routing.strategy=relay::DnsStrategy::ipv6_only; break;
            }
            for (auto const& server : config.dns->servers) {
                relay::DnsServer entry;
                if (server.upstream) entry={server.upstream->address,server.upstream->ipv6,server.upstream->port,
                                            server.upstream->tcp,server.upstream->host,server.upstream->resolver};
                else if (server.kind!=config::DnsServerKind::standard) { entry.address={127,0,0,1}; entry.port=53; }
                entry.protection=protection[routing.servers.size()];
                entry.proxy_detour=server.upstream && (server.upstream->detour_index || server.upstream->detour_group);
                routing.servers.push_back(std::move(entry));
            }
            for (auto const& rule : config.dns->rules) routing.rules.push_back(rule);
            auto result=server.set_dns_routing(std::move(routing));
            if (!result) { return std::unexpected("DNS configuration: "+result.error().message()); }
        }
        if (auto result=server.set_direct_connect_timeout(config.direct_connect_timeout_ms); !result) {
            return std::unexpected("configuration: "+result.error());
        }
        if (auto result=server.set_direct_tcp_options(config.direct_tcp_options); !result) {
            return std::unexpected("configuration: "+result.error());
        }
        auto to_kx=[](config::TlsKeyExchange k) {
            return k==config::TlsKeyExchange::x25519 ? relay::TlsKeyExchange::x25519 :
                k==config::TlsKeyExchange::x25519_mlkem768 ? relay::TlsKeyExchange::x25519_mlkem768 :
                relay::TlsKeyExchange::x25519_mlkem768_only;
        };
        for (auto const& named : config.vless_outbounds) {
            auto const& outbound=named.config;
            std::optional<relay::Reality> reality;
            if (outbound.reality) reality=relay::Reality{outbound.reality->public_key,outbound.reality->short_id};
            auto prepared=server.add_vless(outbound.host,outbound.port,outbound.uuid_file,outbound.server_name,outbound.ca_file,to_kx(outbound.key_exchange),outbound.bootstrap_index,reality,outbound.vision,outbound.connect_timeout_ms,outbound.tcp_options,outbound.transport,outbound.grpc,outbound.tcp_fast_open.value_or(false),outbound.fingerprint,outbound.record_size_limit,outbound.packetaddr,outbound.fixed_udp,outbound.xhttp,outbound.certificate_sha256,outbound.ech,outbound.tls_fragment,outbound.alpn);
            if (!prepared) { return std::unexpected("configuration: "+prepared.error()); }
            if (outbound.multiplex && outbound.multiplex->enabled) {
                if (auto wrapped=server.wrap_outbound_multiplex(*prepared,*outbound.multiplex); !wrapped)
                    return std::unexpected("configuration: "+wrapped.error());
            }
        }
        for (auto const& named : config.shadowsocks_outbounds) {
            auto const& outbound=named.config;
            auto file=::rulefile::read_private_file(outbound.key_file);
            if (!file) { return std::unexpected("shadowsocks key: "+file.error()); }
            SecretKey key;
            auto size=outbound.method=="2022-blake3-aes-128-gcm" ? 16U : 32U;
            auto bytes=std::span(key.bytes).first(size);
            if (!decode_key(file->bytes(),bytes)) { return std::unexpected("shadowsocks key: invalid base64 or key length"); }
            struct Identities {
                std::array<std::array<std::uint8_t,32>,8> keys{};
                ~Identities() {utility::secure_zero(keys.data(),sizeof(keys));}
            } identities;
            auto identity_keys=std::span(identities.keys).first(outbound.identity_key_files.size());
            for (std::size_t index=0;index<identity_keys.size();++index) {
                auto identity=::rulefile::read_private_file(outbound.identity_key_files[index]);
                if (!identity || !decode_key(identity->bytes(),std::span(identity_keys[index]).first(size))) {
                    return std::unexpected("shadowsocks identity key: invalid private file, base64 or key length");
                }
            }
            auto prepared=server.add_shadowsocks(outbound.host,outbound.port,bytes,outbound.bootstrap_index,outbound.udp_over_tcp,
                outbound.connect_timeout_ms,outbound.tcp_options,outbound.tcp_fast_open.value_or(false),identity_keys,
                outbound.method=="2022-blake3-chacha20-poly1305" ? relay::ShadowsocksCipher::chacha20 : relay::ShadowsocksCipher::aes,outbound.udp_native);
            if (!prepared) { return std::unexpected("configuration: "+prepared.error()); }
            if (outbound.multiplex && outbound.multiplex->enabled) {
                if (auto wrapped=server.wrap_outbound_multiplex(*prepared,*outbound.multiplex); !wrapped)
                    return std::unexpected("configuration: "+wrapped.error());
            }
        }
        for (auto const& named:config.trojan_outbounds) {
            auto const& outbound=named.config;
            auto prepared=server.add_trojan(outbound.host,outbound.port,outbound.password_file,outbound.server_name,outbound.ca_file,to_kx(outbound.key_exchange),
                outbound.bootstrap_index,outbound.connect_timeout_ms,outbound.tcp_options,outbound.tcp_fast_open.value_or(false),outbound.fingerprint,outbound.record_size_limit,outbound.certificate_sha256,outbound.transport,outbound.grpc,outbound.ech,outbound.tls_fragment,outbound.alpn);
            if (!prepared) { return std::unexpected("Trojan configuration: "+prepared.error()); }
            if (outbound.multiplex && outbound.multiplex->enabled) {
                if (auto wrapped=server.wrap_outbound_multiplex(*prepared,*outbound.multiplex); !wrapped)
                    return std::unexpected("Trojan configuration: "+wrapped.error());
            }
        }
        for (auto const& named:config.anytls_outbounds) {
            auto const& outbound=named.config.connection;
            auto const& options=named.config.pool;
            relay::AnyTlsOptions pool{options.max_sessions,options.min_idle,std::chrono::milliseconds(options.idle_timeout_ms),std::chrono::milliseconds(options.check_interval_ms)};
            auto prepared=server.add_anytls(outbound.host,outbound.port,outbound.password_file,outbound.server_name,outbound.ca_file,to_kx(outbound.key_exchange),
                outbound.bootstrap_index,outbound.connect_timeout_ms,outbound.tcp_options,pool,outbound.tcp_fast_open.value_or(false),outbound.fingerprint,outbound.record_size_limit,outbound.certificate_sha256,outbound.transport,outbound.grpc,outbound.ech,outbound.tls_fragment,outbound.alpn);
            if (!prepared) { return std::unexpected("AnyTLS configuration: "+prepared.error()); }
        }
        for (auto const& named:config.hysteria2_outbounds) {
            auto const& outbound=named.config.connection;
            auto const& transport=named.config.transport;
            auto prepared=server.add_hysteria2(outbound.host,outbound.port,outbound.password_file,outbound.server_name,outbound.ca_file,to_kx(outbound.key_exchange),
                outbound.bootstrap_index,outbound.connect_timeout_ms,outbound.tcp_options,transport.handshake_timeout_ms,
                transport.idle_timeout_ms,transport.native_bytes,transport.udp,
                transport.salamander_password_file ? std::optional<std::string_view>(*transport.salamander_password_file) : std::nullopt,
                transport.max_udp_payload_size,transport.disable_path_mtu_discovery,transport.send_bps,transport.receive_bps,transport.disable_compensation,outbound.fingerprint,transport.lazy_tcp_response,outbound.ech,transport.receive_windows,outbound.certificate_sha256,transport.port_ranges,transport.hop_interval_ms,transport.hop_interval_max_ms);
            if (!prepared) { return std::unexpected("Hysteria2 configuration: "+prepared.error()); }
        }
        for (auto const& named:config.snell_outbounds) {
            auto const& c=named.config;std::optional<std::string_view> user;
            if(c.user_file) user=*c.user_file;
            auto prepared=server.add_snell(c.host,c.port,c.psk_file,user,c.bootstrap_index,c.connect_timeout_ms,c.tcp_options,c.tcp_fast_open.value_or(false),c.http_obfs,c.obfs_host,c.obfs_uri,c.reuse);
            if(!prepared){return std::unexpected("Snell configuration: "+prepared.error());}
            if(c.multiplex&&c.multiplex->enabled){
                if(auto wrapped=server.wrap_outbound_multiplex(*prepared,*c.multiplex);!wrapped)
                    return std::unexpected("Snell configuration: "+wrapped.error());
            }
        }
        for (auto const& n : config.shadowtls_outbounds) { auto const& o = n.config.connection;
            auto options=o.tcp_options;
            options.tcp_fast_open=o.tcp_fast_open;
            if (auto r = server.add_shadowtls(o.host, o.port, o.password_file, o.server_name, o.ca_file, to_kx(o.key_exchange), o.bootstrap_index, o.connect_timeout_ms, std::move(options), o.fingerprint, n.config.strict_tls13, o.certificate_sha256); !r) {
                return std::unexpected("ShadowTLS configuration: "+r.error()); }
        }
        for (auto const& n : config.tuic_outbounds) { auto const& t = n.config;
            if (auto r = server.add_tuic(t.host, t.port, t.uuid_file, t.password_file, t.server_name, t.ca_file, to_kx(t.key_exchange), t.fingerprint, t.congestion_control, t.udp_over_stream, t.heartbeat_ms, t.handshake_timeout_ms, t.idle_timeout_ms, t.native_bytes, t.bootstrap_index, t.connect_timeout_ms, t.tcp_options, t.ech, t.certificate_sha256, t.zero_rtt_handshake); !r) {
                return std::unexpected("TUIC configuration: "+r.error()); }
        }
        for (auto const& n : config.masque_outbounds) { auto const& m = n.config;
            relay::MasqueIpOptions ip{m.connect_ip, m.path, m.mtu, m.local_v4, m.local_v6, m.protocol, m.connect_headers};
            if (auto r = server.add_masque(m.host, m.port, m.authority, m.bearer_file, m.server_name, m.ca_file, to_kx(m.key_exchange), m.fingerprint, m.handshake_timeout_ms, m.idle_timeout_ms, m.native_bytes, m.bootstrap_index, m.connect_timeout_ms, m.tcp_options, std::move(ip), m.ech, m.certificate_sha256); !r) {
                return std::unexpected("MASQUE outbound configuration: "+r.error()); }
        }
        for (auto const& n : config.wireguard_outbounds) {
            if (auto r = server.add_wireguard(n.config); !r) {
                return std::unexpected("WireGuard outbound configuration: "+r.error()); }
        }
        for (auto const& n : config.ssh_outbounds) { auto const& s = n.config;
            auto pw = s.password_file ? std::optional<std::string_view>(*s.password_file) : std::nullopt;
            auto pk = s.private_key_file ? std::optional<std::string_view>(*s.private_key_file) : std::nullopt;
            if (auto r = server.add_ssh(s.host, s.port, s.user, pw, pk, s.host_key_sha256, s.cipher, s.bootstrap_index, s.connect_timeout_ms, s.keepalive_interval_ms, s.max_sessions, s.tcp_options, s.tcp_fast_open.value_or(false)); !r) {
                return std::unexpected("SSH outbound configuration: "+r.error()); }
        }
        for (auto const& named : config.naive_outbounds) {
            auto added = server.add_naive(named.config);
            if (!added) return std::unexpected("NaiveProxy outbound configuration: "+added.error());
        }
        for (auto const& named : config.openvpn_outbounds) {
            auto added = server.add_openvpn(named.config);
            if (!added) return std::unexpected("OpenVPN outbound configuration: "+added.error());
        }
        for (auto const& named : config.openconnect_outbounds) {
            auto added = server.add_openconnect(named.config);
            if (!added) return std::unexpected("OpenConnect outbound configuration: "+added.error());
        }
        if(auto result=cli::tailscale_outbound::prepare(server,config.tailscale_outbounds);!result) {
            return std::unexpected("Tailscale outbound configuration: "+result.error());
        }
        for (auto const& named:config.tcp_proxy_outbounds) {
            auto added=server.add_tcp_proxy(named.config);
            if (!added) {return std::unexpected("TCP proxy configuration: "+added.error());}
        }
        std::vector<relay::OutboundDetour> detours;
        std::size_t base=2;
        auto collect_detours=[&](auto const& list, auto get_detour) {
            for(std::size_t i=0;i<list.size();++i) if(auto d=get_detour(list[i])) detours.push_back({i+base,*d});
            base+=list.size();
        };
        collect_detours(config.vless_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.shadowsocks_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.trojan_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.anytls_outbounds,[](auto const& n){return n.config.connection.detour_index;});
        collect_detours(config.hysteria2_outbounds,[](auto const& n){return n.config.connection.detour_index;});
        collect_detours(config.snell_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.shadowtls_outbounds,[](auto const& n){return n.config.connection.detour_index;});
        collect_detours(config.tuic_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.masque_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.wireguard_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.ssh_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.naive_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.openvpn_outbounds,[](auto const& n){return n.config.detour_index;});
        collect_detours(config.openconnect_outbounds,[](auto const& n){return n.config.detour_index;});
        base+=config.tailscale_outbounds.size();
        collect_detours(config.tcp_proxy_outbounds,[](auto const& named){return named.config.detour_index;});
        if (auto result=server.set_outbound_detours(detours); !result) {
            return std::unexpected("configuration: "+result.error());
        }
        return {};
    }

    auto outbound_secrets_fingerprint(config::Config const& cfg) -> std::expected<std::string,std::string> {
        std::vector<std::string> paths;
        auto add = [&](std::string const& p) { if (!p.empty()) paths.push_back(p); };
        auto add_opt = [&](std::optional<std::string> const& p) { if (p && !p->empty()) paths.push_back(*p); };
        if (cfg.certificate) add(cfg.certificate->ca_file);
        if (cfg.vless) { add(cfg.vless->uuid_file); add(cfg.vless->ca_file); add(cfg.vless->ech.config_file); }
        for (auto const& n : cfg.vless_outbounds) { add(n.config.uuid_file); add(n.config.ca_file); add(n.config.ech.config_file); }
        for (auto const& n : cfg.shadowsocks_outbounds) {
            add(n.config.key_file);
            for (auto const& id : n.config.identity_key_files) add(id);
        }
        for (auto const& n : cfg.trojan_outbounds) { add(n.config.password_file); add(n.config.ca_file); add(n.config.ech.config_file); }
        for (auto const& n : cfg.anytls_outbounds) { add(n.config.connection.password_file); add(n.config.connection.ca_file); add(n.config.connection.ech.config_file); }
        for (auto const& n : cfg.hysteria2_outbounds) {
            add(n.config.connection.password_file); add(n.config.connection.ca_file); add(n.config.connection.ech.config_file);
            add_opt(n.config.transport.salamander_password_file);
        }
        for (auto const& n : cfg.snell_outbounds) { add(n.config.psk_file); add_opt(n.config.user_file); }
        for (auto const& n : cfg.shadowtls_outbounds) { add(n.config.connection.password_file); add(n.config.connection.ca_file); }
        for (auto const& n : cfg.tuic_outbounds) { add(n.config.uuid_file); add(n.config.password_file); add(n.config.ca_file); add(n.config.ech.config_file); }
        for (auto const& n : cfg.masque_outbounds) { add(n.config.bearer_file); add(n.config.ca_file); add(n.config.ech.config_file); }
        for (auto const& n : cfg.wireguard_outbounds) {
            add(n.config.private_key_file); add(n.config.peer_public_key_file); add_opt(n.config.preshared_key_file);
            for (auto const& peer : n.config.peers) { add(peer.peer_public_key_file); add_opt(peer.preshared_key_file); }
        }
        for (auto const& n : cfg.ssh_outbounds) { add_opt(n.config.password_file); add_opt(n.config.private_key_file); }
        for (auto const& n : cfg.naive_outbounds) { add(n.config.password_file); add(n.config.ca_file); add(n.config.ech.config_file); }
        for (auto const& n : cfg.openvpn_outbounds) {
            add(n.config.ca_file); add_opt(n.config.password_file); add_opt(n.config.static_key_file);
            add_opt(n.config.client_cert_file); add_opt(n.config.client_key_file);
        }
        for (auto const& n : cfg.openconnect_outbounds) {
            add(n.config.ca_file); add_opt(n.config.password_file); add_opt(n.config.cookie_file);
            add_opt(n.config.client_cert_file); add_opt(n.config.client_key_file);
        }
        for (auto const& n : cfg.tailscale_outbounds) add(n.endpoint_file);
        for (auto const& n : cfg.tcp_proxy_outbounds) {
            add(n.config.password_file);
            if (n.config.tls) { add(n.config.tls->ca_file); add(n.config.tls->ech.config_file); }
        }
        std::ranges::sort(paths);
        paths.erase(std::unique(paths.begin(), paths.end()), paths.end());
        std::string summary;
        summary.reserve(paths.size() * 64);
        for (auto const& path : paths) {
            auto content = ::rulefile::read_regular_file(path);
            if (!content) return std::unexpected("outbound credential file " + path + ": " + content.error());
            auto digest = ::state::fingerprint(std::as_bytes(std::span(*content)));
            if (!content->empty()) utility::secure_zero(content->data(), content->size());
            summary.append(path);
            summary.push_back('\0');
            summary.append(reinterpret_cast<char const*>(digest.data()), digest.size());
        }
        auto master = ::state::fingerprint(std::as_bytes(std::span(summary)));
        return std::string(reinterpret_cast<char const*>(master.data()), master.size());
    }
}
