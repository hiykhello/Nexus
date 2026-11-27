module;
#include <boost/capy/ex/run_async.hpp>

module cli.proxy_services;
import std;
import capy;
import corosio;
import config;
import logging;
import logging.cli;
import acme.types;
import acme.jws;
import acme.store;
import acme.client;
import acme.dns01_providers;
import cli.svc_acme_dns01;
import http.header;
import rulefile;
import tls.profiles;
import tls.server_credential;
import tls.corosio_server_handshake;

namespace cli {
    namespace {
        using Clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        using namespace acme_detail;

        struct AcmeRuntimeState {
            acme::AcmeConfig cfg;
            std::string ca_file;
            std::uint32_t check_interval_ms = 3600000;
            acme::EcAccountKey account_key;
            Dns01ProviderRuntime dns01_provider;
            acme::CertificateStore store;
            std::shared_ptr<tls::AtomicServerCredential> live_credential = std::make_shared<tls::AtomicServerCredential>();
            AcmeHooks hooks;
            logging::Runtime* logs = nullptr;

            // Live challenge state (must outlive io_context coroutine frames).
            std::uint16_t http01_port = 0;
            std::uint16_t alpn01_port = 0;
            std::mutex ch_mu;
            std::unordered_map<std::string, std::string> http01_tokens;
            std::unordered_map<std::string, std::string> dns01_records;
            tls::AtomicServerCredential alpn01_cred;

            std::atomic_bool stopping{false};
            std::mutex cv_mu;
            std::condition_variable_any cv;
            corosio::io_context io;
            corosio::tcp_acceptor http01_acc{io};
            corosio::tcp_acceptor alpn01_acc{io};
            std::jthread io_thread;
            std::jthread renew_thread;

            AcmeRuntimeState(acme::AcmeConfig c, std::string ca, std::uint32_t interval,
                acme::EcAccountKey k, Dns01ProviderRuntime dp,
                std::shared_ptr<tls::AtomicServerCredential> shared_cred, AcmeHooks h, logging::Runtime* l)
                : cfg(std::move(c)), ca_file(std::move(ca)), check_interval_ms(interval),
                  account_key(std::move(k)), dns01_provider(std::move(dp)),
                  live_credential(shared_cred ? std::move(shared_cred) : std::make_shared<tls::AtomicServerCredential>()),
                  hooks(std::move(h)), logs(l) {}

            ~AcmeRuntimeState() { stop(); }

            auto stop() noexcept -> void {
                if (stopping.exchange(true, std::memory_order_acq_rel)) return;
                renew_thread.request_stop();
                cv.notify_all();
                if (renew_thread.joinable()) renew_thread.join();
                http01_acc.close();
                alpn01_acc.close();
                io.stop();
                if (io_thread.joinable()) io_thread.join();
            }

            auto serve_http01(corosio::tcp_socket sock) -> capy::task<> {
                std::array<char, 2048> buf{};
                auto dl = Clock::now() + 3s;
                auto [ec, n] = co_await corosio::timeout(sock.read_some(capy::mutable_buffer(buf.data(), buf.size())), dl);
                if (ec || n == 0) co_return;
                std::string_view req(buf.data(), n);
                auto hdr = http::inspect_header(req);
                std::string reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                constexpr std::string_view kPrefix = "GET /.well-known/acme-challenge/";
                if (hdr.status == http::HeaderStatus::complete && hdr.first.starts_with(kPrefix)) {
                    auto rest = hdr.first.substr(kPrefix.size());
                    auto sp = rest.find(' ');
                    if (sp != std::string_view::npos) {
                        auto token = std::string(rest.substr(0, sp));
                        std::lock_guard lk(ch_mu);
                        if (auto it = http01_tokens.find(token); it != http01_tokens.end()) {
                            reply = std::format(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                it->second.size(), it->second);
                        }
                    }
                }
                (void)co_await corosio::timeout(sock.write_some(capy::const_buffer(reply.data(), reply.size())), dl);
            }

            auto serve_alpn01(corosio::tcp_socket sock) -> capy::task<> {
                auto cred = alpn01_cred.clone_current();
                if (!cred) co_return;
                auto hs = tls::make_server_handshake(*cred, now_ms(), now_ms() + 3000, {}, "acme-tls/1");
                if (!hs) co_return;
                (void)co_await tls::detail::server_handshake(sock, *hs);
            }

            auto accept_loop(corosio::tcp_acceptor& acc, bool is_http01) -> capy::task<> {
                while (!stopping.load(std::memory_order_acquire)) {
                    auto [ec, s] = co_await acc.accept();
                    if (ec) break;
                    if (is_http01) capy::run_async(io.get_executor())(serve_http01(std::move(s)));
                    else capy::run_async(io.get_executor())(serve_alpn01(std::move(s)));
                }
            }

            static auto cred_error_name(tls::ServerCredentialError err) noexcept -> std::string_view {
                switch (err) {
                case tls::ServerCredentialError::invalid_certificate: return "invalid_certificate";
                case tls::ServerCredentialError::invalid_private_key: return "invalid_private_key";
                case tls::ServerCredentialError::key_mismatch: return "key_mismatch";
                case tls::ServerCredentialError::unsupported_key: return "unsupported_key";
                case tls::ServerCredentialError::invalid_transcript: return "invalid_transcript";
                case tls::ServerCredentialError::invalid_state: return "invalid_state";
                case tls::ServerCredentialError::crypto_error: return "crypto_error";
                }
                return "unknown";
            }

            auto publish_live_credential(acme::CertificateBundle const& bundle)
                -> std::expected<void, std::string> {
                auto gen = live_credential->update_pem(bundle.cert_pem, bundle.key_pem);
                if (!gen)
                    return std::unexpected(std::format("TLS credential rejected ({})", cred_error_name(gen.error())));
                if (hooks.on_credential_updated) hooks.on_credential_updated(bundle.cert_pem, bundle.key_pem);
                if (logs) logs->emit(logging::Level::info, logging::Domain::core, 102, {},
                    "acme hot-swapped TLS ServerCredential (generation={})", *gen);
                return {};
            }

            auto run_renewal_once() -> void {
                auto http_fn = [this](acme::HttpRequest const& req) -> std::expected<acme::HttpResponse, std::string> {
                    corosio::io_context cctx;
                    std::expected<acme::HttpResponse, std::string> out = std::unexpected("acme HTTP did not complete");
                    capy::run_async(cctx.get_executor(),
                        [&](auto res) noexcept { out = std::move(res); },
                        [&](std::exception_ptr) noexcept {})(http_exchange_coro(cctx, req, ca_file));
                    cctx.run_for(6s);
                    return out;
                };
                std::vector<acme::Dns01RecordHandle> active_dns_handles;
                auto pub_http = [this](std::string_view tok, std::string_view ka) -> bool {
                    std::lock_guard lk(ch_mu);
                    http01_tokens[std::string(tok)] = std::string(ka);
                    return true;
                };
                auto pub_alpn = [this](std::string_view, std::string_view cp, std::string_view kp) -> bool {
                    return alpn01_cred.update_pem(cp, kp).has_value();
                };
                auto pub_dns = [this, &http_fn, &active_dns_handles](std::string_view dom, std::string_view txt) -> bool {
                    if (dns01_provider.has_remote()) {
                        auto rec = dns01_provider.publish(dom, txt, http_fn);
                        if (!rec) {
                            if (logs) logs->emit(logging::Level::warn, logging::Domain::core, 108, {},
                                "acme DNS-01 publish failed for {}: {}", dom, rec.error());
                            return false;
                        }
                        active_dns_handles.push_back(std::move(*rec));
                    }
                    std::string body;
                    {
                        std::lock_guard lk(ch_mu);
                        dns01_records[std::string(dom)] = std::string(txt);
                        for (auto const& [k, v] : dns01_records) body += std::format("_acme-challenge.{} TXT {}\n", k, v);
                    }
                    if (!dns01_provider.has_remote() && !cfg.state_dir.empty())
                        (void)rulefile::replace_file((cfg.state_dir / "dns01_challenges.txt").string(), body);
                    return true;
                };
                auto clean = [this, &http_fn, &active_dns_handles]() {
                    if (dns01_provider.has_remote() && !active_dns_handles.empty()) {
                        dns01_provider.cleanup(active_dns_handles, http_fn);
                        active_dns_handles.clear();
                    }
                    std::lock_guard lk(ch_mu);
                    http01_tokens.clear();
                };
                auto pub_cert = [this](acme::CertificateBundle const& bundle) -> std::expected<void, std::string> {
                    return publish_live_credential(bundle);
                };
                acme::ChallengeHooks ch_hooks{
                    .publish_http01 = pub_http,
                    .publish_alpn01 = pub_alpn,
                    .publish_dns01 = pub_dns,
                    .publish_certificate = pub_cert,
                    .cleanup = clean,
                };
                auto res = acme::ensure_certificate(cfg, store, account_key, http_fn, ch_hooks, now_epoch());
                if (!res && logs) {
                    logs->emit(logging::Level::warn, logging::Domain::core, 108, {}, "acme renewal attempt: {}", res.error());
                }
            }

            auto renew_loop(std::stop_token st) -> void {
                while (!st.stop_requested() && !stopping.load(std::memory_order_acquire)) {
                    if (store.needs_renewal(now_epoch(), cfg.renew_before_seconds)) run_renewal_once();
                    std::unique_lock lk(cv_mu);
                    cv.wait_for(lk, st, std::chrono::milliseconds(std::max<std::uint32_t>(check_interval_ms, 50u)),
                        [this] { return stopping.load(std::memory_order_acquire); });
                }
            }
        };
    }

    auto init_acme_service(config::AcmeServiceConfig const& cfg, logging::Runtime& logs, AcmeHooks hooks)
        -> std::expected<ServiceHandle, std::string> {
        if (cfg.directory_url.empty() || cfg.domains.empty() || cfg.state_dir.empty())
            return std::unexpected("acme: directory_url, domains, and state_dir are required");
        auto eab = load_acme_eab(cfg);
        if (!eab) return std::unexpected(eab.error());
        auto dns_prov = Dns01ProviderRuntime::load(cfg);
        if (!dns_prov) return std::unexpected(dns_prov.error());

        std::error_code fs_ec;
        std::filesystem::create_directories(cfg.state_dir, fs_ec);
        if (fs_ec) return std::unexpected("acme: cannot create state_dir: " + fs_ec.message());

        auto key_path = (std::filesystem::path(cfg.state_dir) / "account.key").string();
        std::optional<acme::EcAccountKey> acct_key;
        if (auto existing = rulefile::read_private_file(key_path); existing) {
            auto parsed = acme::EcAccountKey::from_pem({existing->bytes().data(), existing->bytes().size()});
            if (parsed) acct_key.emplace(std::move(*parsed));
        }
        if (!acct_key) {
            auto gen = acme::EcAccountKey::generate_p256();
            if (!gen) return std::unexpected("acme: account key generation failed: " + gen.error());
            if (auto saved = rulefile::replace_file(key_path, gen->to_pem()); !saved)
                return std::unexpected("acme: cannot persist account key: " + saved.error());
            acct_key.emplace(std::move(*gen));
        }

        acme::ChallengeType ct = acme::ChallengeType::http01;
        if (cfg.challenge == "tls-alpn-01") ct = acme::ChallengeType::tls_alpn01;
        else if (cfg.challenge == "dns-01") ct = acme::ChallengeType::dns01;

        acme::AcmeConfig ac{
            .directory_url = cfg.directory_url,
            .domains = cfg.domains,
            .email = cfg.email,
            .challenge = ct,
            .state_dir = cfg.state_dir,
            .renew_before_seconds = cfg.renew_before_seconds,
            .eab = std::move(*eab),
        };
        auto shared_cred = std::static_pointer_cast<tls::AtomicServerCredential>(hooks.shared_credential);
        auto st = std::make_unique<AcmeRuntimeState>(std::move(ac), cfg.ca_file, cfg.check_interval_ms,
            std::move(*acct_key), std::move(*dns_prov), std::move(shared_cred), std::move(hooks), &logs);

        if (auto loaded = acme::CertificateStore::load_from_dir(cfg.state_dir); loaded) {
            if (auto pub = st->publish_live_credential(*loaded); pub) {
                st->store.install(std::move(*loaded));
            } else {
                logs.emit(logging::Level::warn, logging::Domain::core, 108, {},
                    "acme ignoring invalid persisted credential: {}", pub.error());
            }
        }

        auto bind_acc = [](corosio::tcp_acceptor& acc, std::string_view host, std::uint16_t port, std::string_view tag)
            -> std::expected<std::uint16_t, std::string> {
            auto ep = parse_ip_ep(host, port);
            if (!ep) return std::unexpected(ep.error());
            if (auto ec = acc.open(); ec) return std::unexpected(std::format("acme {} open: {}", tag, ec.message()));
            if (auto ec = acc.bind(*ep); ec) return std::unexpected(std::format("acme {} bind: {}", tag, ec.message()));
            if (auto ec = acc.listen(); ec) return std::unexpected(std::format("acme {} listen: {}", tag, ec.message()));
            return acc.local_endpoint().port();
        };
        bool need_io = false;
        if (ct == acme::ChallengeType::http01) {
            auto bp = bind_acc(st->http01_acc, cfg.http_listen_host, cfg.http_listen_port, "http-01");
            if (!bp) return std::unexpected(bp.error());
            st->http01_port = *bp;
            capy::run_async(st->io.get_executor())(st->accept_loop(st->http01_acc, true));
            need_io = true;
        } else if (ct == acme::ChallengeType::tls_alpn01) {
            auto bp = bind_acc(st->alpn01_acc, cfg.tls_alpn_listen_host, cfg.tls_alpn_listen_port, "alpn-01");
            if (!bp) return std::unexpected(bp.error());
            st->alpn01_port = *bp;
            capy::run_async(st->io.get_executor())(st->accept_loop(st->alpn01_acc, false));
            need_io = true;
        }
        if (need_io) st->io_thread = std::jthread([ptr = st.get()] { ptr->io.run(); });
        st->renew_thread = std::jthread([ptr = st.get()](std::stop_token tok) { ptr->renew_loop(tok); });

        logs.emit(logging::Level::info, logging::Domain::core, 101, {},
            "acme service started (challenge={}, provider={}, http01_port={}, alpn01_port={})",
            cfg.challenge, cfg.dns01_provider.empty() ? "file" : cfg.dns01_provider, st->http01_port, st->alpn01_port);
        return ServiceHandle::create(std::move(st));
    }

    auto acme_http01_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->http01_port : 0;
    }
    auto acme_alpn01_port(ServiceHandle const& h) noexcept -> std::uint16_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->alpn01_port : 0;
    }
    auto acme_credential_generation(ServiceHandle const& h) noexcept -> std::uint64_t {
        return h.state ? static_cast<AcmeRuntimeState const*>(h.state.get())->live_credential->generation() : 0;
    }
    auto acme_has_valid_credential(ServiceHandle const& h) noexcept -> bool {
        return h.state && !static_cast<AcmeRuntimeState const*>(h.state.get())->live_credential->empty();
    }
    auto acme_credential_provider_erased(ServiceHandle const& h) noexcept -> std::shared_ptr<void> {
        return h.state ? std::static_pointer_cast<void>(static_cast<AcmeRuntimeState const*>(h.state.get())->live_credential) : nullptr;
    }
    auto acme_dns01_record(ServiceHandle const& h, std::string_view domain) -> std::optional<std::string> {
        if (!h.state) return std::nullopt;
        auto* st = static_cast<AcmeRuntimeState*>(h.state.get());
        std::lock_guard lk(st->ch_mu);
        auto it = st->dns01_records.find(std::string(domain));
        return it == st->dns01_records.end() ? std::nullopt : std::optional<std::string>(it->second);
    }
}
