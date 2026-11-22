export module naive.h3_client;
import std;
import naive.padding;
export import naive.h3_connect;
import masque.client_profile;
import masque.session;
import masque.datagram;
import quic.cid_registry;
import quic.native_memory;
import quic.datagram_port;
import quic.datagram_session;
import net.datagram_driver;
import hysteria2.transport_options;
import crypto;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

export namespace naive {
    template<class Connector, bool EnableDatagrams>
    class OwnedH3ConnectClient {
    public:
        using Registry = quic::CidRegistry<1, 8>;
        using Tls = masque::ClientProfile::Tls;
        using Hooks = H3ConnectHooks<Registry, false, kH3StreamCapacity, EnableDatagrams>;
        using App = masque::Session<Tls, Hooks, EnableDatagrams>;
        using QuicSession = quic::DatagramSession<Tls, App>;

        struct Bundle {
            std::unique_ptr<Tls> tls;
            Hooks hooks;
            quic::NativeMemory<> memory;
            App app;
            QuicSession session;

            Bundle(std::unique_ptr<Tls> t, Registry& reg, quic::SessionHandle id, nex::capy::async_event& ev,
                   nex::corosio::endpoint const& local, std::size_t native_bytes)
                : tls(std::move(t)), hooks(reg, id, ev), memory(native_bytes),
                  app(*tls, hooks, false, memory.http3()), session(*tls, app, local) {}
        };

    private:
        struct Factory {
            using Session = QuicSession;
            std::unique_ptr<Bundle> bundle;
            bool joined = false;
            int failure = 0;
            auto admit(q::ngtcp2_pkt_hd const&, nex::corosio::endpoint const&, H3Clock::time_point) const noexcept -> bool {
                return false;
            }
            auto create(quic::SessionHandle, Registry&, std::span<std::uint8_t const>, q::ngtcp2_pkt_hd const&,
                        nex::corosio::endpoint const&, H3Clock::time_point) noexcept -> std::expected<Session*, int> {
                return std::unexpected(q::err_callback_failure);
            }
            auto application_drained(quic::SessionHandle, Session const&) const noexcept -> bool { return joined; }
            auto failed(quic::SessionHandle, int err) noexcept -> void { failure = err; }
            auto destroy(quic::SessionHandle, Session&) noexcept -> void { bundle.reset(); }
        };

    public:
        using Socket = typename Connector::Socket;
        using Port = quic::DatagramPort<Factory, 1, 8, 8, true>;
        using Driver = net::DatagramDriver<Port, Socket>;
        using StreamHandle = H3StreamHandle<Bundle, Driver>;

    private:
        Connector connector_;
        masque::ClientProfile const& profile_;
        Socket socket_;
        nex::corosio::endpoint local_;
        Factory factory_;
        Port port_{factory_};
        Driver driver_{socket_, port_};
        bool starting_ = false, running_ = false, stopped_ = false, canceled_ = false;
        std::uint16_t leased_ = 0;
        unsigned active_calls_ = 0;

        auto clear() noexcept -> void {
            if (active_calls_ > 1 || starting_ || running_ || leased_ || !canceled_) return;
            driver_.finish();
            factory_.bundle.reset();
        }
        struct Call {
            OwnedH3ConnectClient& owner;
            explicit Call(OwnedH3ConnectClient& v) noexcept : owner(v) { ++owner.active_calls_; }
            ~Call() { owner.clear(); --owner.active_calls_; }
        };
        struct RootGuard {
            OwnedH3ConnectClient* owner;
            explicit RootGuard(OwnedH3ConnectClient& v) noexcept : owner(&v) {}
            RootGuard(RootGuard const&) = delete;
            RootGuard(RootGuard&& o) noexcept : owner(std::exchange(o.owner, nullptr)) {}
            ~RootGuard() {
                if (owner) {
                    Call call(*owner);
                    owner->factory_.joined = true;
                    owner->stop();
                    owner->running_ = false;
                    owner->driver_.changed().set();
                }
            }
        };
        static auto root(RootGuard guard) -> nex::capy::task<> {
            (void)co_await guard.owner->driver_.run();
        }

        auto check_response_headers(Hooks::Stream const& stream, bool expect_padding) const noexcept
            -> std::optional<bool> {
            std::string_view status;
            std::string_view pad_reply;
            for (auto const& h : stream.headers) {
                if (h.name == ":status") status = h.value;
                else if (header_ci_equal(h.name, "padding-type-reply")) pad_reply = h.value;
            }
            if (status != "200") return std::nullopt;
            return expect_padding && parse_padding_type_reply(pad_reply);
        }

    public:
        template<class... Args>
        OwnedH3ConnectClient(masque::ClientProfile const& profile, nex::corosio::io_context& ctx, Args&&... args)
            : connector_(ctx, std::forward<Args>(args)...), profile_(profile), socket_(ctx) {}

        ~OwnedH3ConnectClient() {
            if (starting_ || running_ || leased_ || active_calls_) std::terminate();
            stop();
            clear();
        }
        OwnedH3ConnectClient(OwnedH3ConnectClient const&) = delete;
        auto operator=(OwnedH3ConnectClient const&) -> OwnedH3ConnectClient& = delete;

        auto acquired() noexcept -> void { ++leased_; }
        auto released() noexcept -> void { Call call(*this); --leased_; }
        auto cancel() noexcept -> void { stop(); }
        auto stop() noexcept -> void {
            Call call(*this);
            stopped_ = canceled_ = true;
            connector_.cancel();
            if (factory_.bundle) {
                factory_.bundle->hooks.stopping();
                factory_.bundle->app.request_stop();
            }
            driver_.finish();
            driver_.changed().set();
        }
        auto usable() const noexcept -> bool {
            return !canceled_ && !stopped_ && driver_.running() && factory_.bundle &&
                   factory_.bundle->app.can_request() && !factory_.bundle->hooks.dead &&
                   !factory_.bundle->hooks.goaway;
        }
        auto available() const noexcept -> bool {
            return usable() && leased_ < kH3StreamCapacity;
        }
        auto drained() const noexcept -> bool {
            return !starting_ && !running_ && !leased_ && !active_calls_;
        }

        enum class StartResult { connected, failed, timeout };

        auto start(nex::corosio::io_context& ctx, H3Clock::time_point deadline) -> nex::capy::task<StartResult> {
            if (H3Clock::now() >= deadline) co_return StartResult::timeout;
            if (starting_ || running_ || canceled_) co_return StartResult::failed;
            starting_ = true;
            auto cleanup_unstarted = [&]() -> nex::capy::task<> {
                stop();
                while (running_) {
                    driver_.changed().clear();
                    co_await driver_.changed().wait();
                }
                starting_ = false;
            };
            auto peer = co_await connector_.prepare(socket_, deadline);
            if (!peer || canceled_) {
                co_await cleanup_unstarted();
                co_return H3Clock::now() >= deadline ? StartResult::timeout : StartResult::failed;
            }
            local_ = socket_.local_endpoint();
            auto reserved = port_.registry().reserve();
            if (!reserved) {
                co_await cleanup_unstarted();
                co_return StartResult::failed;
            }
            std::array<std::uint8_t, 8> src_bytes{};
            std::array<std::uint8_t, 16> dst_bytes{};
            auto tls = profile_.tls_client(*peer, nullptr);
            auto settings = hysteria2::TransportProfile<kH3StreamCapacity, kH3Window>::settings(profile_.transport());
            auto params = hysteria2::TransportProfile<kH3StreamCapacity, kH3Window>::parameters(profile_.transport());
            if (!crypto::random_bytes(src_bytes) || !crypto::random_bytes(dst_bytes) ||
                !port_.registry().insert(*reserved, src_bytes) || !tls || !settings || !params) {
                (void)port_.registry().release(*reserved);
                co_await cleanup_unstarted();
                co_return StartResult::failed;
            }
            auto now = H3Clock::now();
            if (now >= deadline) {
                (void)port_.registry().release(*reserved);
                co_await cleanup_unstarted();
                co_return StartResult::timeout;
            }
            auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now).count();
            settings->handshake_timeout = std::min(settings->handshake_timeout, static_cast<std::uint64_t>(remaining));
            factory_.bundle = std::make_unique<Bundle>(
                std::move(*tls), port_.registry(), *reserved, driver_.changed(), local_, profile_.transport().native_bytes);
            q::ngtcp2_cid src{}, dst{};
            q::ngtcp2_cid_init(&src, src_bytes.data(), src_bytes.size());
            q::ngtcp2_cid_init(&dst, dst_bytes.data(), dst_bytes.size());
            if (factory_.bundle->session.start(false, dst, src, *peer, *settings, *params,
                    factory_.bundle->memory.transport(), now) ||
                !port_.attach(*reserved, factory_.bundle->session)) {
                (void)port_.registry().release(*reserved);
                co_await cleanup_unstarted();
                co_return StartResult::failed;
            }
            running_ = true;
            bool launch_failed = false;
            try {
                nex::capy::run_async(ctx.get_executor(), [] {}, [this](std::exception_ptr) noexcept { stop(); })(
                    root(RootGuard(*this)));
            } catch (...) {
                running_ = false;
                launch_failed = true;
            }
            if (launch_failed) {
                co_await cleanup_unstarted();
                co_return StartResult::failed;
            }
            driver_.notify();
            for (;;) {
                if (factory_.bundle && factory_.bundle->app.can_request() &&
                    (!EnableDatagrams || factory_.bundle->app.can_open())) {
                    starting_ = false;
                    co_return StartResult::connected;
                }
                if (canceled_ || !driver_.running()) break;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err) break;
            }
            co_await cleanup_unstarted();
            co_return H3Clock::now() >= deadline ? StartResult::timeout : StartResult::failed;
        }

        auto open_connect(std::string_view authority, std::string_view auth_header,
                          std::span<std::pair<std::string, std::string> const> extra_headers,
                          bool request_padding, H3Clock::time_point deadline)
            -> nex::capy::task<std::optional<std::unique_ptr<StreamHandle>>> {
            if (!usable()) co_return std::nullopt;
            std::int64_t id = -1;
            for (;;) {
                if (!usable() || factory_.bundle->hooks.streams.size() >= kH3StreamCapacity) co_return std::nullopt;
                auto rc = q::ngtcp2_conn_open_bidi_stream(factory_.bundle->session.transport().native(), &id, nullptr);
                if (!rc) break;
                if (rc != q::err_stream_id_blocked) co_return std::nullopt;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err) co_return std::nullopt;
            }
            auto* s = factory_.bundle->hooks.open(id, false);
            if (!s) co_return std::nullopt;
            std::string pad_val;
            std::vector<h3::nghttp3_nv> fields;
            fields.reserve(4 + extra_headers.size());
            fields.push_back(h3_nv(":method", "CONNECT"));
            fields.push_back(h3_nv(":authority", authority));
            if (!auth_header.empty()) fields.push_back(h3_nv("proxy-authorization", auth_header));
            if (request_padding) {
                pad_val = generate_padding_header();
                fields.push_back(h3_nv("padding", pad_val));
                fields.push_back(h3_nv("padding-type-request", "1, 0"));
            }
            for (auto const& [k, v] : extra_headers) fields.push_back(h3_nv(k, v));
            if (factory_.bundle->app.h3().request(id, fields, true)) {
                factory_.bundle->hooks.streams.erase(id);
                co_return std::nullopt;
            }
            driver_.notify();
            while (usable()) {
                auto* cur = factory_.bundle->hooks.find(id);
                if (!cur || cur->failed || cur->retired) co_return std::nullopt;
                if (cur->complete) {
                    auto pad = check_response_headers(*cur, request_padding);
                    if (!pad) {
                        StreamHandle discard(*factory_.bundle, driver_, id, false);
                        (void)discard;
                        co_return std::nullopt;
                    }
                    co_return std::make_unique<StreamHandle>(*factory_.bundle, driver_, id, *pad);
                }
                if (cur->closed) co_return std::nullopt;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err) break;
            }
            co_return std::nullopt;
        }

        auto open_connect_udp(std::string_view proxy_authority, std::string_view target_host,
                              std::uint16_t target_port, std::string_view auth_header,
                              H3Clock::time_point deadline)
            -> nex::capy::task<std::optional<std::unique_ptr<StreamHandle>>> requires (EnableDatagrams) {
            if (!usable() || !factory_.bundle->app.can_open()) co_return std::nullopt;
            std::int64_t id = -1;
            if (q::ngtcp2_conn_open_bidi_stream(factory_.bundle->session.transport().native(), &id, nullptr))
                co_return std::nullopt;
            auto* s = factory_.bundle->hooks.open(id, true);
            if (!s) co_return std::nullopt;
            auto path = build_connect_udp_path(target_host, target_port);
            std::vector<h3::nghttp3_nv> fields{
                h3_nv(":method", "CONNECT"),
                h3_nv(":protocol", "connect-udp"),
                h3_nv(":scheme", "https"),
                h3_nv(":authority", proxy_authority),
                h3_nv(":path", path),
                h3_nv("capsule-protocol", "?1"),
            };
            if (!auth_header.empty()) fields.push_back(h3_nv("proxy-authorization", auth_header));
            if (factory_.bundle->app.h3().request(id, fields, true)) {
                factory_.bundle->hooks.streams.erase(id);
                co_return std::nullopt;
            }
            driver_.notify();
            while (usable()) {
                auto* cur = factory_.bundle->hooks.find(id);
                if (!cur || cur->failed || cur->retired) co_return std::nullopt;
                if (cur->complete) {
                    if (!check_response_headers(*cur, false)) {
                        StreamHandle discard(*factory_.bundle, driver_, id, false);
                        (void)discard;
                        co_return std::nullopt;
                    }
                    co_return std::make_unique<StreamHandle>(*factory_.bundle, driver_, id, false);
                }
                if (cur->closed) co_return std::nullopt;
                driver_.changed().clear();
                auto [err] = co_await nex::corosio::timeout(driver_.changed().wait(), deadline);
                if (err) break;
            }
            co_return std::nullopt;
        }
    };
}
