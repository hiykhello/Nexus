module relay;
import std;
import proxy.v4;
import snell.record;
import snell.cipher;
import snell.owner;
import snell.client_owner;
import snell.client_stream;
import snell.client_pool;
import snell.client_start;
import snell.async_record;
import snell.packet;
import snell.async_packet;
import snell.credential_file;
import snell.http_obfs;
import net.stream_relay;
import net.tcp_connect;
import net.tcp_fast_open_stream;
import net.unified_stream;
import capy;
import corosio;

namespace relay {
    namespace {
        enum class SnellMode : std::uint8_t { physical, layered, fast_open };
        struct SnellWorker;
        struct SnellProfile {
            std::string host; std::uint16_t port; snell::ClientOwner owner; std::optional<std::size_t> bootstrap;
            std::uint32_t timeout; TcpSocketOptions options; bool http_obfs; std::string obfs_host, obfs_uri;
            std::mutex mutex;
            std::vector<std::unique_ptr<SnellWorker>> physical;
            std::vector<std::unique_ptr<SnellWorker>> layered;
            std::vector<std::unique_ptr<SnellWorker>> fast;
            SnellProfile(std::string_view h, std::uint16_t p, snell::Credential credential, std::optional<std::size_t> b,
                         std::uint32_t t, TcpSocketOptions o, bool obfs, std::string_view oh, std::string_view ou);
            ~SnellProfile();
        };
        struct SnellLower {
            pro::proxy<TunnelFacade>& lower;
            auto read(std::span<std::uint8_t> data) { return lower->read(data); }
            auto send(std::span<std::uint8_t const> data) { return lower->send(data); }
            auto close_output() { return lower->close_output(); }
            auto cancel() noexcept -> void { if (lower) lower->cancel(); }
        };
        template<class Socket> class SnellRelay {
            Session& session_; Socket& socket_; SnellProfile const& profile_; bool local_;
            std::optional<snell::ClientStream<Socket>> stream_;
            using RecordStream = snell::AsyncRecord<Socket, snell::Cipher>;
            std::optional<RecordStream> packet_stream_; std::optional<snell::AsyncPacket<RecordStream>> packets_;
            net::DatagramDecoder packet_input_{net::DatagramFraming{}};
            std::vector<std::uint8_t> packet_output_; std::size_t packet_offset_ = 0;
            bool upload_started_ = false, download_started_ = false;
        public:
            SnellRelay(Session& session, Socket& socket, SnellProfile const& profile, bool local)
                : session_(session), socket_(socket), profile_(profile), local_(local) {}
            auto cancel() noexcept -> void { if (stream_) stream_->cancel(); else if (packets_) packets_->cancel(); else socket_.cancel(); }
            auto start(corosio::endpoint destination, Clock::time_point deadline, std::string_view domain = {}) -> capy::task<TunnelConnectResult> {
                if ((domain.empty() && !valid_destination(destination)) || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                snell::Request request{5, {}, domain.empty() ? destination.address().to_string() : std::string(domain), destination.port()};
                auto writer = co_await profile_.owner.start(socket_, std::move(request), {}, deadline);
                if (session_.closed) { socket_.cancel(); co_return TunnelConnectResult::failed; }
                if (!writer) co_return writer.error() == snell::IoError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                stream_.emplace(socket_, profile_.owner, std::move(*writer)); co_return TunnelConnectResult::connected;
            }
            auto start_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                auto connected = co_await profile_.owner.connect(socket_, snell::Request{6, {}, "", 0}, {}, deadline);
                if (session_.closed) { socket_.cancel(); co_return TunnelConnectResult::failed; }
                if (!connected) {
                    auto const& e = connected.error();
                    co_return std::holds_alternative<snell::IoError>(e) && std::get<snell::IoError>(e) == snell::IoError::timeout
                        ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                }
                if (!connected->early.empty()) { socket_.cancel(); co_return TunnelConnectResult::failed; }
                packet_stream_.emplace(socket_, std::move(connected->reader), std::move(connected->writer));
                packets_.emplace(*packet_stream_, true);
                co_return TunnelConnectResult::connected;
            }
            auto send(std::span<std::uint8_t const> data) -> capy::task<bool> {
                if (packets_) {
                    auto fed = packet_input_.feed(data);
                    if (fed.status != net::DatagramStatus::accepted || fed.consumed != data.size()) { cancel(); co_return false; }
                    auto p = packet_input_.packet(); if (!p) { cancel(); co_return false; }
                    auto const& a = p->destination;
                    snell::AddressKind kind = a.family == net::ProxyAddressFamily::ipv4 ? snell::AddressKind::ipv4
                        : a.family == net::ProxyAddressFamily::ipv6 ? snell::AddressKind::ipv6 : snell::AddressKind::domain;
                    snell::Packet packet{{kind, snell::Bytes(a.bytes.begin(), a.bytes.begin() + a.length), a.port},
                                         snell::Bytes(p->payload.begin(), p->payload.end())};
                    auto sent = co_await packets_->send(packet, {}, Clock::now() + std::chrono::seconds(300));
                    (void)packet_input_.consume();
                    if (sent) session_.touched = Clock::now();
                    co_return bool(sent);
                }
                if (!stream_) co_return false;
                auto ok = co_await stream_->send(data, Clock::now() + std::chrono::seconds(300));
                if (ok) session_.touched = Clock::now();
                co_return ok;
            }
            auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t, std::string>> {
                if (packets_) {
                    if (data.empty()) co_return std::unexpected("empty Snell packet output buffer");
                    if (packet_offset_ == packet_output_.size()) {
                        auto packet = co_await packets_->receive(Clock::now() + std::chrono::seconds(300));
                        if (!packet) co_return std::unexpected("Snell packet read failed");
                        net::ProxyAddress a;
                        a.family = packet->address.kind == snell::AddressKind::ipv4 ? net::ProxyAddressFamily::ipv4 : net::ProxyAddressFamily::ipv6;
                        if (packet->address.kind == snell::AddressKind::domain || packet->address.value.size() > a.bytes.size()) {
                            cancel(); co_return std::unexpected("invalid Snell packet source");
                        }
                        a.length = packet->address.value.size(); a.port = packet->address.port;
                        std::ranges::copy(packet->address.value, a.bytes.begin());
                        auto framed = net::encode_datagram({}, a, packet->payload);
                        if (!framed) { cancel(); co_return std::unexpected("invalid Snell packet"); }
                        packet_output_ = std::move(*framed); packet_offset_ = 0;
                    }
                    auto n = std::min(data.size(), packet_output_.size() - packet_offset_);
                    std::ranges::copy(std::span(packet_output_).subspan(packet_offset_, n), data.begin());
                    packet_offset_ += n; session_.touched = Clock::now(); co_return n;
                }
                if (!stream_) co_return std::unexpected("Snell stream not started");
                auto value = co_await stream_->read(data, Clock::now() + std::chrono::seconds(300));
                if (!value) {
                    auto const& remote = stream_->reply_error();
                    if (remote && std::holds_alternative<snell::RemoteError>(*remote)) {
                        auto const& error = std::get<snell::RemoteError>(*remote);
                        co_return std::unexpected("Snell remote error " + std::to_string(error.code) + ": " + error.message);
                    }
                    co_return std::unexpected("Snell stream read failed");
                }
                if (*value) session_.touched = Clock::now();
                co_return *value;
            }
            auto close_output() -> capy::task<bool> { return !stream_ ? ([]() -> capy::task<bool> { co_return false; }()) : stream_->close_output(Clock::now() + std::chrono::seconds(300)); }
            auto upload() -> capy::task<bool> {
                if (upload_started_ || !stream_) co_return false;
                upload_started_ = true;
                co_return co_await net::stream_relay::upload(net::ByteRelayAdapter{session_.client, *this, [this] { session_.touched = Clock::now(); }, local_, session_.traffic_delivery()});
            }
            auto download() -> capy::task<bool> {
                if (download_started_ || !stream_) co_return false;
                download_started_ = true;
                co_return co_await net::stream_relay::download(net::ByteRelayAdapter{session_.client, *this, [this] { session_.touched = Clock::now(); }, local_, session_.traffic_delivery()});
            }
        };

        // Shared lower-connection helper across SnellTunnel and pooled SnellNode.
        inline auto bind_snell_socket(
            SnellMode mode, Session& state, corosio::io_context& ctx, SnellProfile const& profile,
            TcpSocketOptions const& options, TunnelFactory const* detour, DnsSlot& dns,
            std::unique_ptr<LowerConnector>& lower, std::unique_ptr<SnellLower>& lower_stream,
            std::unique_ptr<corosio::tcp_socket>& tcp, std::unique_ptr<net::FastOpenStream>& fast,
            net::UnifiedStreamSocket& socket, Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
            if (mode == SnellMode::layered) {
                if (!detour) co_return TunnelConnectResult::failed;
                lower = std::unique_ptr<LowerConnector>(new LowerConnector{{}, &ctx, detour, profile.host, profile.port, profile.bootstrap});
                LowerConnector::Candidates candidates;
                auto result = co_await lower->connect(state, deadline, candidates);
                if (state.closed) co_return TunnelConnectResult::failed;
                if (result != TunnelConnectResult::connected) co_return result;
                lower_stream = std::make_unique<SnellLower>(SnellLower{lower->tunnel});
                socket.bind(*lower_stream);
                co_return TunnelConnectResult::connected;
            }
            auto resolved = profile.bootstrap
                ? co_await resolve_bootstrap_owned(state, ctx, dns, *profile.bootstrap, profile.host, profile.port, deadline)
                : co_await resolve_local_owned(state, ctx, dns, profile.host, profile.port, deadline);
            if (state.closed) co_return TunnelConnectResult::failed;
            if (!resolved || resolved->empty() || resolved->size() > 64)
                co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::retryable;
            if (mode == SnellMode::fast_open) {
                fast = std::make_unique<net::FastOpenStream>(ctx, std::move(*resolved), deadline, options);
                socket.bind(*fast);
                co_return TunnelConnectResult::connected;
            }
            tcp = std::make_unique<corosio::tcp_socket>(ctx);
            for (auto endpoint : *resolved) {
                if (state.closed) co_return TunnelConnectResult::failed;
                if (!valid_destination(endpoint)) continue;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                if (net::prepare_tcp_socket(*tcp, endpoint, options, deadline)) co_return TunnelConnectResult::failed;
                auto [error] = co_await corosio::timeout(tcp->connect(endpoint), deadline);
                if (state.closed) co_return TunnelConnectResult::failed;
                if (error) {
                    tcp->close();
                    if (capy::is_timeout(error) || Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                    continue;
                }
                socket.bind(*tcp);
                co_return TunnelConnectResult::connected;
            }
            co_return TunnelConnectResult::retryable;
        }

        class SnellDirectTunnel {
            using Socket = net::UnifiedStreamSocket;
            using Obfs = snell::HttpObfs<Socket>;
            SnellMode mode_; Session& session_; corosio::io_context& context_; SnellProfile const& profile_;
            TcpSocketOptions options_; TunnelFactory const* detour_;
            DnsSlot dns_; std::unique_ptr<LowerConnector> lower_; std::unique_ptr<SnellLower> lower_stream_;
            std::unique_ptr<corosio::tcp_socket> tcp_; std::unique_ptr<net::FastOpenStream> fast_;
            Socket socket_; Obfs obfs_; SnellRelay<Obfs> relay_;
            std::stop_source stop_; bool local_, starting_ = false, connected_ = false;
        public:
            SnellDirectTunnel(SnellMode mode, Session& s, corosio::io_context& c, SnellProfile const& p, bool local,
                              TcpSocketOptions options, TunnelFactory const* detour = nullptr)
                : mode_(mode), session_(s), context_(c), profile_(p), options_(std::move(options)), detour_(detour),
                  obfs_(socket_, p.http_obfs, false, p.obfs_host, p.obfs_uri), relay_(s, obfs_, p, local), local_(local) {}
            auto cancel() noexcept -> void {
                stop_.request_stop(); dns_.cancel(); relay_.cancel();
                if (lower_) lower_->cancel(); if (fast_) fast_->cancel(); if (tcp_) tcp_->cancel();
            }
            auto connect(corosio::endpoint target) -> capy::task<TunnelConnectResult> { return connect_until(target, session_.started + std::chrono::milliseconds(profile_.timeout)); }
            auto connect_until(corosio::endpoint target, Clock::time_point deadline) -> capy::task<TunnelConnectResult> { return start(target, deadline, false); }
            auto connect_domain(std::string_view domain, std::uint16_t port, Clock::time_point deadline) { return start(corosio::endpoint(corosio::ipv4_address{}, port), deadline, false, domain); }
            auto start(corosio::endpoint target, Clock::time_point deadline, bool packets, std::string_view domain = {}) -> capy::task<TunnelConnectResult> {
                if (starting_ || connected_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                starting_ = true;
                struct Guard { SnellDirectTunnel& self; bool done = false; ~Guard() { self.starting_ = false; if (!done) self.cancel(); } } guard{*this};
                auto bound = co_await bind_snell_socket(mode_, session_, context_, profile_, options_, detour_, dns_, lower_, lower_stream_, tcp_, fast_, socket_, deadline);
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (bound != TunnelConnectResult::connected) co_return bound;
                TunnelConnectResult result = packets ? co_await relay_.start_packets(deadline) : co_await relay_.start(target, deadline, domain);
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (result != TunnelConnectResult::connected) co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : result;
                connected_ = true; guard.done = true; co_return result;
            }
            auto send(std::span<std::uint8_t const> b) { return relay_.send(b); }
            auto read(std::span<std::uint8_t> b) { return relay_.read(b); }
            auto close_output() { return relay_.close_output(); }
            auto upload() { return relay_.upload(); }
            auto download() { return relay_.download(); }
            auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed, {}, false}; }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> { return start({}, deadline, true); }
            auto has_uot() const noexcept -> bool { return false; }
            auto has_xudp() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        };

        class SnellNode {
            using Socket = net::UnifiedStreamSocket;
            using Obfs = snell::HttpObfs<Socket>;
            using Stream = snell::ClientStream<Obfs>;
            SnellMode mode_;
            Session state_; OutboundContext env_; SnellProfile const& profile_; TcpSocketOptions options_; TunnelFactory const* detour_;
            DnsSlot dns_; std::unique_ptr<LowerConnector> lower_; std::unique_ptr<SnellLower> lower_stream_;
            std::unique_ptr<corosio::tcp_socket> tcp_; std::unique_ptr<net::FastOpenStream> fast_;
            Socket socket_; std::unique_ptr<Obfs> obfs_; std::unique_ptr<Stream> stream_;
            std::optional<snell::ClientReuse<Obfs>> reusable_;
            bool stopping_ = false, open_ = false;
        public:
            SnellNode(SnellMode mode, OutboundContext const& env, SnellProfile const& profile,
                      TcpSocketOptions options, TunnelFactory const* detour)
                : mode_(mode), state_(env.context), env_(env), profile_(profile), options_(std::move(options)), detour_(detour) {
                state_.dns = env.dns; state_.local_dns = env.local_dns;
                state_.tunnel_factories = env.factories; state_.direct_tcp_options = env.direct_options;
            }
            ~SnellNode() { cancel(); }
            [[nodiscard]] auto stopping() const noexcept -> bool { return stopping_; }
            [[nodiscard]] auto reusable() const noexcept -> bool { return !stopping_ && open_ && reusable_.has_value() && !stream_; }
            auto cancel() noexcept -> void {
                if (stopping_) return; stopping_ = true; dns_.cancel();
                if (stream_) stream_->cancel(); reusable_.reset(); if (obfs_) obfs_->cancel();
                socket_.cancel(); if (lower_) lower_->cancel(); if (fast_) fast_->cancel(); if (tcp_) tcp_->cancel();
                state_.close();
            }
            auto connect(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (stopping_ || Clock::now() >= deadline)
                    co_return Clock::now() >= deadline ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                if (open_) co_return TunnelConnectResult::connected;
                auto bound = co_await bind_snell_socket(mode_, state_, env_.context, profile_, options_, detour_,
                    dns_, lower_, lower_stream_, tcp_, fast_, socket_, deadline);
                if (stopping_ || state_.closed) co_return TunnelConnectResult::failed;
                if (bound != TunnelConnectResult::connected) co_return bound;
                obfs_ = std::make_unique<Obfs>(socket_, profile_.http_obfs, false, profile_.obfs_host, profile_.obfs_uri);
                open_ = true;
                co_return TunnelConnectResult::connected;
            }
            auto start(corosio::endpoint target, Clock::time_point deadline, std::string_view domain = {}) -> capy::task<TunnelConnectResult> {
                if (stopping_ || stream_ || (domain.empty() && !valid_destination(target))) co_return TunnelConnectResult::failed;
                auto connected = co_await connect(deadline); if (connected != TunnelConnectResult::connected) co_return connected;
                snell::Request request{5, {}, domain.empty() ? target.address().to_string() : std::string(domain), target.port()};
                if (reusable_) {
                    auto resumed = co_await profile_.owner.resume_start(*obfs_, std::move(*reusable_), std::move(request), deadline);
                    reusable_.reset();
                    if (stopping_) co_return TunnelConnectResult::failed;
                    if (!resumed) co_return resumed.error() == snell::IoError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    stream_ = Stream::resume(*obfs_, profile_.owner, std::move(*resumed));
                    if (!stream_) co_return TunnelConnectResult::failed;
                } else {
                    auto writer = co_await profile_.owner.start(*obfs_, std::move(request), {}, deadline);
                    if (stopping_) co_return TunnelConnectResult::failed;
                    if (!writer) co_return writer.error() == snell::IoError::timeout ? TunnelConnectResult::timeout : TunnelConnectResult::failed;
                    stream_ = std::make_unique<Stream>(*obfs_, profile_.owner, std::move(*writer));
                }
                co_return TunnelConnectResult::connected;
            }
            auto finish() -> bool {
                if (stopping_ || !stream_) return false;
                auto completed = stream_->finish(); if (!completed) return false;
                stream_.reset(); reusable_.emplace(std::move(*completed)); return true;
            }
            auto stream() noexcept -> Stream* { return stream_.get(); }
        };

        struct SnellWorker {
            SnellMode mode; OutboundContext env; SnellProfile const& profile; TcpSocketOptions options; TunnelFactory const* detour;
            snell::ClientPool<SnellNode> pool;
            SnellWorker(SnellMode m, OutboundContext const& e, SnellProfile const& p, TcpSocketOptions o, TunnelFactory const* d)
                : mode(m), env(e), profile(p), options(std::move(o)), detour(d), pool(e.context) {}
            auto create() -> std::unique_ptr<SnellNode> { return std::make_unique<SnellNode>(mode, env, profile, options, detour); }
        };
        SnellProfile::SnellProfile(std::string_view h, std::uint16_t p, snell::Credential credential, std::optional<std::size_t> b,
            std::uint32_t t, TcpSocketOptions o, bool obfs, std::string_view oh, std::string_view ou)
            : host(h), port(p), owner(std::move(credential)), bootstrap(b), timeout(t), options(o), http_obfs(obfs), obfs_host(oh), obfs_uri(ou) {}
        SnellProfile::~SnellProfile() = default;

        auto snell_slots(SnellProfile& profile, SnellMode mode) noexcept -> auto& {
            if (mode == SnellMode::layered) return profile.layered;
            if (mode == SnellMode::fast_open) return profile.fast;
            return profile.physical;
        }
        auto snell_find(SnellProfile& profile, SnellMode mode, corosio::io_context& context) noexcept -> SnellWorker* {
            for (auto const& worker : snell_slots(profile, mode))
                if (worker && &worker->env.context == &context) return worker.get();
            return nullptr;
        }
        auto snell_initialize(SnellProfile& profile, SnellMode mode, OutboundContext const& env,
                              TunnelFactory const* detour, bool direct) -> bool {
            std::lock_guard lock(profile.mutex);
            if (snell_find(profile, mode, env.context) || (direct && !env.direct_options)) return false;
            auto& slots = snell_slots(profile, mode);
            auto slot = std::ranges::find_if(slots, [](auto const& value) { return !value; });
            bool append = slot == slots.end();
            if (append) slots.reserve(slots.size() + 1);
            auto worker = std::make_unique<SnellWorker>(mode, env, profile, direct ? *env.direct_options : profile.options, detour);
            worker->pool.start();
            if (!append) *slot = std::move(worker); else slots.push_back(std::move(worker));
            return true;
        }
        auto snell_stop(SnellProfile& profile, corosio::io_context& context) noexcept -> void {
            for (auto mode : {SnellMode::physical, SnellMode::layered, SnellMode::fast_open}) {
                SnellWorker* worker = nullptr;
                { std::lock_guard lock(profile.mutex); worker = snell_find(profile, mode, context); }
                if (worker) worker->pool.stop();
            }
        }
        auto snell_finish(SnellProfile& profile, corosio::io_context& context) noexcept -> void {
            std::lock_guard lock(profile.mutex);
            for (auto mode : {SnellMode::physical, SnellMode::layered, SnellMode::fast_open})
                for (auto& worker : snell_slots(profile, mode))
                    if (worker && &worker->env.context == &context) {
                        if (!worker->pool.drained()) std::terminate();
                        worker.reset(); break;
                    }
        }

        class SnellPooledTunnel {
            using Worker = SnellWorker; using Node = SnellNode; using Pool = snell::ClientPool<Node>;
            Session& session_; Worker& worker_;
            bool local_, starting_ = false, ready_ = false, finished_ = false, upload_started_ = false, download_started_ = false;
            std::stop_source stop_; std::optional<typename Pool::Lease> lease_; pro::proxy<TunnelFacade> legacy_;
        public:
            SnellPooledTunnel(Session& session, Worker& worker, bool local) : session_(session), worker_(worker), local_(local) {}
            ~SnellPooledTunnel() { cancel(); }
            auto cancel() noexcept -> void {
                stop_.request_stop(); if (legacy_) legacy_->cancel();
                if (lease_ && !finished_) { auto node = lease_->hold(); finished_ = node->finish(); if (!finished_) node->cancel(); }
            }
            auto connect(corosio::endpoint ep) -> capy::task<TunnelConnectResult> { return connect_until(ep, session_.started + std::chrono::milliseconds(worker_.profile.timeout)); }
            auto connect_domain(std::string_view d, std::uint16_t p, Clock::time_point dl) { return connect_until(corosio::endpoint(corosio::ipv4_address{}, p), dl, d); }
            auto connect_until(corosio::endpoint endpoint, Clock::time_point deadline, std::string_view domain = {})
                -> capy::task<TunnelConnectResult> {
                if (starting_ || ready_ || legacy_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (Clock::now() >= deadline) co_return TunnelConnectResult::timeout;
                starting_ = true;
                struct Guard { SnellPooledTunnel& self; bool done = false; ~Guard() { self.starting_ = false; if (!done) self.cancel(); } } guard{*this};
                auto lease = worker_.pool.take([this] { return worker_.create(); }); if (!lease) co_return TunnelConnectResult::failed;
                lease_.emplace(std::move(*lease));
                auto result = co_await lease_->node().start(endpoint, deadline, domain);
                if (stop_.stop_requested() || session_.closed || lease_->node().stopping()) co_return TunnelConnectResult::failed;
                if (result != TunnelConnectResult::connected) co_return result;
                ready_ = true; guard.done = true; co_return result;
            }
            auto connect_packets(Clock::time_point deadline) -> capy::task<TunnelConnectResult> {
                if (starting_ || ready_ || legacy_ || stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                starting_ = true;
                struct Guard { SnellPooledTunnel& self; bool done = false; ~Guard() { self.starting_ = false; if (!done) self.cancel(); } } guard{*this};
                legacy_ = pro::make_proxy<TunnelFacade, SnellDirectTunnel>(worker_.mode, session_, worker_.env.context,
                    worker_.profile, local_, worker_.options, worker_.detour);
                auto result = co_await legacy_->connect_packets(deadline);
                if (stop_.stop_requested() || session_.closed) co_return TunnelConnectResult::failed;
                if (result == TunnelConnectResult::connected) { ready_ = true; guard.done = true; }
                co_return result;
            }
            auto send(std::span<std::uint8_t const> data) -> capy::task<bool> {
                if (legacy_) co_return co_await legacy_->send(data);
                if (!ready_ || stop_.stop_requested()) co_return false;
                auto result = co_await lease_->node().stream()->send(data, Clock::now() + std::chrono::seconds(300));
                if (result) session_.touched = Clock::now();
                co_return result;
            }
            auto read(std::span<std::uint8_t> data) -> capy::task<std::expected<std::size_t, std::string>> {
                if (legacy_) co_return co_await legacy_->read(data);
                if (!ready_ || stop_.stop_requested()) co_return std::unexpected("Snell stream closed");
                auto* stream = lease_->node().stream();
                auto result = co_await stream->read(data, Clock::now() + std::chrono::seconds(300));
                if (!result) {
                    auto const& remote = stream->reply_error();
                    if (remote && std::holds_alternative<snell::RemoteError>(*remote)) {
                        auto const& error = std::get<snell::RemoteError>(*remote);
                        co_return std::unexpected("Snell remote error " + std::to_string(error.code) + ": " + error.message);
                    }
                    co_return std::unexpected("Snell stream read failed");
                }
                if (*result) session_.touched = Clock::now();
                co_return *result;
            }
            auto close_output() -> capy::task<bool> {
                if (legacy_) co_return co_await legacy_->close_output();
                if (!ready_ || stop_.stop_requested()) co_return false;
                co_return co_await lease_->node().stream()->close_output(Clock::now() + std::chrono::seconds(300));
            }
            auto relay_dir(bool up) -> capy::task<bool> {
                if (legacy_) co_return co_await (up ? legacy_->upload() : legacy_->download());
                auto& flag = up ? upload_started_ : download_started_;
                if (!ready_ || flag) co_return false;
                flag = true;
                net::ByteRelayAdapter adapter{session_.client, *this, [this] { session_.touched = Clock::now(); }, local_, session_.traffic_delivery()};
                co_return co_await (up ? net::stream_relay::upload(std::move(adapter)) : net::stream_relay::download(std::move(adapter)));
            }
            auto upload() -> capy::task<bool> { return relay_dir(true); }
            auto download() -> capy::task<bool> { return relay_dir(false); }
            auto packet_transport() const noexcept -> net::PacketTransport { return {net::PacketTransportKind::framed, {}, false}; }
            auto has_uot() const noexcept -> bool { return false; } auto has_xudp() const noexcept -> bool { return false; }
            auto connect_uot() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_uot_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp() -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
            auto connect_xudp_until(Clock::time_point) -> capy::task<TunnelConnectResult> { co_return TunnelConnectResult::failed; }
        };
    }

    auto make_snell_factory(std::string_view host, std::uint16_t port, std::string_view psk, std::optional<std::string_view> user,
        std::optional<std::size_t> bootstrap, std::uint32_t timeout, TcpSocketOptions options, bool fast_open,
        bool http_obfs, std::string_view obfs_host, std::string_view obfs_uri, bool reuse) -> std::expected<TunnelFactory, std::string> {
        if (host.empty() || host.size() > 253 || !port || !timeout || timeout > 3600000 || !options.valid())
            return std::unexpected("invalid Snell dial options");
        auto visible = [](std::string_view value) { return std::ranges::all_of(value, [](unsigned char ch) { return ch > 32 && ch < 127; }); };
        if ((!http_obfs && (!obfs_host.empty() || !obfs_uri.empty())) || obfs_host.size() > 253 || !visible(obfs_host) ||
            obfs_uri.size() > 1024 || (!obfs_uri.empty() && obfs_uri.front() != '/') || !visible(obfs_uri))
            return std::unexpected("invalid Snell HTTP obfs options");
        auto credential = snell::load_credential(psk, user); if (!credential) return std::unexpected(credential.error());
        auto profile = std::make_unique<SnellProfile>(host, port, std::move(*credential), bootstrap, timeout, options, http_obfs, obfs_host, obfs_uri);
        auto* borrowed = profile.get();
        TunnelFactory factory{[profile = std::move(profile), fast_open, reuse](Session& s, corosio::io_context& c, bool local, TcpSocketOptions const* inherited) -> pro::proxy<TunnelFacade> {
            if (reuse) {
                std::lock_guard lock(profile->mutex);
                if (auto w = snell_find(*profile, SnellMode::fast_open, c)) return pro::make_proxy<TunnelFacade, SnellPooledTunnel>(s, *w, local);
                if (auto w = snell_find(*profile, SnellMode::physical, c)) return pro::make_proxy<TunnelFacade, SnellPooledTunnel>(s, *w, local);
                return {};
            }
            auto mode = (inherited ? inherited->tcp_fast_open.value_or(false) : fast_open) ? SnellMode::fast_open : SnellMode::physical;
            return pro::make_proxy<TunnelFacade, SnellDirectTunnel>(mode, s, c, *profile, local, inherited ? *inherited : profile->options);
        }, timeout, [borrowed, reuse](Session& s, corosio::io_context& c, TunnelFactory const& detour, bool local) -> pro::proxy<TunnelFacade> {
            if (reuse) {
                std::lock_guard lock(borrowed->mutex);
                auto w = snell_find(*borrowed, SnellMode::layered, c);
                return w ? pro::make_proxy<TunnelFacade, SnellPooledTunnel>(s, *w, local) : pro::proxy<TunnelFacade>{};
            }
            return pro::make_proxy<TunnelFacade, SnellDirectTunnel>(SnellMode::layered, s, c, *borrowed, local, borrowed->options, &detour);
        }, std::nullopt, options.configured() || fast_open};
        if (reuse) {
            factory.start_context = [borrowed, fast_open](OutboundContext const& env, TunnelFactory const* detour, bool direct) {
                auto fast = direct && env.direct_options ? env.direct_options->tcp_fast_open.value_or(false) : fast_open;
                return detour ? snell_initialize(*borrowed, SnellMode::layered, env, detour, direct)
                    : snell_initialize(*borrowed, fast ? SnellMode::fast_open : SnellMode::physical, env, nullptr, direct);
            };
            factory.stop_context = [borrowed](corosio::io_context& c) noexcept { snell_stop(*borrowed, c); };
            factory.quiesced_context = [borrowed](corosio::io_context& c) noexcept {
                std::lock_guard lock(borrowed->mutex);
                return std::ranges::none_of(std::array{SnellMode::physical, SnellMode::layered, SnellMode::fast_open},
                    [&](auto m) { auto* w = snell_find(*borrowed, m, c); return w && !w->pool.drained(); });
            };
            factory.finish_context = [borrowed](corosio::io_context& c) noexcept { snell_finish(*borrowed, c); };
        }
        return factory;
    }
}
