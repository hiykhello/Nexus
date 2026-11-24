module;
#include <proxy/proxy_macros.h>
#include <boost/capy/buffers.hpp>
#include <boost/capy/cond.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/backend.hpp>
#include <boost/corosio/posix_stream_descriptor.hpp>
#include <boost/corosio/tcp_acceptor.hpp>
#include <boost/corosio/tcp_socket.hpp>
#include <boost/corosio/endpoint.hpp>

module relay;
import std;
import dns.tls_query;
import dns.https_query;
import dns.quic_query;
import relay.dns_backend;
import relay.dns_state;
import corosio;

#if defined(NEXUS_TEST_VLESS_ABANDON) || defined(NEXUS_TEST_SS_ABANDON) || defined(NEXUS_TEST_TUNNEL_PROFILE) || defined(NEXUS_TEST_DNS_OWNER) || defined(NEXUS_TEST_FAKEIP_ABANDON)
extern "C" bool nexus_test_skip_server_stop();
#endif

namespace relay {
    using namespace std::chrono_literals;

    namespace {
        // A close may synchronously release other sessions. Reverse indices
        // keep unvisited survivors below remaining despite swap/pop removal.
        // No iterator or Session reference is used after invoking the visitor.
        // Attachment occurs in executor tasks, not during these control walks.
        template<class Visitor>
        auto visit_sessions(std::vector<Session*>& sessions,Visitor&& visitor) -> void {
            auto remaining=sessions.size();
            while (remaining) {
                remaining=std::min(remaining,sessions.size());
                if (!remaining) break;
                auto* session=sessions[--remaining];
                visitor(*session);
            }
        }
    }

    auto Server::record_failure(RuntimeFailure value) -> void {
        std::lock_guard lock(failure_mutex);
        if (!failure_state) failure_state=value;
    }

    auto Server::get_failure() const -> std::optional<RuntimeFailure> {
        std::lock_guard lock(failure_mutex);
        return failure_state;
    }


    Server::Server() : context(*owned_context), listener(std::in_place, *owned_context) {}
    Server::Server(RoutingOnly) : context(*owned_context) {}
    Server::Server(io::io_context& external_context)
        : owned_context(std::nullopt), context(external_context), shared_context(true), listener(std::in_place, external_context) {}
    Server::~Server() {
        if(!listener)return;
#if defined(NEXUS_TEST_VLESS_ABANDON) || defined(NEXUS_TEST_SS_ABANDON) || defined(NEXUS_TEST_TUNNEL_PROFILE) || defined(NEXUS_TEST_DNS_OWNER) || defined(NEXUS_TEST_FAKEIP_ABANDON)
        // Exercise member destruction with suspended tasks in the test target.
        if (nexus_test_skip_server_stop()) return;
#endif
        stop();
    }
    auto make_shared_io_context() -> std::expected<std::unique_ptr<io::io_context>, std::error_code> {
        try {
#if BOOST_COROSIO_HAVE_LIBURING
            return std::make_unique<io::io_context>(io::uring);
#else
            return std::make_unique<io::io_context>();
#endif
        } catch (std::system_error const& error) { return std::unexpected(error.code()); }
    }
    auto Server::create() -> std::expected<std::unique_ptr<Server>, std::error_code> {
        try { return std::make_unique<Server>(); }
        catch (std::system_error const& error) { return std::unexpected(error.code()); }
    }
    auto Server::create_shared(io::io_context& external_context) -> std::expected<std::unique_ptr<Server>, std::error_code> {
        try { return std::make_unique<Server>(external_context); }
        catch (std::system_error const& error) { return std::unexpected(error.code()); }
    }

    auto describe(FailureKind kind) noexcept -> std::string_view {
        switch (kind) {
        case FailureKind::accept: return "accept failed";
        case FailureKind::accept_task: return "accept task failed";
        case FailureKind::worker: return "worker failed";
        case FailureKind::transparent_udp: return "TPROXY UDP receive failed";
        }
        return "unknown proxy failure";
    }

    auto Server::healthy() const noexcept -> bool {
        return this->running && !this->failed.load(std::memory_order_relaxed);
    }

    auto Server::failure() const -> std::optional<RuntimeFailure> { return this->get_failure(); }

    auto Server::queue_outbound_probe(std::shared_ptr<OutboundProbe> probe) -> bool {
        auto& owner=workers.empty() ? *this : *workers.front();
        std::shared_ptr<OutboundProbe> empty;
        if (!owner.pending_probe.compare_exchange_strong(empty,std::move(probe),
            std::memory_order_release,std::memory_order_relaxed)) return false;
        if (!workers.empty()) owner.context.stop();
        return true;
    }

    auto Server::run_probe(std::shared_ptr<OutboundProbe> probe) -> capy::task<> {
        auto started=Clock::now();
        auto lease=acquire_session();
        auto measurement=1u;
        if (lease && started<probe->deadline) {
            Session session(context);
            attach_session(session,std::move(*lease));
            session.handshake_deadline=probe->deadline;
            auto run_probe_op=[&]() -> capy::task<capy::results<>> {
                if (probe->mode==OutboundProbeMode::h2_ping) {
                    if (auto rtt=co_await probe_h2_ping(session,*probe)) {
                        measurement=*rtt+2;
                    }
                } else if (co_await probe_http(session,*probe)) {
                    auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-started);
                    measurement=static_cast<std::uint32_t>(elapsed.count())+2;
                }
                co_return capy::results<>{};
            };
            // The routed TUN and QUIC executors do not use Server::poll's
            // session expiry. The probe owns its deadline on every executor.
            (void)co_await corosio::timeout(run_probe_op(),probe->deadline);
            session.close();
        }
        probe->result.store(measurement,std::memory_order_release);
    }

    auto Server::start_pending_probe() -> void {
        if (probe_running || !running || drain_requested.load(std::memory_order_relaxed)) return;
        auto probe=pending_probe.exchange({},std::memory_order_acq_rel);
        if (!probe) return;
        probe_running=true;
        try {
            capy::run_async(context.get_executor(),[this] {probe_running=false;},
                [this,probe](std::exception_ptr) noexcept {
                    probe->result.store(1,std::memory_order_release);
                    probe_running=false;
                })(run_probe(probe));
        } catch (...) {
            probe->result.store(1,std::memory_order_release);
            probe_running=false;
        }
    }

    auto Server::close_listener() noexcept -> void {
        if (listener) listener->close();
        if (listener_readiness) listener_readiness->close();
        staged_listener.close();
        unix_listener_cleanup=nullptr;
    }

    auto Server::retire_acceptor() noexcept -> void {
        accepting = false;
        close_listener();
    }

    auto Server::begin_drain() noexcept -> void {
        if (drain_requested.exchange(true,std::memory_order_acq_rel)) return;
        retained_listeners.clear();
        if (!workers.empty()) {
            for (auto& worker : workers) worker->context.stop();
            return;
        }
        accepting=false;
        if (admission) admission->detach(this);
        close_listener();
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        drain_xhttp3();
#endif
#ifdef NEXUS_ENABLE_NAIVE
        drain_modern_h3();
#endif
        drain_fixed_udp();
#ifdef NEXUS_TPROXY_UDP
        stop_transparent_udp();
#endif
        if (auto probe=pending_probe.exchange({},std::memory_order_acq_rel))
            probe->result.store(1,std::memory_order_release);
    }

    auto Server::drained() const noexcept -> bool {
        if (workers.empty()) return drain_complete.load(std::memory_order_acquire);
        return std::ranges::all_of(workers,[](auto const& worker) {return worker->drained();});
    }

    auto Server::set_memory_shed(std::shared_ptr<std::atomic_bool const> flag) noexcept -> void {
        memory_shed=std::move(flag);
        for (auto& w : workers) w->set_memory_shed(memory_shed);
    }

    auto Server::request_memory_reclaim(std::uint8_t level) noexcept -> void {
        if (!level) return;
        std::uint8_t cur=memory_reclaim_requested.load(std::memory_order_relaxed);
        while (cur<level && !memory_reclaim_requested.compare_exchange_weak(cur,level,std::memory_order_release)) {}
        for (auto& w : workers) w->request_memory_reclaim(level);
    }

    auto Server::set_shadowsocks_dynamic_users(std::shared_ptr<ShadowsocksUserDirectory> users) noexcept -> void {
        ss_dynamic_users=std::move(users);
        for (auto& w : workers) w->set_shadowsocks_dynamic_users(ss_dynamic_users);
    }

    auto Server::apply_memory_reclaim(std::uint8_t level) noexcept -> void {
        if (level>=1) {
            direct_buffers.clear();
            splice_pipe_pool.clear();
            dns::reap_idle_tls_queries(context,Clock::time_point::max());
            dns::reap_idle_https_queries(context,Clock::time_point::max());
            reap_outbound_contexts();
        }
        if (level>=2) {
            if (dns && dns->message_cache) dns->message_cache->clear_entries();
            if (reverse_cache) (void)reverse_cache->clear();
        }
    }

    auto Server::prepare_poll() -> std::chrono::milliseconds {
        if (!workers.empty()) return std::chrono::milliseconds::max();
        if (auto rl = memory_reclaim_requested.exchange(0, std::memory_order_acq_rel)) apply_memory_reclaim(rl);
        start_pending_probe();
        auto cap = std::chrono::milliseconds::max();
        if (splice_pipe_pool.has_idle()) cap = std::min(cap, std::chrono::milliseconds(100));
#ifdef NEXUS_TPROXY_UDP
        if (transparent_udp) {
            poll_transparent_udp();
            cap = 5ms;
        }
#endif
        return cap;
    }

    auto Server::finish_poll(Clock::time_point now, bool maintain_dns) -> void {
        if (!workers.empty()) return;
        poll_fixed_udp(now);
        if (drain_requested.load(std::memory_order_relaxed)) {
            dns::reap_idle_tls_queries(context, Clock::time_point::max());
            dns::reap_idle_https_queries(context, Clock::time_point::max());
            direct_buffers.clear();
            splice_pipe_pool.clear();
        } else {
            if (maintain_dns) dns_tls_maintenance.poll(context, now);
            direct_buffers.reap(now);
            splice_pipe_pool.reap(now);
        }
        visit_sessions(sessions, [now](Session& session) {
            auto const half_close_idle = session.half_closed &&
                now - std::max(session.touched, session.half_close_started) >= session.half_close_timeout;
            auto const expired = session.http_draining ? now - session.http_drain_started >= 5s :
                                 session.relaying ? (half_close_idle || now - session.touched >= 300s) :
                                 now >= session.handshake_deadline;
            if (!session.done && !session.closed && ((!session.transport_owner && (expired || now >= session.lifetime_deadline)) ||
                session.traffic.close_requested())) session.close();
        });
        if (drain_requested.load(std::memory_order_relaxed) && sessions.empty() && !probe_running &&
            !(inbound_type == Inbound::fixed_udp && accept_task_active)
#ifdef NEXUS_ENABLE_NAIVE
            && modern_h3_drained()
#endif
        )
            drain_complete.store(true, std::memory_order_release);
    }

    auto Server::poll(std::chrono::milliseconds maximum_wait) -> void {
        auto& state = *this;
        if (!state.workers.empty()) { std::this_thread::sleep_for(std::clamp(maximum_wait,0ms,100ms)); return; }
        auto wait = std::clamp(std::min(maximum_wait, state.prepare_poll()), 0ms, 250ms);
        state.context.restart();
        if (wait <= 0ms) (void)state.context.poll();
        else (void)state.context.run_for(wait);
        state.finish_poll(Clock::now(), true);
    }

    auto Server::process_traffic_closes() -> void {
        if (!traffic) return;
        visit_sessions(sessions,[](Session& session) {
            if (!session.done && !session.closed && session.traffic.close_requested()) session.close();
        });
    }

    auto Server::stop() noexcept -> void {
        auto& state = *this;
        retained_listeners.clear();
        if (!state.workers.empty()) {
            state.stopping=true;
            for (auto& worker : state.workers) worker->context.stop();
            for (auto& thread : state.threads) if (thread.joinable()) thread.join();
            state.threads.clear();
            // Workers without threads arise only on a partial thread-start failure.
            for (auto& worker : state.workers) worker->stop();
            state.workers.clear();
            state.running=false;
            state.admission.reset();
            return;
        }
        state.running = false;
        state.accepting = false;
        if (state.admission) state.admission->detach(&state);
        if (auto probe=state.pending_probe.exchange({},std::memory_order_acq_rel))
            probe->result.store(1,std::memory_order_release);
        state.close_listener();
#ifdef NEXUS_ENABLE_XHTTP_VLESS
        state.stop_xhttp3();
#endif
#ifdef NEXUS_ENABLE_NAIVE
        state.stop_modern_h3();
#endif
        state.stop_fixed_udp();
#ifdef NEXUS_TPROXY_UDP
        state.stop_transparent_udp();
#endif
        bool was_registered = std::exchange(state.context_registered, false);
        std::size_t remaining_servers = was_registered ? unregister_context_server(state.context, &state) : 1;
        bool full_io_shutdown = !state.shared_context || (was_registered && remaining_servers == 0);
        if (full_io_shutdown) {
            dns::stop_tls_queries(state.context);
            dns::stop_https_queries(state.context);
            dns::stop_quic_queries(state.context);
        }
        if (state.dns) state.dns->stop_message_refresh();
        visit_sessions(state.sessions,[](Session& session) { session.close(); });
        state.stop_outbound_contexts();
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        if (state.dns && state.dns->refresh) stop_group_refresh(state.dns->refresh.get());
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        if (state.dns && state.dns->coordinator) state.dns->coordinator->stop();
#if defined(NEXUS_DNS_SHARED) && defined(NEXUS_DNS_RESPONSE)
        if (state.dns && state.dns->response_coordinator) state.dns->response_coordinator->stop();
#endif
#endif
        if (full_io_shutdown) {
            state.context.restart();
            (void)state.context.run();
        } else {
            auto self_drained = [&] {
                bool dns_ok = !state.dns
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
                    || ((!state.dns->coordinator || state.dns->coordinator->drained())
#if defined(NEXUS_DNS_SHARED) && defined(NEXUS_DNS_RESPONSE)
                        && (!state.dns->response_coordinator || state.dns->response_coordinator->drained())
#endif
                       )
#endif
                    ;
                return state.sessions.empty() && !state.accept_task_active && !state.probe_running &&
                       dns_ok && state.outbound_contexts_quiesced();
            };
            for (int iter = 0; iter < 500 && !self_drained(); ++iter) {
                state.context.restart();
                if (!state.context.poll()) (void)state.context.run_for(1ms);
            }
        }
        state.direct_buffers.clear();
        state.splice_pipe_pool.clear();
        state.fixed_udp_inbound.reset();
        state.cached_route_snapshot.reset();
        state.cached_route_version = 0;
        if (state.dns) state.dns->message_cache.reset();
        state.admission.reset();
        state.finish_outbound_contexts();
#ifdef NEXUS_TPROXY_UDP
        state.transparent_udp.reset();
#endif
#ifdef NEXUS_TEST_DNS_GROUP_REFRESH
        if (state.dns && state.dns->refresh) {
            if (!group_refresh_drained(state.dns->refresh.get())) std::terminate();
            state.dns->refresh.reset();
        }
#endif
#if defined(NEXUS_DNS_SHARED) || defined(NEXUS_TEST_DNS_COORDINATOR)
        if (state.dns && state.dns->coordinator) {
            if (!state.dns->coordinator->drained()) std::terminate();
            state.dns->coordinator.reset(); state.dns->views.reset();
#ifdef NEXUS_DNS_SHARED
#ifdef NEXUS_DNS_RESPONSE
            if (state.dns->response_coordinator && !state.dns->response_coordinator->drained()) std::terminate();
            state.dns->response_coordinator.reset();
#endif
            state.dns->local_views.reset();
#endif
        }
#endif
    }

    auto Server::run_worker_thread(Server* ptr) -> void {
        try {
            while (!stopping.load(std::memory_order_relaxed)) {
                if (drain_requested.load(std::memory_order_acquire)) ptr->begin_drain();
                auto const wait = ptr->drain_requested.load(std::memory_order_relaxed) ? 20ms :
                                  ptr->sessions.empty() ? 200ms : 100ms;
                ptr->poll(wait);
                if (!ptr->running) {
                    record_failure(ptr->get_failure().value_or(RuntimeFailure{FailureKind::worker, {}}));
                    failed = true;
                    stopping = true;
                }
            }
            ptr->stop();
        } catch (...) {
            try { record_failure({FailureKind::worker, {}}); } catch (...) {}
            failed = true;
            stopping = true;
            ptr->stop();
        }
    }
}
