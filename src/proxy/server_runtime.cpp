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

module proxy;
import std;
import dns.tls_query;
import dns.https_query;
import proxy.dns_backend;
import proxy.dns_state;
import nexus.thirdparty.corosio;

#if defined(NEXUS_TEST_VLESS_ABANDON) || defined(NEXUS_TEST_SS_ABANDON) || defined(NEXUS_TEST_TUNNEL_PROFILE) || defined(NEXUS_TEST_DNS_OWNER) || defined(NEXUS_TEST_FAKEIP_ABANDON)
extern "C" bool nexus_test_skip_server_stop();
#endif

namespace proxy {
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


    Server::Server():listener(std::in_place,context) {}
    Server::Server(RoutingOnly) {}
    Server::~Server() {
        if(!listener)return;
#if defined(NEXUS_TEST_VLESS_ABANDON) || defined(NEXUS_TEST_SS_ABANDON) || defined(NEXUS_TEST_TUNNEL_PROFILE) || defined(NEXUS_TEST_DNS_OWNER) || defined(NEXUS_TEST_FAKEIP_ABANDON)
        // Exercise member destruction with suspended tasks in the test target.
        if (nexus_test_skip_server_stop()) return;
#endif
        stop();
    }
    auto Server::create() -> std::expected<std::unique_ptr<Server>, std::error_code> {
        try { return std::make_unique<Server>(); }
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
        return owner.pending_probe.compare_exchange_strong(empty,std::move(probe),
            std::memory_order_release,std::memory_order_relaxed);
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
            (void)co_await nex::corosio::timeout(run_probe_op(),probe->deadline);
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
        unix_listener_cleanup=nullptr;
    }

    auto Server::begin_drain() noexcept -> void {
        if (drain_requested.exchange(true,std::memory_order_acq_rel)) return;
        retained_listener.close();
        if (!workers.empty()) return;
        accepting=false;
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

    auto Server::poll(std::chrono::milliseconds maximum_wait) -> void {
        auto& state = *this;
        if (!state.workers.empty()) { std::this_thread::sleep_for(std::clamp(maximum_wait,0ms,100ms)); return; }
        state.start_pending_probe();
        auto wait = std::clamp(maximum_wait, 0ms, 100ms);
#ifdef NEXUS_TPROXY_UDP
        if (state.transparent_udp) {
            state.poll_transparent_udp();
            wait=std::min(wait,5ms);
        }
#endif
        state.context.restart();
        if (wait <= 0ms) (void)state.context.poll();
        else (void)state.context.run_for(wait);
        auto const now = Clock::now();
        state.poll_fixed_udp(now);
        if (state.drain_requested.load(std::memory_order_relaxed)) {
            dns::reap_idle_tls_queries(state.context,Clock::time_point::max());
            dns::reap_idle_https_queries(state.context,Clock::time_point::max());
            state.direct_buffers.clear();
            state.splice_pipe_pool.clear();
        } else {
            dns_tls_maintenance.poll(state.context,now);
            state.direct_buffers.reap(now);
            state.splice_pipe_pool.reap(now);
        }
        visit_sessions(state.sessions,[now](Session& session) {
            auto const half_close_idle = session.half_closed &&
                now - std::max(session.touched, session.half_close_started) >= session.half_close_timeout;
            auto const expired = session.http_draining ? now - session.http_drain_started >= 5s :
                                 session.relaying ? (half_close_idle || now - session.touched >= 300s) :
                                 now >= session.handshake_deadline;
            if (!session.done && !session.closed && ((!session.transport_owner && (expired || now>=session.lifetime_deadline)) ||
                session.traffic.close_requested())) session.close();
        });
        if (state.drain_requested.load(std::memory_order_relaxed) && state.sessions.empty() && !state.probe_running
#ifdef NEXUS_ENABLE_NAIVE
            && state.modern_h3_drained()
#endif
        )
            state.drain_complete.store(true,std::memory_order_release);
    }

    auto Server::process_traffic_closes() -> void {
        if (!traffic) return;
        visit_sessions(sessions,[](Session& session) {
            if (!session.done && !session.closed && session.traffic.close_requested()) session.close();
        });
    }

    auto Server::stop() noexcept -> void {
        auto& state = *this;
        retained_listener.close();
        if (!state.workers.empty()) {
            state.stopping=true;
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
        dns::stop_tls_queries(state.context);
        dns::stop_https_queries(state.context);
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
        state.context.restart();
        (void)state.context.run();
        state.direct_buffers.clear();
        state.splice_pipe_pool.clear();
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
}
