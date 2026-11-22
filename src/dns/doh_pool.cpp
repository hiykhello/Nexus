module dns.doh_pool;
import std;
import dns.corosio_query;
import dns.doh_exchange;
import dns.input_budget;
import http2.client_channel;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

namespace dns::doh_detail {
    namespace {
        struct HttpsProfile {
            StreamFactory stream;
            std::optional<std::chrono::milliseconds> connect_timeout;
            std::string authority,path;
        };

#include "https_pool.hpp"

        struct HttpsQuery {
            std::shared_ptr<HttpsProfile const> profile;

            auto operator()(Io& context,Endpoint endpoint,QueryMessage const& query,std::uint16_t id,
                Clock::time_point deadline,InputBudget& budget,std::stop_token stop) const -> Reply {
                if (stop.stop_requested()) co_return std::unexpected(Error::canceled);
                if (Clock::now()>=deadline) co_return std::unexpected(Error::timeout);
                auto request=make_query_wire(query);
                if (!request) co_return std::unexpected(request.error());
                auto& pool=context.use_service<HttpsPool>();
                if (pool.stopped()) co_return std::unexpected(Error::canceled);
                if (auto connection=pool.find(*profile,endpoint))
                    co_return co_await connection->query(query,id,std::move(*request),deadline,budget,stop);

                auto handshake=pool.join(context,profile,endpoint);
                if (!handshake) co_return std::unexpected(handshake.error());

                Stream stream;
                if (*handshake) {
                    auto ready=co_await (*handshake)->wait(deadline,stop);
                    if (!ready) co_return std::unexpected(ready.error());
                    if (pool.stopped()) co_return std::unexpected(Error::canceled);
                    if (auto connection=pool.find(*profile,endpoint))
                        co_return co_await connection->query(query,id,std::move(*request),deadline,budget,stop);
                    stream=(*handshake)->take();
                }
                if (!stream) {
                    // Each HTTP/1.1 exchange owns its TLS connection. Another
                    // waiter may already have taken the negotiated stream.
                    auto made=profile->stream(context,endpoint);
                    if (!made) co_return std::unexpected(made.error());
                    stream=std::move(*made);
                    std::stop_callback cancellation(stop,[&] noexcept {stream->cancel();});
                    auto connect_by=profile->connect_timeout ? std::min(deadline,Clock::now()+*profile->connect_timeout) : deadline;
                    if (!co_await stream->start(connect_by) || stop.stop_requested() || pool.stopped())
                        co_return std::unexpected(stop.stop_requested() || pool.stopped() ? Error::canceled :
                            Clock::now()>=deadline ? Error::timeout : Error::transport);
                }
                if (stream->multiplexed()) {
                    if (auto connection=pool.adopt(profile,endpoint,stream)) {
                        connection->start(context,connection);
                        co_return co_await connection->query(query,id,std::move(*request),deadline,budget,stop);
                    }
                }
                std::stop_callback cancellation(stop,[&] noexcept {stream->cancel();});
                co_return co_await stream->fresh(profile->authority,profile->path,endpoint.port(),
                    query,id,*request,deadline,budget,stop);
            }
        };
    }

    auto pooled_query(StreamFactory stream,std::string authority,std::string path,
        std::optional<std::chrono::milliseconds> connect_timeout) -> dns::detail::ProtectedQuery {
        return dns::detail::ProtectedQuery{HttpsQuery{std::make_shared<HttpsProfile const>(
            HttpsProfile{std::move(stream),connect_timeout,std::move(authority),std::move(path)})}};
    }
    auto stop_pool(Io& context) noexcept -> void {
        if (auto* pool=context.find_service<HttpsPool>()) pool->stop();
    }
    auto resume_pool(Io& context) noexcept -> void {
        if (auto* pool=context.find_service<HttpsPool>()) pool->resume();
    }
    auto reap_pool(Io& context,Clock::time_point now) noexcept -> void {
        if (auto* pool=context.find_service<HttpsPool>()) pool->reap(now);
    }
}
