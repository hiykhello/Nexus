module;
#include <proxy/proxy_macros.h>
#include <boost/capy/ex/async_event.hpp>
#include <boost/capy/ex/run_async.hpp>
#include <boost/capy/task.hpp>
#include <boost/capy/when_all.hpp>
#include <boost/corosio/delay.hpp>
#include <boost/corosio/endpoint.hpp>
#include <boost/corosio/io_context.hpp>
#include <boost/corosio/ipv4_address.hpp>
#include <boost/corosio/ipv6_address.hpp>
#include <boost/corosio/timeout.hpp>
module proxy;
import std;
import proxy.v4;
import packet;
import tcp.send;
import tcp.receive;
import net.datagram_frame;
import net.stream_relay;
import platform.linux_random;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
#include "l3_mux.hpp"

namespace proxy {
    namespace {
        auto now_ms() noexcept -> std::uint64_t {
            return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now().time_since_epoch()).count();
        }

        struct MeshHost : std::enable_shared_from_this<MeshHost> {
            std::shared_ptr<MeshLink> link;
            io::io_context& context;
            std::uint16_t mtu;
            std::optional<std::uint64_t> revision;
            L3Mux mux;
            bool stopped=false, active=false;
            std::stop_source stop_source;

            MeshHost(std::shared_ptr<MeshLink> value, io::io_context& io, std::uint16_t limit)
                : link(std::move(value)), context(io), mtu(limit), mux({false,{},false,{},mtu},
                    [](void* raw, std::span<std::uint8_t const> packet) {
                        auto& self=*static_cast<MeshHost*>(raw);
                        return self.revision && !self.stopped && self.link->send(*self.revision,packet);
                    },this) {}

            auto stop() noexcept -> void {
                stopped=true;
                stop_source.request_stop();
                mux.reset_flows();
                revision.reset();
            }
            auto refresh() -> void {
                auto next=link->network();
                if(!next) {
                    if(revision)mux.reset_flows();
                    revision.reset();
                    return;
                }
                if(revision==next->revision)return;
                mux.reset_flows();
                revision=next->revision;
                mux.set_endpoint({next->ipv4.has_value(),next->ipv4.value_or(std::array<std::uint8_t,4>{}),
                    next->ipv6.has_value(),next->ipv6.value_or(std::array<std::uint8_t,16>{}),mtu});
            }
            static auto drive(std::shared_ptr<MeshHost> self) -> capy::task<> {
                while(!self->stopped && !self->link->failed()) {
                    self->refresh();
                    auto now=now_ms();
                    if(self->revision) {
                        for(unsigned i=0;i<32;++i) {
                            auto packet=self->link->receive(*self->revision);
                            if(!packet)break;
                            self->mux.on_ip_packet(*packet,now);
                        }
                        self->mux.tick(now);
                    }
                    auto [error]=co_await io::delay(std::chrono::milliseconds(3));
                    if(error)break;
                }
                self->stop();
                self->active=false;
            }
            auto ensure_started(Session& session,DnsSlot&,Clock::time_point deadline) -> capy::task<bool> {
                if (!active && !stopped) {
                    active=true;
                    auto self=shared_from_this();
                    try {
                        capy::run_async(context.get_executor(),stop_source.get_token(),[]() noexcept {},
                            [self](std::exception_ptr) noexcept {self->active=false;self->stop();})(drive(self));
                    } catch(...) {active=false;stop();co_return false;}
                }
                while(!stopped && !session.closed && !link->failed() && Clock::now()<deadline) {
                    refresh();
                    if(revision)co_return true;
                    auto [error]=co_await io::delay(std::chrono::milliseconds(10));
                    if(error)break;
                }
                co_return false;
            }
        };
#include "l3_tunnel.hpp"

        struct MeshProfile {
            std::shared_ptr<MeshLink> link;
            std::uint16_t mtu;
            std::mutex mutex;
            std::unordered_map<io::io_context*,std::shared_ptr<MeshHost>> hosts;
            MeshProfile(std::shared_ptr<MeshLink> value,std::uint16_t limit):link(std::move(value)),mtu(limit) {}
        };
    }

    auto Server::add_mesh(std::shared_ptr<MeshLink> link, std::uint16_t mtu) -> std::expected<std::size_t,std::string> {
        if(!link || mtu<1280 || mtu>1500 || outbounds.size()>=16 || running)
            return std::unexpected("invalid Tailscale outbound or routing state");
        auto profile=std::make_shared<MeshProfile>(std::move(link),mtu);
        TunnelFactory factory{
            [profile](Session& session,io::io_context& context,bool relay,TcpSocketOptions const*) -> pro::proxy<TunnelFacade> {
                std::lock_guard lock(profile->mutex);
                auto& host=profile->hosts[&context];
                if(!host)host=std::make_shared<MeshHost>(profile->link,context,profile->mtu);
                return pro::make_proxy<TunnelFacade,L3Tunnel<MeshHost>>(session,host,10000,relay);
            },
            10000
        };
        factory.stop_context=[profile](io::io_context& context) noexcept {
            std::lock_guard lock(profile->mutex);
            if(auto found=profile->hosts.find(&context);found!=profile->hosts.end())found->second->stop();
        };
        factory.quiesced_context=[profile](io::io_context& context) noexcept {
            std::lock_guard lock(profile->mutex);
            auto found=profile->hosts.find(&context);
            return found==profile->hosts.end() || !found->second->active;
        };
        factory.finish_context=[profile](io::io_context& context) noexcept {
            std::lock_guard lock(profile->mutex);
            profile->hosts.erase(&context);
        };
        auto index=outbounds.size()+2;
        outbounds.push_back(std::move(factory));
        return index;
    }
}
