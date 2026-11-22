module;
#include <boost/capy/ex/run.hpp>
#include <boost/corosio/socket_option.hpp>

module proxy;
import std;
import proxy.v4;
import crypto;
import http.connect;
import http.header;
import http2.driver;
import http2.server_streams;
import http2.client_types;
import http2.headers;
import hysteria2.transport_options;
import masque.session;
import quic.cid_registry;
import quic.datagram_port;
import quic.datagram_session;
import quic.native_memory;
import quic.retry_admission;
import quic.retry_token;
import quic.tls_server;
import net.datagram_driver;
import tls.profiles;
import tls.server_credential;
import nexus.thirdparty.nghttp3;
import nexus.thirdparty.ngtcp2;
import memory.budget;
import net.socket_stream;
import reality.server_profile;
import reality.server_probe;
import reality.fallback;
import rules;
import socks5;
import tls.byte_stream;
import tls.corosio_application;
import tls.corosio_server_handshake;
import vless;
import vless.server_profile;
import vless.tls_server;
import xhttp.client;
import xhttp.config;
import xhttp.server;
import xhttp.wire;
import proxy.stream_relay;
import proxy.vless_mux;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;

#include "xhttp_http1.hpp"
#include "reality_tcp_server.hpp"
#include "xhttp_http3_streams.hpp"
#include "xhttp_http3_channel.hpp"

namespace proxy {
    namespace vless_xhttp {
        struct Split {
            nex::capy::async_event change,paired,space;
            xhttp::Pairing sides;
            xhttp::Reassembly input;
            std::uint64_t sequence=0;
            bool upload_end=false;
            Split(xhttp::Limits limits,std::shared_ptr<memory::Budget> const& budget)
                :sides{Clock::now()+limits.pair_timeout},input(limits,budget) {}
        };

        struct InboundProfile {
            vless::ServerProfile vless;
            xhttp::Profile transport;
            std::vector<std::string> names;
            std::shared_ptr<memory::Budget> budget;
            std::unordered_map<std::string,std::shared_ptr<Split>> sessions;
            bool secure;
            std::optional<RealityTcpProfile> reality;
            std::size_t streaming=0;
            auto find(std::string const& key) -> std::pair<std::shared_ptr<Split>,bool> {
                if (auto item=sessions.find(key);item!=sessions.end()) return {item->second,false};
                if (sessions.size()+streaming>=transport.limits.sessions) return {};
                auto session=std::make_shared<Split>(transport.limits,budget);
                sessions.emplace(key,session);
                return {std::move(session),true};
            }
            auto retire(std::string const& key,std::shared_ptr<Split> const& split,bool unpaired_only) noexcept -> void {
                if (unpaired_only && split->sides.download) return;
                split->sides.closed=true;
                split->input.close();
                split->change.set();split->paired.set();split->space.set();
                auto entry=sessions.find(key);
                if (entry!=sessions.end() && entry->second==split) sessions.erase(entry);
            }
        };

        struct SplitOwner {
            InboundProfile& profile;
            std::string const& id;
            std::shared_ptr<Split> const& split;
            bool active,orphan=false;
            ~SplitOwner() {if (active) profile.retire(id,split,orphan);}
        };

        auto read_split(Split& split,std::span<std::uint8_t> output,Deadline until)
            -> nex::capy::task<std::expected<std::size_t,IoError>> {
            while (!output.empty()) {
                if (split.sides.closed) co_return std::unexpected(IoError::io);
                if (auto size=split.input.read(output)) {
                    split.space.set();
                    co_return size;
                }
                if (split.upload_end) co_return 0;
                auto deadline=until.value_or(Clock::now()+std::chrono::minutes(5));
                if (!split.sides.paired()) deadline=std::min(deadline,split.sides.deadline);
                if (Clock::now()>=deadline) co_return std::unexpected(IoError::timeout);
                split.change.clear();
                auto [error]=co_await nex::corosio::timeout(split.change.wait(),deadline);
                if (error) co_return std::unexpected(IoError::io);
            }
            co_return 0;
        }

        class DownloadStream {
            Lower& lower_;
            Split& split_;
        public:
            DownloadStream(Lower& lower,Split& split) noexcept :lower_(lower),split_(split) {}
            auto cancel() noexcept -> void {lower_.cancel();}
            auto packet_up() const noexcept -> bool {return true;}
            auto read(std::span<std::uint8_t> output,Deadline until={}) {return read_split(split_,output,until);}
            auto send(std::span<std::uint8_t const> input,Deadline until={}) -> nex::capy::task<bool> {
                if (input.empty()) co_return true;
                std::array<char,2*sizeof(std::size_t)+2> head;
                auto [end,error]=std::to_chars(head.data(),head.data()+head.size()-2,input.size(),16);
                if (error!=std::errc{}) co_return false;
                *end++='\r';*end++='\n';
                co_return co_await lower_.send(bytes(std::string_view(head.data(),end)),until) &&
                    co_await lower_.send(input,until) && co_await lower_.send(bytes("\r\n"),until);
            }
            auto close_output(Deadline until={}) -> nex::capy::task<bool> {
                co_return co_await lower_.send(bytes("0\r\n\r\n"),until) && co_await lower_.close_output(until);
            }
        };

#include "xhttp_vless_payload.hpp"

        auto watch_download(Session& session,Lower& lower) -> nex::capy::task<nex::capy::results<>> {
            std::array<std::uint8_t,1> buffer;
            (void)co_await lower.read(buffer);
            session.close();
            co_return nex::capy::results<>{std::make_error_code(std::errc::operation_canceled)};
        }

        auto response_head(InboundProfile const& profile,std::string_view status,bool stream,bool close) -> std::optional<std::string> {
            auto random=entropy();
            if (!random) return {};
            std::string head="HTTP/1.1 ";head+=status;
            head+="\r\nX-Padding: ";head+=xhttp::padding_bytes(profile.transport.padding,*random);
            if (stream) head+="\r\nTransfer-Encoding: chunked\r\nX-Accel-Buffering: no\r\nCache-Control: no-store";
            else head+="\r\nContent-Length: 0";
            if (close) head+="\r\nConnection: close";
            head+="\r\n\r\n";
            return head;
        }

        auto read_request(Lower& lower,std::string& input,Clock::time_point deadline)
            -> nex::capy::task<std::optional<RequestHead>> {
            std::array<std::uint8_t,4096> block;
            for (;;) {
                auto head=http::inspect_header(input);
                if (head.status==http::HeaderStatus::complete) co_return parse_request(head);
                if (head.status!=http::HeaderStatus::incomplete) co_return std::nullopt;
                auto size=co_await lower.read(block,deadline);
                if (!size || !*size) co_return std::nullopt;
                input.append(reinterpret_cast<char const*>(block.data()),*size);
            }
        }

#include "xhttp_http1_ingress.hpp"
#include "xhttp_http2_server.hpp"
#include "xhttp_http3_server.hpp"

        auto serve(Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy,
            InboundProfile& profile) -> nex::capy::task<> {
            struct Done {
                Session& session;
                ~Done(){session.close();session.done=true;}
            } done{session};
            if (session.ordered_tcp) co_return;
            std::optional<tls::detail::ApplicationConnection<Socket>> connection;
            Lower lower(session.client);
            if (profile.secure) {
                auto limit=session.started+std::chrono::seconds(10);
                auto ms=[](Clock::time_point when) {return std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();};
                auto budget=std::make_shared<memory::Budget>(8*1024*1024);
                auto protocol=profile.transport.endpoint.version==xhttp::HttpVersion::http2 ? "h2" : "";
                auto establish=[&]() -> nex::capy::task<std::optional<tls::detail::ServerAsyncResult>> {
                    if (profile.reality)
                        co_return co_await reality_tcp::establish(session,context,*profile.reality,budget,ms(session.started),ms(limit),protocol);
                    auto handshake=profile.vless.tls_handshake(ms(session.started),ms(limit),budget,protocol);
                    if (!handshake) co_return std::nullopt;
                    auto accepted=co_await tls::detail::server_handshake(session.client,*handshake,budget);
                    if (!accepted) co_return std::nullopt;
                    co_return std::move(*accepted);
                };
                auto accepted=co_await establish();
                if (!accepted || session.closed) co_return;
                connection.emplace(session.client,std::move(accepted->records),std::move(accepted->unread));
                if (!accepted->release_unread_reservation()) co_return;
                lower.attach(*connection);
            }
            if (profile.transport.endpoint.version==xhttp::HttpVersion::http1) {
                co_await process(session,context,policy,profile,lower);
                co_return;
            }
            http2::ClientLimits limits;
            limits.header_bytes=http::max_header_bytes;
            auto native=H2Session::create(limits);
            if (!native) co_return;
            H2Driver driver(lower,std::move(*native));
            RelaySlots slots;
            session.relaying=true;
            auto run=[&]() -> nex::capy::task<nex::capy::results<>> {
                auto result=co_await driver.run();
                session.close();
                co_return result;
            };
            std::vector<nex::capy::task<nex::capy::results<>>> workers;
            workers.reserve(17);
            workers.push_back(run());
            for (unsigned i=0;i<16;++i) workers.push_back(h2_worker(session,context,policy,profile,driver,slots));
            try {(void)co_await nex::capy::when_all(std::move(workers));}
            catch (...) {driver.cancel();}
        }
    }

    static auto load_xhttp_inbound(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport,std::optional<RealityInbound> reality)
        -> std::expected<std::unique_ptr<vless_xhttp::InboundProfile>,std::string> {
        using namespace vless_xhttp;
        if (!transport.limits.valid() || !xhttp::valid_padding(transport.padding) || transport.download)
            return std::unexpected("invalid VLESS XHTTP inbound options");
        if (transport.endpoint.version==xhttp::HttpVersion::http1 &&
            transport.mode!=xhttp::Mode::automatic && transport.mode!=xhttp::Mode::packet_up)
            return std::unexpected("VLESS XHTTP HTTP/1.1 requires packet-up");
        if (!names.empty() && names.size()!=users.size()) return std::unexpected("VLESS user names do not match UUIDs");
        for (std::size_t i=0;i<names.size();++i)
            if (names[i].empty() || names[i].size()>255 || names[i].contains('\0') ||
                std::find(names.begin(),names.begin()+i,names[i])!=names.begin()+i)
                return std::unexpected("invalid or duplicate VLESS user name");
        auto secure=reality || !certificate.empty();
        auto pki_tcp=secure && !reality && transport.endpoint.version!=xhttp::HttpVersion::http3;
        auto auth=pki_tcp ? vless::ServerProfile::load(certificate,key,users) : vless::ServerProfile::load_users(users);
        if (!auth) return std::unexpected(auth.error());
        auto budget=std::make_shared<memory::Budget>(transport.limits.buffer_bytes+128u*transport.limits.buffered_posts);
        auto profile=std::unique_ptr<InboundProfile>(new InboundProfile{std::move(*auth),std::move(transport),
            {names.begin(),names.end()},std::move(budget),{},secure,{}});
        if (reality) {
            auto authenticated=RealityTcpProfile::load(std::move(*reality));
            if (!authenticated) return std::unexpected(authenticated.error());
            profile->reality.emplace(std::move(*authenticated));
        }
        return profile;
    }

    auto make_vless_xhttp_inbound_factory(std::string_view certificate,std::string_view key,std::span<std::string const> users,
        std::span<std::string const> names,xhttp::Profile transport,std::optional<RealityInbound> reality)
        -> std::expected<InboundFactory,std::string> {
        auto profile=load_xhttp_inbound(certificate,key,users,names,std::move(transport),std::move(reality));
        if (!profile) return std::unexpected(profile.error());
        return InboundFactory{[profile=std::move(*profile)](Session& session,nex::corosio::io_context& context,rules::RouteMatcher const& policy) {
            return vless_xhttp::serve(session,context,policy,*profile);
        }};
    }

#include "xhttp_http3_listener.hpp"

#include "xhttp_http3_entry.hpp"
}
