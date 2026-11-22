export module quic.datagram_session;
import std;
import net.datagram_driver;
import quic.connection;
import quic.endpoint_path;
import quic.pmtud_native;
import nexus.thirdparty.ngtcp2;
import nexus.thirdparty.corosio;

export namespace quic {
    // This owner supplies synchronous native/path/token policy. The shared
    // port and the standalone endpoint both use the sole generic UDP driver.
    // The application and its concrete TLS handler outlive this owner.
    template<class Tls,class Application> class DatagramSession {
    public:
        using Failure=int;
        using Transport=Connection<Tls,Application>;
    private:
        Application& application_;
        nex::corosio::endpoint const& local_;
        Transport transport_;
        std::uint64_t token_=0,pending_=0;
        bool stopped_=false,shaping_=true,pmtud_=true,mtu_fallback_=false;
        std::size_t pending_path_limit_=0,recovery_goal_=0;
        net::DatagramDeadline reprobe_;
        static constexpr auto reprobe_interval=std::chrono::minutes(10);
        static auto time(net::DatagramClock::time_point point) noexcept -> std::uint64_t {return std::chrono::duration_cast<std::chrono::nanoseconds>(point.time_since_epoch()).count();}
    public:
        DatagramSession(Tls& tls,Application& application,nex::corosio::endpoint const& local) noexcept:application_(application),local_(local),transport_(tls,application){application.attach(transport_);}
        DatagramSession(DatagramSession const&)=delete;
        auto operator=(DatagramSession const&) -> DatagramSession& = delete;
        ~DatagramSession(){stop();drain();}
        auto transport() noexcept -> Transport& {return transport_;}
        auto start(bool server,nex::ngtcp2::ngtcp2_cid const& destination,nex::ngtcp2::ngtcp2_cid const& source,nex::corosio::endpoint const& peer,nex::ngtcp2::ngtcp2_settings settings,nex::ngtcp2::ngtcp2_transport_params const& parameters,nex::ngtcp2::ngtcp2_mem const& memory,net::DatagramClock::time_point now) -> int {
            EndpointPath path(local_,peer);settings.initial_ts=time(now);shaping_=!settings.no_tx_udp_payload_size_shaping;pmtud_=!settings.no_pmtud;
            return transport_.start(server,destination,source,path.native(),settings,parameters,memory);
        }
        auto request_stop() noexcept -> void {stopped_=true;application_.request_stop();}
        auto stopping() const noexcept -> bool {return stopped_ || application_.stopping();}
        // Call only after native callbacks, borrowed packets and business roots
        // have drained. The port enforces this for all of its concrete owners.
        auto stop() noexcept -> void {application_.joined();transport_.stop();pending_=0;}
        auto drain() noexcept -> void {application_.drain();}
        auto next_expiry() const noexcept -> net::DatagramDeadline {
            if(stopping())return {};
            net::DatagramDeadline result=reprobe_;
            auto next=transport_.expiry();
            if(next && *next!=std::numeric_limits<std::uint64_t>::max()) {
                auto native=net::DatagramClock::time_point(std::chrono::nanoseconds(*next));
                if(!result || native<*result)result=native;
            }
            return result;
        }
        auto receive(nex::corosio::endpoint const& peer,std::span<std::uint8_t const> bytes,net::DatagramClock::time_point now) -> std::expected<void,int> {
            if(stopping())return {};
            EndpointPath path(local_,peer);application_.time(time(now));auto error=transport_.read(path.native(),nullptr,bytes,time(now));
            if(error==nex::ngtcp2::err_draining){request_stop();return {};}
            if(error)return std::unexpected(error);return {};
        }
        auto expire(net::DatagramClock::time_point now) -> std::expected<void,int> {
            if(stopping())return {};
            auto error=transport_.expire(time(now));if(error)return std::unexpected(error);
            if(reprobe_ && now>=*reprobe_) {
                if(nex::ngtcp2::ngtcp2_conn_get_path_max_tx_udp_payload_size2(transport_.native())>=recovery_goal_) {
                    reprobe_.reset();recovery_goal_=0;
                } else {
                    error=nexus_ngtcp2_restart_pmtud(transport_.native(),0);
                    if(error)return std::unexpected(error);
                    reprobe_=now+reprobe_interval;
                }
            }
            return {};
        }
        auto output(std::span<std::uint8_t> bytes,net::DatagramClock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,int> {
            namespace n=nex::ngtcp2;
            if(stopping())return std::optional<net::DatagramOutput>{};
            if(pending_ || token_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(n::err_invalid_argument);
            if constexpr(requires {application_.take_congestion();}) {
                if(auto selected=application_.take_congestion();selected && selected->first) {
                    auto code=nexus_ngtcp2_set_brutal(transport_.native(),selected->first,selected->second,time(now));
                    if(code)return std::unexpected(code);
                }
            }
            // Native selects the authenticated path; incoming source addresses
            // neither select a session nor silently replace its output peer.
            n::ngtcp2_path_storage path{};n::ngtcp2_path_storage_zero(&path);
            auto path_limit=n::ngtcp2_conn_get_path_max_tx_udp_payload_size2(transport_.native());
            if(mtu_fallback_)bytes=bytes.first(std::min<std::size_t>(bytes.size(),1200));
            auto result=application_.output(bytes,time(now),&path.path);if(!result)return std::unexpected(result.error());
            if(!*result)return std::optional<net::DatagramOutput>{};
            auto peer=EndpointPath::endpoint(path.path.remote);if(!peer)return std::unexpected(n::err_invalid_argument);
            pending_path_limit_=path_limit;pending_=++token_;return net::DatagramOutput{*peer,*result,pending_,shaping_ && *result>path_limit,shaping_ && *result>1200};
        }
        // Called only at the port's quiescent output boundary. One close
        // packet is pinned through actual socket completion like ordinary output.
        auto close_output(std::span<std::uint8_t> bytes,net::DatagramClock::time_point now) -> std::expected<std::optional<net::DatagramOutput>,int> {
            namespace n=nex::ngtcp2;
            if(pending_ || token_==std::numeric_limits<std::uint64_t>::max())return std::unexpected(n::err_invalid_argument);
            n::ngtcp2_path_storage path{};n::ngtcp2_path_storage_zero(&path);
            n::ngtcp2_ccerr error{};n::ngtcp2_ccerr_default(&error);
            if constexpr (requires {application_.close_error(error);}) application_.close_error(error);
            auto result=transport_.write_close(bytes,&path.path,nullptr,error,time(now));
            if(!result)return std::unexpected(result.error());
            if(!*result)return std::optional<net::DatagramOutput>{};
            auto peer=EndpointPath::endpoint(path.path.remote);if(!peer)return std::unexpected(n::err_invalid_argument);
            pending_=++token_;return net::DatagramOutput{*peer,*result,pending_};
        }
        auto transmitted(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,int> {
            if(!pending_ || token!=pending_ || !transport_.native())return std::unexpected(nex::ngtcp2::err_invalid_argument);
            pending_=0;nex::ngtcp2::ngtcp2_conn_update_pkt_tx_time(transport_.native(),time(now));return {};
        }
        // ngtcp2 has already registered this packet. Treat it as lost and
        // lower the native path limit so loss recovery emits smaller packets.
        // Native probes are independent of stream and DATAGRAM payloads.
        // DATAGRAM frames in the rejected packet remain unreliable.
        auto mtu_rejected(std::uint64_t token,net::DatagramClock::time_point now) -> std::expected<void,int> {
            if(!pending_ || token!=pending_ || !transport_.native() || !shaping_)return std::unexpected(nex::ngtcp2::err_invalid_argument);
            auto previous_limit=pending_path_limit_;
            auto result=transmitted(token,now);if(!result)return result;
            if(!pmtud_) {mtu_fallback_=true;return {};}
            auto error=nexus_ngtcp2_restart_pmtud(transport_.native(),1);
            if(error)return std::unexpected(error);
            recovery_goal_=std::max(recovery_goal_,previous_limit);
            reprobe_=now+reprobe_interval;return {};
        }
    };
}
