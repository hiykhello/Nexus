module dns.quic_query;
import std;
import crypto;
import dns.corosio_query;
import dns.input_budget;
import net.datagram_driver;
import net.udp_connect;
import platform.socket_options;
import quic.cid_registry;
import quic.connection;
import quic.datagram_port;
import quic.datagram_session;
import quic.transport_memory;
import tls.fingerprint;
import tls.profiles;
import nexus.thirdparty.capy;
import nexus.thirdparty.corosio;
import nexus.thirdparty.ngtcp2;
import quic.resumption;


namespace dns::doq_detail {
    constexpr bool supports_early_data=true;
    class TransportTicket : public tls::ResumptionTicket {
        std::inplace_vector<std::uint8_t,256> parameters_;
        std::uint16_t suite_;

        TransportTicket(tls::ResumptionTicket&& ticket,std::uint16_t suite,std::span<std::uint8_t const> parameters)
            : tls::ResumptionTicket(std::move(ticket)), suite_(suite) {
            if (parameters.size()<=parameters_.capacity())
                parameters_.append_range(parameters);
        }

    public:
        template<bool Quic>
        [[nodiscard]] static auto from_message(std::span<std::uint8_t const> body,crypto::Hash hash,
            std::span<std::uint8_t const> master,tls::TicketBinding const& binding,std::uint64_t now,
            std::uint16_t suite,std::span<std::uint8_t const> parameters) -> std::expected<TransportTicket,tls::PskError> {
            static_assert(Quic);
            auto ticket=tls::ResumptionTicket::from_message<Quic>(body,hash,master,binding,now);
            if (!ticket) return std::unexpected(ticket.error());
            return TransportTicket(std::move(*ticket),suite,parameters);
        }
        [[nodiscard]] auto parameters() const noexcept -> std::span<std::uint8_t const> { return parameters_; }
        [[nodiscard]] auto suite() const noexcept -> std::uint16_t { return suite_; }
    };

    using Cache = tls::ResumptionCache<8,TransportTicket>;
    using Tls = quic::ResumingTlsClient<Cache, tls::PskSteadyClock>;
    // A connection may still be draining when the context service stops.
    using TicketCache = std::shared_ptr<Cache>;

    auto make_ticket_cache() -> TicketCache {
        return std::make_shared<Cache>();
    }

    class Profile {
        std::array<std::uint8_t, 16> generation_;
        std::vector<std::span<std::uint8_t const>> anchors_;

    public:
        tls::ClientProfile tls;
        platform::SocketBinding binding;
        std::chrono::milliseconds connect_timeout;
        QuicDnsDatagramFactory datagram;
        bool early_data;

        Profile(tls::ClientProfile identity, platform::SocketBinding socket, std::chrono::milliseconds timeout,
            std::array<std::uint8_t, 16> generation,bool early,QuicDnsDatagramFactory route)
            : generation_(generation), tls(std::move(identity)), binding(std::move(socket)), connect_timeout(timeout), datagram(std::move(route)), early_data(early) {
            anchors_.reserve(tls.anchors.size());
            for (auto const& certificate : tls.anchors) anchors_.emplace_back(certificate);
        }
        Profile(Profile const&) = delete;
        auto operator=(Profile const&) -> Profile& = delete;

        auto anchors(this Profile const& self) noexcept -> std::span<std::span<std::uint8_t const> const> {
            return self.anchors_;
        }

        auto scope(this Profile const& self, nex::corosio::endpoint const& peer) noexcept
            -> std::array<std::uint8_t, 39> {
            // Generation, address family, port, 16 address bytes and the IPv6 zone.
            std::array<std::uint8_t, 39> scope{};
            std::ranges::copy(self.generation_, scope.begin());
            auto address = peer.address();
            scope[16] = address.is_v4() ? 4 : 6;
            scope[17] = static_cast<std::uint8_t>(peer.port() >> 8);
            scope[18] = static_cast<std::uint8_t>(peer.port());
            if (address.is_v4()) {
                std::ranges::copy(address.to_v4().to_bytes(), scope.begin() + 19);
            } else {
                auto ip = address.to_v6();
                std::ranges::copy(ip.to_bytes(), scope.begin() + 19);
                for (std::size_t i = 0; i < 4; ++i)
                    scope[35 + i] = static_cast<std::uint8_t>(ip.scope_id() >> (8 * (3 - i)));
            }
            return scope;
        }
    };

    auto make_profile(tls::ClientProfile identity, platform::SocketBinding socket, std::chrono::milliseconds timeout,
        bool early_data,QuicDnsDatagramFactory datagram)
        -> std::expected<std::shared_ptr<Profile const>, std::string> {
        std::array<std::uint8_t, 16> generation{};
        if (!crypto::random_bytes(generation)) return std::unexpected("cannot initialize DoQ ticket scope");
        return std::make_shared<Profile const>(std::move(identity), std::move(socket), timeout, generation, early_data,std::move(datagram));
    }

    auto initialize_tls(std::optional<Tls>& session, tls::FingerprintHello hello, Profile const& profile,
        nex::corosio::endpoint const& peer, TicketCache const& tickets,bool replayable) -> bool {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        auto const& server = profile.tls.server_name;
        auto name = std::span(reinterpret_cast<std::uint8_t const*>(server.data()), server.size());
        auto setup = quic::ClientResumptionSetup<Cache>::create(std::move(hello.hello), hello.initial_groups(),
            profile.anchors(), tls::PeerNameKind::dns, name, now, "doq", *tickets, profile.scope(peer),profile.early_data && replayable);
        if (!setup) return false;
        session.emplace(std::move(*setup));
        return true;
    }
}

#include "quic_query_runtime.hpp"
