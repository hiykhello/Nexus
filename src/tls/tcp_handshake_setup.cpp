module tls.client_handshake_io;
import std;
import containers.inplace_vector;
import tls.psk_client_policy;
import tls.server_hello;

namespace tls {
    namespace {
        struct TcpTickets {
            std::mutex mutex;
            ResumptionCache<32> cache;
        };

        auto tickets() -> TcpTickets& {
            static TcpTickets store;
            return store;
        }

        auto offers_legacy(ClientHello const& hello) noexcept -> bool {
            auto* versions=hello.extension(43);
            if (!versions) return false;
            for (std::size_t i=1;i+1<versions->data.size();i+=2)
                if (versions->data[i]==3 && versions->data[i+1]==3) return true;
            return false;
        }
    }

    auto cache_ticket(ResumptionReceiver& receiver,std::span<std::uint8_t const> body) -> std::expected<void,RecordError> {
        auto& store=tickets();
        std::lock_guard lock(store.mutex);
        auto result=receiver.ticket(body,store.cache,PskSteadyClock::now());
        if (!result) return std::unexpected(result.error()==PskError::crypto_error ? RecordError::crypto_error : RecordError::invalid_record);
        return {};
    }

    auto ClientHandshakeIo::create(ClientHello hello,std::span<std::uint16_t const> groups,
        std::span<crypto::Bytes const> anchors,PeerNameKind kind,std::span<std::uint8_t const> peer_name,
        std::int64_t verification_time,std::uint64_t now,std::uint64_t deadline,std::span<std::uint8_t const> target,std::span<std::array<std::uint8_t,32> const> pins,quic::EchConfig const* ech)
        -> std::expected<ClientHandshakeIo,ClientHandshakeIoError> {
        using Error=ClientHandshakeIoError;
        std::vector<std::span<std::uint8_t const>> trust;
        trust.reserve(anchors.size());
        for (auto const& anchor:anchors) trust.emplace_back(anchor);
        auto legacy=offers_legacy(hello);
        if (ech && (legacy || kind!=PeerNameKind::dns)) return std::unexpected(Error::invalid_argument);
        std::unique_ptr<PskClientPolicy<>> recovery;
        if (!ech && !target.empty() && pins.empty()) {
            crypto::Bytes scope{target.begin(),target.end()};
            if (auto* alpn=hello.extension(16)) scope.append_range(alpn->data);
            auto binding=make_ticket_binding(hello,trust,kind,peer_name,{},scope);
            if (!binding) return std::unexpected(Error::invalid_argument);
            containers::inplace_vector<ResumptionTicket,8> offers;
            {
                auto& store=tickets();
                std::lock_guard lock(store.mutex);
                auto instant=PskSteadyClock::now();
                auto take=[&](std::span<std::uint8_t const> protocol) {
                    binding->alpn.assign(protocol.begin(),protocol.end());
                    if (auto ticket=store.cache.take(*binding,hello.cipher_suites,instant)) offers.push_back(std::move(*ticket));
                };
                if (auto* alpn=hello.extension(16)) {
                    auto protocols=std::span(alpn->data);
                    for (std::size_t i=2;i<protocols.size() && offers.empty();) {
                        auto size=protocols[i++];
                        if (!size || size>protocols.size()-i) return std::unexpected(Error::invalid_argument);
                        take(protocols.subspan(i,size));
                        i+=size;
                    }
                    if (offers.empty()) take({});
                } else take({});
            }
            auto policy=PskClientPolicy<>::create(std::move(*binding),std::move(offers));
            if (!policy) return std::unexpected(Error::invalid_argument);
            recovery=std::make_unique<PskClientPolicy<>>(std::move(*policy));
        }
        auto session=ech ? ClientSessionHandshake::create_ech(std::move(hello),groups,trust,kind,peer_name,verification_time,*ech) :
            recovery ? ClientSessionHandshake::create(std::move(hello),groups,trust,kind,peer_name,verification_time,*recovery) :
            ClientSessionHandshake::create(std::move(hello),groups,trust,kind,peer_name,verification_time);
        if (!session) return std::unexpected(session.error()==ClientSessionHandshakeError::crypto_error ? Error::crypto_error : Error::invalid_argument);
        session->set_certificate_pins(pins);
        auto adapter=create(std::move(*session),now,deadline);
        if (!adapter) return std::unexpected(adapter.error());
        adapter->recovery_=std::move(recovery);
        if (legacy) {
            auto wire=adapter->pending_output();
            if (wire.size()<9) return std::unexpected(Error::invalid_argument);
            auto sent=ClientHello::parse(wire.subspan(9));
            if (!sent) return std::unexpected(Error::invalid_argument);
            auto fallback=Tls12Client::from_offer(std::move(*sent),{anchors.begin(),anchors.end()},
                {peer_name.begin(),peer_name.end()},kind,verification_time);
            if (!fallback) return std::unexpected(Error::invalid_argument);
            fallback->set_certificate_pins(pins);
            adapter->legacy_=std::make_unique<Tls12Client>(std::move(*fallback));
            adapter->probe_=std::make_unique<VersionProbe>();
        }
        return adapter;
    }

    auto ClientHandshakeIo::feed_probe(std::span<std::uint8_t const> input)
        -> std::expected<ClientHandshakeIoFeed,ClientHandshakeIoError> {
        using Error=ClientHandshakeIoError;
        auto& probe=*probe_;
        auto frame=probe.records.feed(input,RecordFraming::plaintext);
        if (!frame || frame->consumed>98304-probe.prefix.size()) return fail(Error::protocol_error);
        probe.prefix.append_range(input.first(frame->consumed));
        if (!frame->record) return ClientHandshakeIoFeed{frame->consumed};
        auto const& record=frame->record->bytes;
        if (record[0]!=22 || record.size()==5) return fail(Error::protocol_error);
        probe.body.append_range(std::span(record).subspan(5));
        auto wire=std::span(probe.body);
        if (wire[0]!=2) return fail(Error::protocol_error);
        if (wire.size()<4) return ClientHandshakeIoFeed{frame->consumed};
        auto size=(std::size_t{wire[1]}<<16)|(std::size_t{wire[2]}<<8)|wire[3];
        if (size>65535) return fail(Error::protocol_error);
        if (wire.size()<4+size) return ClientHandshakeIoFeed{frame->consumed};
        auto first=ServerHello::parse(wire.subspan(4,size));
        if (!first) return fail(Error::protocol_error);
        auto selected=std::ranges::find(first->extensions,std::uint16_t{43},&Extension::type);
        if (selected==first->extensions.end() && !first->is_retry()) {
            handshake_.reset();
            recovery_.reset();
        } else legacy_.reset();
        auto prefix=std::move(probe.prefix);
        probe_.reset();
        auto bytes=std::span<std::uint8_t const>(prefix);
        while (!bytes.empty()) {
            auto result=feed_selected(bytes);
            if (!result) return result;
            if (!result->consumed) return fail(Error::protocol_error);
            bytes=bytes.subspan(result->consumed);
        }
        return ClientHandshakeIoFeed{frame->consumed};
    }
}
