export module test.hy2_retry_port_link;
import std;
import crypto;
import net.datagram_driver;
import quic.datagram_port;
import quic.cid_registry;
import quic.retry_admission;
import quic.retry_token;
import tls.server_credential;
import ngtcp2;
import corosio;
import test.quic_tls_link;
import test.hy2_port_link;
export namespace test::hy2_retry_port {
namespace base=test::hy2_port;namespace q=quic;namespace n = ::ngtcp2;namespace io = ::corosio;namespace support=test::quic_tls;
using Clock=std::chrono::steady_clock;
using Registry=base::Registry;using Session=base::Session;using Bundle=base::Bundle;using BusinessRoot=base::BusinessRoot;
struct Factory:base::Factory {
    using Session=base::Session;
    using ControlFailure=q::RetryFailure;
    q::RetryAdmission<8,8,crypto::random_bytes,true> retry;
    std::optional<q::RetryClaims> permit;
    std::optional<ControlFailure> admission_error;
    Factory(tls::ServerCredential const& credential,io::endpoint const& local) noexcept:base::Factory(credential,local){auto result=retry.initialize();if(!result)admission_error=result.error();}
    auto admit(n::ngtcp2_pkt_hd const& initial,io::endpoint const& peer,Clock::time_point now,std::size_t received) noexcept -> bool {
        permit.reset();auto result=retry.inspect(initial,peer,now,received);
        if(!result){if(!admission_error)admission_error=result.error();return false;}permit=*result;return permit.has_value();
    }
    auto control_failure() const noexcept {return admission_error;}
    auto control_output(std::span<std::uint8_t> bytes,Clock::time_point now) noexcept -> std::expected<std::optional<net::DatagramOutput>,ControlFailure> {
        if(admission_error)return std::unexpected(*admission_error);return retry.output(bytes,now);
    }
    auto control_transmitted(std::uint64_t token,Clock::time_point now) noexcept {return retry.transmitted(token,now);}
    auto control_next_expiry() const noexcept {return retry.next_expiry();}
    auto control_expire(Clock::time_point now) noexcept {return retry.expire(now);}
    auto control_request_stop() noexcept -> void {retry.request_stop();}
    auto control_stop() noexcept -> void {permit.reset();retry.stop();}
    auto control_drained() const noexcept -> bool {return retry.drained();}
    auto create(q::SessionHandle owner,Registry& registry,std::span<std::uint8_t const> source,n::ngtcp2_pkt_hd const& initial,io::endpoint const& peer,Clock::time_point now) noexcept -> std::expected<Session*,int> {
        try {
            if(!permit || !std::ranges::equal(permit->retry.bytes(),std::span(initial.dcid.data).first(initial.dcid.datalen)))return std::unexpected(n::err_callback_failure);
            auto verified=*permit;permit.reset();
            auto& bundle=bundles[owner.slot];if(bundle)return std::unexpected(n::err_callback_failure);
            bundle.emplace(credential,registry,owner,work,local);auto parameters=support::parameters(true);
            n::ngtcp2_cid_init(&parameters.original_dcid,verified.original.data.data(),verified.original.size);parameters.original_dcid_present=1;parameters.retry_scid=initial.dcid;parameters.retry_scid_present=1;
            parameters.initial_max_stream_data_bidi_local=parameters.initial_max_stream_data_bidi_remote=16384;parameters.initial_max_streams_bidi=4;parameters.active_connection_id_limit=4;
            n::ngtcp2_cid cid{};n::ngtcp2_cid_init(&cid,source.data(),source.size());
            auto settings=support::settings();settings.token=initial.token;settings.tokenlen=initial.tokenlen;settings.token_type=n::NGTCP2_TOKEN_TYPE_RETRY;
            auto error=bundle->session.start(true,initial.scid,cid,peer,settings,parameters,bundle->memory.transport(),now);
            if(error){bundle->session.request_stop();bundle->session.stop();bundle->session.drain();valid&=bundle->app.clean() && !bundle->memory.used && !bundle->h3memory.used && !bundle->session.transport().key_slots();bundle.reset();return std::unexpected(error);}
            ++created;work.set();return &bundle->session;
        }catch(...){bundles[owner.slot].reset();return std::unexpected(n::err_nomem);}
    }
};
using Port=q::DatagramPort<Factory,4,8>;using Driver=net::DatagramDriver<Port>;
}
