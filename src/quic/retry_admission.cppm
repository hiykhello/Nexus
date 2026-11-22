export module quic.retry_admission;
import std;
import crypto;
import net.datagram_driver;
import quic.retry_token;
import quic.retry_packet;
import nexus.thirdparty.corosio;
import nexus.thirdparty.ngtcp2;

export namespace quic {
    struct RetryFailure {
        enum class Stage { token,packet,entropy,state } stage=Stage::state;
        RetryTokenError token=RetryTokenError::state;
        int native=0;
    };
    struct RetryStatistics {std::uint64_t queued=0,committed=0,expired=0,throttled=0,invalid=0,validated=0;};
    template<bool Enabled>struct RetryStatisticsStorage {};
    template<>struct RetryStatisticsStorage<true> {RetryStatistics value;};
    // Stateless address validation owns no native connection. Its bounded
    // queue retains only Initial identities. Packet crypto/serialization writes
    // directly into the sole generic driver's output buffer when selected.
    template<std::size_t Capacity=8,std::size_t RetryCidBytes=8,auto Entropy=crypto::random_bytes,bool TrackStatistics=false>
    class RetryAdmission {
        static_assert(Capacity && Capacity<=1024 && RetryCidBytes>=8 && RetryCidBytes<=20);
        struct Entry {
            RetryCid original,destination;
            nex::corosio::endpoint peer;
            net::DatagramClock::time_point expires;
            std::uint64_t token;
        };
        RetryTokenAuthority<Entropy> authority_;
        RetryPacketWriter writer_;
        std::array<std::optional<Entry>,Capacity> entries_;
        std::optional<std::size_t> sealed_;
        std::uint64_t next_token_=1;
        net::DatagramClock::time_point refill_{};
        std::size_t quota_=Capacity;
        bool initialized_=false,rate_started_=false,stopped_=false,joined_=false;
        [[no_unique_address]] RetryStatisticsStorage<TrackStatistics> statistics_;
        static auto failure(RetryTokenError error) noexcept -> RetryFailure {return {RetryFailure::Stage::token,error,0};}
        auto refill(net::DatagramClock::time_point now) noexcept -> void {
            if(!rate_started_){rate_started_=true;refill_=now;return;}
            if(now<=refill_)return;
            auto elapsed=std::chrono::duration_cast<std::chrono::milliseconds>(now-refill_).count();
            if(elapsed<20)return;
            auto credit=static_cast<std::size_t>(std::min<std::int64_t>(Capacity,elapsed/20));quota_=std::min(Capacity,quota_+credit);refill_=now;
        }
        static auto cid(nex::ngtcp2::ngtcp2_cid const& input) noexcept -> RetryCid {
            RetryCid out;out.size=static_cast<std::uint8_t>(input.datalen);std::ranges::copy(std::span(input.data).first(input.datalen),out.data.begin());return out;
        }
    public:
        using Statistics=RetryStatistics;
        static constexpr bool tracks_statistics=TrackStatistics;
        RetryAdmission()=default;
        RetryAdmission(RetryAdmission const&)=delete;
        auto operator=(RetryAdmission const&) -> RetryAdmission& = delete;
        ~RetryAdmission(){stop();}
        auto initialize() noexcept -> std::expected<void,RetryFailure> {
            if(initialized_ || stopped_)return std::unexpected(RetryFailure{});
            auto key=authority_.initialize();if(!key)return std::unexpected(failure(key.error()));
            auto integrity=writer_.initialize();if(!integrity){authority_.clear();return std::unexpected(RetryFailure{RetryFailure::Stage::packet,RetryTokenError::state,integrity.error()});}
            initialized_=true;return {};
        }
        auto statistics() const noexcept -> Statistics requires(TrackStatistics) {return statistics_.value;}
        auto key_slots() const noexcept -> unsigned {return static_cast<unsigned>(authority_.valid())+static_cast<unsigned>(writer_.valid());}
        auto pending() const noexcept -> std::size_t {return std::ranges::count_if(entries_,[](auto const& entry){return entry.has_value();});}
        // The original datagram length is supplied by the sole port parser.
        // Only valid minimum-size v1 Initials can cause any response. Even the
        // maximal local Retry is146B, so its amplification ratio stays below1.
        auto inspect(nex::ngtcp2::ngtcp2_pkt_hd const& initial,nex::corosio::endpoint const& peer,net::DatagramClock::time_point now,std::size_t received_bytes)
            noexcept -> std::expected<std::optional<RetryClaims>,RetryFailure> {
            namespace n=nex::ngtcp2;
            if(!initialized_ || stopped_)return std::unexpected(RetryFailure{});
            if(now.time_since_epoch()<net::DatagramClock::duration::zero() || now>net::DatagramClock::time_point::max()-std::chrono::milliseconds(250))
                return std::unexpected(failure(RetryTokenError::argument));
            if(received_bytes<1200 || initial.version!=1 || initial.type!=n::NGTCP2_PKT_INITIAL || initial.dcid.datalen<8 || initial.dcid.datalen>20 || initial.scid.datalen>20 || !peer.port()){
                if constexpr(TrackStatistics)++statistics_.value.invalid;return std::optional<RetryClaims>{};
            }
            if(initial.tokenlen){
                if(!initial.token){if constexpr(TrackStatistics)++statistics_.value.invalid;return std::optional<RetryClaims>{};}
                auto checked=authority_.verify({initial.token,initial.tokenlen},std::span(initial.dcid.data).first(initial.dcid.datalen),peer,now);
                if(checked){if constexpr(TrackStatistics)++statistics_.value.validated;return std::optional(*checked);}
                if(checked.error()==RetryTokenError::invalid || checked.error()==RetryTokenError::expired){if constexpr(TrackStatistics)++statistics_.value.invalid;return std::optional<RetryClaims>{};}
                return std::unexpected(failure(checked.error()));
            }
            (void)expire(now);refill(now);
            auto free=std::ranges::find_if(entries_,[](auto const& entry){return !entry;});
            if(!quota_ || free==entries_.end()){if constexpr(TrackStatistics)++statistics_.value.throttled;return std::optional<RetryClaims>{};}
            if(!next_token_)return std::unexpected(failure(RetryTokenError::exhausted));
            free->emplace(Entry{cid(initial.dcid),cid(initial.scid),peer,now+std::chrono::milliseconds(250),next_token_++});
            --quota_;if constexpr(TrackStatistics)++statistics_.value.queued;return std::optional<RetryClaims>{};
        }
        auto output(std::span<std::uint8_t> bytes,net::DatagramClock::time_point now) noexcept
            -> std::expected<std::optional<net::DatagramOutput>,RetryFailure> {
            if(!initialized_)return std::unexpected(RetryFailure{});
            if(stopped_)return std::optional<net::DatagramOutput>{};
            if(sealed_)return std::unexpected(RetryFailure{});
            (void)expire(now);std::optional<std::size_t> selected;
            for(std::size_t i=0;i<Capacity;++i)if(entries_[i] && (!selected || entries_[i]->token<entries_[*selected]->token))selected=i;
            if(!selected)return std::optional<net::DatagramOutput>{};
            auto& entry=*entries_[*selected];std::array<std::uint8_t,RetryCidBytes> source{};bool distinct=false;
            for(unsigned attempt=0;attempt<8 && !distinct;++attempt){
                try{if(!Entropy(std::span(source)))return std::unexpected(RetryFailure{RetryFailure::Stage::entropy,RetryTokenError::entropy,0});}
                catch(std::bad_alloc const&){return std::unexpected(RetryFailure{RetryFailure::Stage::entropy,RetryTokenError::allocation,0});}
                catch(...){return std::unexpected(RetryFailure{RetryFailure::Stage::entropy,RetryTokenError::entropy,0});}
                distinct=!crypto::constant_time_equal(source,entry.original.bytes());
            }
            if(!distinct)return std::unexpected(RetryFailure{RetryFailure::Stage::entropy,RetryTokenError::entropy,0});
            std::array<std::uint8_t,RetryTokenAuthority<Entropy>::token_bytes> token{};
            auto issued=authority_.issue(token,entry.original.bytes(),source,entry.peer,now);if(!issued)return std::unexpected(failure(issued.error()));
            auto packet=writer_.write(bytes,entry.destination.bytes(),source,entry.original.bytes(),token);
            if(!packet)return std::unexpected(RetryFailure{RetryFailure::Stage::packet,RetryTokenError::state,packet.error()});
            if(*packet>146 || *packet>=1200)return std::unexpected(RetryFailure{RetryFailure::Stage::packet,RetryTokenError::argument,0});
            sealed_=selected;return net::DatagramOutput{entry.peer,*packet,entry.token};
        }
        auto transmitted(std::uint64_t token,net::DatagramClock::time_point) noexcept -> std::expected<void,RetryFailure> {
            if(!sealed_ || !entries_[*sealed_] || entries_[*sealed_]->token!=token)return std::unexpected(RetryFailure{});
            entries_[*sealed_].reset();sealed_.reset();if constexpr(TrackStatistics)++statistics_.value.committed;return {};
        }
        auto next_expiry() const noexcept -> net::DatagramDeadline {
            if(stopped_)return {};net::DatagramDeadline next;
            for(std::size_t i=0;i<Capacity;++i)if(entries_[i] && sealed_!=i && (!next || entries_[i]->expires<*next))next=entries_[i]->expires;
            return next;
        }
        auto expire(net::DatagramClock::time_point now) noexcept -> std::expected<void,RetryFailure> {
            for(std::size_t i=0;i<Capacity;++i)if(entries_[i] && sealed_!=i && entries_[i]->expires<=now){entries_[i].reset();if constexpr(TrackStatistics)++statistics_.value.expired;}
            return {};
        }
        auto request_stop() noexcept -> void {stopped_=true;}
        // The owning port invokes stop only after its unique UDP driver joins.
        // A queued/sealed response is canceled, never counted as transmitted.
        auto stop() noexcept -> void {
            stopped_=joined_=true;for(auto& entry:entries_)entry.reset();sealed_.reset();authority_.clear();writer_.clear();
        }
        auto drained() const noexcept -> bool {return stopped_ && joined_ && !pending() && !sealed_ && !key_slots();}
    };
}
