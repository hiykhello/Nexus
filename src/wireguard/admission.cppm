export module wireguard.admission;
import std;
import crypto;
import net.udp_socket;
import wireguard;
import wireguard.cookie;
import wireguard.crypto;

export namespace wireguard {
    namespace admission {
        using Address=net::UdpEndpoint;
        struct CookieRequest { std::uint64_t ticket; Clock::time_point expires; };
        enum class ErrorCode { closed,clock,source,cookie_secret,stale_request,exhausted,protocol,busy };
        struct Failure { ErrorCode code; std::optional<Error> protocol; };
        [[nodiscard]] inline auto valid_source(Address const& source) noexcept -> bool {
            if (!source.port || (source.family!=4 && source.family!=6)) return false;
            auto size=source.family==4 ? 4u : 16u;
            if (std::ranges::all_of(std::span(source.address).first(size),[](auto c) { return c==0; })) return false;
            if (source.family==4) return std::ranges::all_of(std::span(source.address).subspan(4),[](auto c) { return c==0; });
            return !(std::ranges::all_of(std::span(source.address).first(10),[](auto c) { return c==0; }) && source.address[10]==255 && source.address[11]==255);
        }
        struct AdmittedWire { Key local_public; std::array<std::uint8_t,initiation_size> bytes{}; std::size_t size; };
    }
    class CookieAdmission;
    // Owns the exact MAC1-authenticated wire bytes. This is only a gate into
    // Noise, not proof of a configured peer or an authenticated timestamp.
    class AdmittedHandshake {
        friend class CookieAdmission;
        admission::AdmittedWire wire_;
        bool active_=true;
        AdmittedHandshake(Key const& local,std::span<std::uint8_t const> wire) noexcept : wire_{local,{},wire.size()} {
            std::ranges::copy(wire,wire_.bytes.begin());
        }
    public:
        AdmittedHandshake(AdmittedHandshake const&)=delete;
        auto operator=(AdmittedHandshake const&) -> AdmittedHandshake& = delete;
        AdmittedHandshake(AdmittedHandshake&& other) noexcept : wire_(other.wire_),active_(std::exchange(other.active_,false)) {}
        auto operator=(AdmittedHandshake&& other) noexcept -> AdmittedHandshake& {
            if (this!=&other) { wire_=other.wire_; active_=std::exchange(other.active_,false); } return *this;
        }
        [[nodiscard]] static auto authenticate(Key const& local,std::span<std::uint8_t const> wire) noexcept -> std::expected<AdmittedHandshake,Error> {
            auto checked=detail::check_mac1(wire,local); if (!checked) return std::unexpected(checked.error());
            return AdmittedHandshake(local,wire);
        }
        [[nodiscard]] auto take() noexcept -> std::expected<admission::AdmittedWire,Error> {
            if (!std::exchange(active_,false)) return std::unexpected(Error::invalid_state);
            return wire_;
        }
    };
    namespace admission {
        struct Decision { std::optional<CookieRequest> cookie; std::optional<AdmittedHandshake> admitted; };
        struct Reply { CookieRequest request; Address destination; std::array<std::uint8_t,cookie_size> bytes; };
    }
    // One direct gate per local identity/UDP port. Hosts inject the secret and
    // nonce. The same component also serves a standalone single-peer owner.
    class CookieAdmission {
        struct Challenge {
            admission::CookieRequest request;
            admission::Address source;
            std::array<std::uint8_t,initiation_size> wire{};
            std::size_t size;
        };
        Key local_public_;
        std::optional<CookieChecker> checker_;
        std::optional<Challenge> challenge_;
        std::optional<Clock::time_point> observed_;
        std::uint64_t latest_=0;
        bool closed_=false,reply_live_=false;
        static auto failure(admission::ErrorCode code,std::optional<Error> protocol={}) noexcept -> std::unexpected<admission::Failure> { return std::unexpected(admission::Failure{code,protocol}); }
        static auto source(admission::Address const& value) noexcept -> CookieSource { return {std::span(value.address).first(value.family==4 ? 4 : 16),value.port}; }
        auto observe(Clock::time_point now) noexcept -> std::expected<void,admission::Failure> {
            if (closed_) return failure(admission::ErrorCode::closed);
            if (now<Clock::time_point{} || (observed_ && now<*observed_)) return failure(admission::ErrorCode::clock);
            observed_=now; return {};
        }
    public:
        explicit CookieAdmission(Key local_public) noexcept : local_public_(local_public) {}
        ~CookieAdmission() { close(); }
        CookieAdmission(CookieAdmission const&)=delete;
        auto operator=(CookieAdmission const&) -> CookieAdmission& = delete;
        CookieAdmission(CookieAdmission&&)=delete;
        auto operator=(CookieAdmission&&) -> CookieAdmission& = delete;
        [[nodiscard]] auto local_public() const noexcept -> Key const& { return local_public_; }
        auto cancel() noexcept -> void { challenge_.reset(); reply_live_=false; }
        auto close() noexcept -> void { cancel(); checker_.reset(); closed_=true; }
        [[nodiscard]] auto rotate_secret(SecretKey secret,Clock::time_point now) noexcept -> std::expected<void,admission::Failure> {
            auto checked=observe(now); if (!checked) return checked;
            if (checker_) {
                auto rotated=checker_->rotate(std::move(secret),now); if (!rotated) return failure(admission::ErrorCode::protocol,rotated.error());
            } else {
                auto checker=CookieChecker::create(local_public_,std::move(secret),now); if (!checker) return failure(admission::ErrorCode::protocol,checker.error());
                checker_.emplace(std::move(*checker));
            }
            cancel(); return {};
        }
        [[nodiscard]] auto admit(std::span<std::uint8_t const> wire,admission::Address peer,bool source_allowed,Clock::time_point now,bool require_cookie=false,bool allow_challenge=true) noexcept
            -> std::expected<admission::Decision,admission::Failure> {
            auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
            if (!source_allowed || !admission::valid_source(peer)) return failure(admission::ErrorCode::source);
            if (!require_cookie) {
                auto admitted=AdmittedHandshake::authenticate(local_public_,wire); if (!admitted) return failure(admission::ErrorCode::protocol,admitted.error());
                admission::Decision result; result.admitted.emplace(std::move(*admitted)); return result;
            }
            if (!checker_) return failure(admission::ErrorCode::cookie_secret);
            auto cookie=checker_->check(wire,source(peer),now,true);
            if (cookie) {
                admission::Decision result; result.admitted.emplace(AdmittedHandshake(local_public_,wire)); return result;
            }
            if (cookie.error()==Error::expired) return failure(admission::ErrorCode::cookie_secret,Error::expired);
            if (cookie.error()!=Error::authentication) return failure(admission::ErrorCode::protocol,cookie.error());
            auto mac1=checker_->check(wire,source(peer),now,false); if (!mac1) return failure(admission::ErrorCode::protocol,mac1.error());
            if (!allow_challenge) return failure(admission::ErrorCode::busy);
            if (latest_==std::numeric_limits<std::uint64_t>::max()) return failure(admission::ErrorCode::exhausted,Error::counter_exhausted);
            auto delay=std::chrono::duration_cast<Clock::duration>(std::chrono::seconds(5));
            auto expires=now.time_since_epoch()>Clock::duration::max()-delay ? Clock::time_point::max() : now+delay;
            admission::CookieRequest request{++latest_,expires}; cancel(); challenge_.emplace(Challenge{request,peer,{},wire.size()});
            std::ranges::copy(wire,challenge_->wire.begin()); admission::Decision result; result.cookie=request; return result;
        }
        [[nodiscard]] auto poll(Clock::time_point now) noexcept -> std::expected<std::optional<admission::CookieRequest>,admission::Failure> {
            auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
            if (challenge_ && now>=challenge_->request.expires) challenge_.reset();
            return challenge_ ? std::optional(challenge_->request) : std::nullopt;
        }
        [[nodiscard]] auto respond(admission::CookieRequest request,std::span<std::uint8_t const,24> nonce,Clock::time_point now)
            -> std::expected<admission::Reply,admission::Failure> {
            auto checked=observe(now); if (!checked) return std::unexpected(checked.error());
            if (!challenge_ || request.ticket!=challenge_->request.ticket || now>=challenge_->request.expires) return failure(admission::ErrorCode::stale_request);
            if (!checker_) return failure(admission::ErrorCode::cookie_secret);
            auto wire=checker_->reply(std::span(challenge_->wire).first(challenge_->size),source(challenge_->source),nonce,now);
            if (!wire) return failure(wire.error()==Error::expired ? admission::ErrorCode::cookie_secret : admission::ErrorCode::protocol,wire.error());
            admission::Reply result{challenge_->request,challenge_->source,*wire}; challenge_.reset(); reply_live_=true; return result;
        }
        [[nodiscard]] auto reply_valid(std::uint64_t ticket) const noexcept -> bool { return !closed_ && reply_live_ && ticket==latest_; }
    };
}
