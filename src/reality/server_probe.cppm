export module reality.server_probe;
import std;
import reality.auth;
import reality.server_auth;
import tls.client_hello_stream;

export namespace reality {
    enum class ProbeStatus { pending, authenticated, fallback };
    struct ProbeFeed { std::size_t consumed=0; ProbeStatus status=ProbeStatus::pending; };
    // One executor owns this bounded probe. Every consumed byte is retained
    // exactly for TLS replay or fallback, including bytes following the Hello.
    // Once decided, callers must forward any unconsumed input separately.
    class ServerProbe {
        // Declared first so the reservation outlives all retained storage.
        std::optional<memory::Budget::Reservation> reservation_;
        tls::ClientHelloStream parser_;
        crypto::Bytes raw_;
        std::size_t parsed_=0,limit_;
        ProbeStatus status_=ProbeStatus::pending;
        std::optional<OpenedHello> opened_;
        explicit ServerProbe(tls::ClientHelloStream&& parser,std::size_t limit,
                             std::optional<memory::Budget::Reservation>&& reservation)
            : reservation_(std::move(reservation)),parser_(std::move(parser)),limit_(limit) {}
    public:
        // Logical lengths for raw input, reassembly, message copies and up to
        // three simultaneous parsed hellos during authentication. Allocator
        // capacity, overhead and cryptographic-library internals are excluded.
        [[nodiscard]] static constexpr auto charge(std::size_t limit) noexcept -> std::size_t {
            return limit + 16389 + 5 + 65539 + 4096 + 3*65539 + 3*tls::ClientHelloStream::parsed_charge(65535);
        }
        [[nodiscard]] static auto create(std::size_t limit=131072,std::shared_ptr<memory::Budget> budget={}) -> std::optional<ServerProbe> {
            if (limit<5 || limit>1048576) return {};
            std::optional<memory::Budget::Reservation> reservation;
            if (budget) { reservation=memory::Budget::reserve(std::move(budget),charge(limit)); if (!reservation) return {}; }
            auto parser=tls::ClientHelloStream::create(); if (!parser) return {};
            return ServerProbe(std::move(*parser),limit,std::move(reservation));
        }
        ServerProbe(ServerProbe const&)=delete;
        auto operator=(ServerProbe const&) -> ServerProbe& = delete;
        ServerProbe(ServerProbe&&)=default;
        auto operator=(ServerProbe&&) -> ServerProbe& = delete;
        [[nodiscard]] auto feed(std::span<std::uint8_t const> input,crypto::X25519Private const& key,
                                ServerPolicy const& policy,std::uint64_t now) -> ProbeFeed {
            if (status_!=ProbeStatus::pending) return {0,status_};
            auto count=std::min(input.size(),limit_-raw_.size());
            raw_.insert(raw_.end(),input.begin(),input.begin()+count);
            if (!raw_.empty() && raw_.front()!=22) {
                status_=ProbeStatus::fallback;
                return {count,status_};
            }
            while (parsed_<raw_.size()) {
                auto result=parser_.feed(std::span(raw_).subspan(parsed_));
                if (!result) { status_=ProbeStatus::fallback; break; }
                parsed_+=result->consumed;
                if (result->hello) {
                    opened_=authenticate_server_hello(result->message,key,policy,now);
                    status_=opened_ ? ProbeStatus::authenticated : ProbeStatus::fallback; break;
                }
                if (!result->consumed) break;
            }
            if (status_==ProbeStatus::pending && raw_.size()==limit_) status_=ProbeStatus::fallback;
            return {count,status_};
        }
        [[nodiscard]] auto bytes() const noexcept -> std::span<std::uint8_t const> { return raw_; }
        [[nodiscard]] auto status() const noexcept -> ProbeStatus { return status_; }
        [[nodiscard]] auto take_authentication() noexcept -> std::optional<OpenedHello> {
            if (status_!=ProbeStatus::authenticated || !opened_) return {};
            auto result=std::move(opened_); opened_.reset(); return result;
        }
    };
}
