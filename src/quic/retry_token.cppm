export module quic.retry_token;
import std;
import crypto;
import crypto.aead_context;
import corosio;

export namespace quic {
    enum class RetryTokenError { state,argument,entropy,crypto,allocation,exhausted,invalid,expired };
    struct RetryCid {
        std::array<std::uint8_t,20> data{};
        std::uint8_t size=0;
        auto bytes() const noexcept -> std::span<std::uint8_t const> {return std::span(data).first(size);}
    };
    struct RetryClaims {RetryCid original,retry;std::uint32_t version=0;std::uint64_t issued_ms=0;};
    // A port owns one non-moving concrete key slot. Tokens are stateless;
    // nonce uniqueness comes from a per-key random prefix and a nonwrapping
    // monotonic counter, rather than per-packet random collision assumptions.
    template<auto Entropy=crypto::random_bytes,std::uint64_t NonceLimit=std::numeric_limits<std::uint64_t>::max()>
    class RetryTokenAuthority {
        static_assert(NonceLimit);
        crypto::AeadContext cipher_;
        std::array<std::uint8_t,4> prefix_{};
        std::uint64_t counter_=0;
        std::chrono::milliseconds lifetime_;
        static constexpr std::size_t claims_bytes=54;
        static auto put(std::span<std::uint8_t> destination,std::uint64_t value) noexcept -> void {
            for(std::size_t i=destination.size();i;--i){destination[i-1]=static_cast<std::uint8_t>(value);value>>=8;}
        }
        static auto get(std::span<std::uint8_t const> source) noexcept -> std::uint64_t {
            std::uint64_t value=0;for(auto byte:source)value=(value<<8)|byte;return value;
        }
        static auto stamp(std::chrono::steady_clock::time_point now) noexcept -> std::optional<std::uint64_t> {
            if(now.time_since_epoch()<std::chrono::steady_clock::duration::zero())return {};
            return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count());
        }
        static auto aad(corosio::endpoint const& peer) noexcept -> std::array<std::uint8_t,36> {
            std::array<std::uint8_t,36> out{'N','E','X','U','S','-','R','E','T','R','Y',1,1};
            if(peer.address().is_v4()){
                out[13]=4;auto bytes=peer.address().to_v4().to_bytes();std::ranges::copy(bytes,out.begin()+14);
            }else{
                out[13]=6;auto address=peer.address().to_v6();auto bytes=address.to_bytes();std::ranges::copy(bytes,out.begin()+14);
                put(std::span(out).subspan(32,4),address.scope_id());
            }
            put(std::span(out).subspan(30,2),peer.port());return out;
        }
    public:
        static constexpr std::size_t token_bytes=1+12+claims_bytes+16;
        explicit RetryTokenAuthority(std::chrono::milliseconds lifetime=std::chrono::seconds(10)) noexcept:lifetime_(lifetime){}
        RetryTokenAuthority(RetryTokenAuthority const&)=delete;
        auto operator=(RetryTokenAuthority const&) -> RetryTokenAuthority& = delete;
        ~RetryTokenAuthority(){clear();}
        auto valid() const noexcept -> bool {return cipher_.valid();}
        auto clear() noexcept -> void {cipher_.clear();crypto::cleanse(prefix_);counter_=0;}
        auto initialize() noexcept -> std::expected<void,RetryTokenError> {
            if(lifetime_.count()<=0 || lifetime_>std::chrono::minutes(10))return std::unexpected(RetryTokenError::argument);
            std::array<std::uint8_t,36> secret{};
            struct Erase{std::array<std::uint8_t,36>& secret;~Erase(){crypto::cleanse(secret);}}erase{secret};
            try{if(!Entropy(std::span(secret)))return std::unexpected(RetryTokenError::entropy);}
            catch(std::bad_alloc const&){return std::unexpected(RetryTokenError::allocation);}
            catch(...){return std::unexpected(RetryTokenError::entropy);}
            if(!cipher_.reset(crypto::Aead::aes_256_gcm,std::span(secret).first(32))){clear();return std::unexpected(RetryTokenError::crypto);}
            std::ranges::copy(std::span(secret).last(4),prefix_.begin());counter_=0;return {};
        }
        auto issue(std::span<std::uint8_t> output,std::span<std::uint8_t const> original,std::span<std::uint8_t const> retry,
            corosio::endpoint const& peer,std::chrono::steady_clock::time_point now,std::uint32_t version=1) noexcept
            -> std::expected<std::size_t,RetryTokenError> {
            if(!valid())return std::unexpected(RetryTokenError::state);
            auto issued=stamp(now);
            if(output.size()<token_bytes || original.size()<8 || original.size()>20 || retry.size()<8 || retry.size()>20 || !peer.port() || !issued || version!=1)
                return std::unexpected(RetryTokenError::argument);
            if(counter_==NonceLimit)return std::unexpected(RetryTokenError::exhausted);
            // Burn the nonce before calling the backend, including failures.
            auto sequence=++counter_;
            std::array<std::uint8_t,claims_bytes> claims{};
            put(std::span(claims).first(4),version);put(std::span(claims).subspan(4,8),*issued);
            claims[12]=static_cast<std::uint8_t>(original.size());std::ranges::copy(original,claims.begin()+13);
            claims[33]=static_cast<std::uint8_t>(retry.size());std::ranges::copy(retry,claims.begin()+34);
            output[0]=1;std::ranges::copy(prefix_,output.begin()+1);put(output.subspan(5,8),sequence);
            auto binding=aad(peer);auto sealed=cipher_.seal_to(output.subspan(13,claims_bytes+16),output.subspan(1,12),claims,binding);
            crypto::cleanse(claims);
            if(!sealed){crypto::cleanse(output.first(token_bytes));return std::unexpected(RetryTokenError::crypto);}
            return token_bytes;
        }
        auto verify(std::span<std::uint8_t const> token,std::span<std::uint8_t const> destination,corosio::endpoint const& peer,
            std::chrono::steady_clock::time_point now,std::uint32_t version=1) const noexcept -> std::expected<RetryClaims,RetryTokenError> {
            if(!valid())return std::unexpected(RetryTokenError::state);
            auto current=stamp(now);
            if(token.size()!=token_bytes || token[0]!=1 || destination.size()<8 || destination.size()>20 || !peer.port() || !current || version!=1)
                return std::unexpected(RetryTokenError::invalid);
            std::array<std::uint8_t,claims_bytes> plaintext{};
            struct Erase{std::array<std::uint8_t,claims_bytes>& value;~Erase(){crypto::cleanse(value);}}erase{plaintext};
            auto binding=aad(peer);auto opened=cipher_.open_to(plaintext,token.subspan(1,12),token.subspan(13),binding);
            if(!opened)return std::unexpected(opened.error()==crypto::Error::authentication_failed?RetryTokenError::invalid:RetryTokenError::crypto);
            auto original_size=plaintext[12],retry_size=plaintext[33];
            if(get(std::span(plaintext).first(4))!=version || original_size<8 || original_size>20 || retry_size<8 || retry_size>20 ||
                !crypto::constant_time_equal(std::span(plaintext).subspan(34,retry_size),destination))return std::unexpected(RetryTokenError::invalid);
            auto issued=get(std::span(plaintext).subspan(4,8));
            if(issued>*current || *current-issued>static_cast<std::uint64_t>(lifetime_.count()))return std::unexpected(RetryTokenError::expired);
            RetryClaims claims;claims.version=version;claims.issued_ms=issued;claims.original.size=original_size;claims.retry.size=retry_size;
            std::ranges::copy(std::span(plaintext).subspan(13,original_size),claims.original.data.begin());
            std::ranges::copy(std::span(plaintext).subspan(34,retry_size),claims.retry.data.begin());return claims;
        }
    };
}
