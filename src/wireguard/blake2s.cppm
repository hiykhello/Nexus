export module wireguard.blake2s;
import std;

export namespace wireguard::blake2s {
    enum class Error { invalid_length,invalid_key,closed,too_large };
    namespace detail {
        inline auto erase(std::span<std::uint8_t> bytes) noexcept -> void {
            volatile std::uint8_t* value=bytes.data(); for (std::size_t i=0;i<bytes.size();++i) value[i]=0;
        }
        template<class T,std::size_t N>
        auto erase(std::array<T,N>& words) noexcept -> void {
            volatile T* value=words.data(); for (std::size_t i=0;i<N;++i) value[i]=0;
        }
        template<class Buffer>
        struct Erase { Buffer& buffer; ~Erase() { erase(buffer); } };
        inline constexpr std::array<std::uint32_t,8> iv{
            0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
        inline constexpr std::array<std::array<std::uint8_t,16>,10> sigma{{
            {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15},{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3},
            {11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4},{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8},
            {9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13},{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9},
            {12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11},{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10},
            {6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5},{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0}
        }};
    }
    // RFC 7693 sequential BLAKE2s; key padding and the last data block are
    // retained until the next nonempty update or finish. No heap storage.
    template<std::size_t Size=32> requires (Size>0 && Size<=32)
    class State {
        std::array<std::uint32_t,8> hash_=detail::iv;
        std::array<std::uint8_t,64> block_{};
        std::size_t used_=0;
        std::uint64_t compressed_=0;
        bool closed_=false;
        explicit State(std::span<std::uint8_t const> key) noexcept {
            hash_[0]^=0x01010000u^(static_cast<std::uint32_t>(key.size())<<8)^Size;
            if (!key.empty()) { std::ranges::copy(key,block_.begin()); used_=block_.size(); }
        }
        auto compress(bool last) noexcept -> void {
            std::array<std::uint32_t,16> message{},work{};
            for (std::size_t i=0;i<16;++i) for (std::size_t j=0;j<4;++j) message[i]|=std::uint32_t(block_[4*i+j])<<(8*j);
            std::ranges::copy(hash_,work.begin()); std::ranges::copy(detail::iv,work.begin()+8);
            work[12]^=static_cast<std::uint32_t>(compressed_); work[13]^=static_cast<std::uint32_t>(compressed_>>32);
            if (last) work[14]=~work[14];
            auto mix=[&](unsigned a,unsigned b,unsigned c,unsigned d,std::uint32_t x,std::uint32_t y) {
                work[a]+=work[b]+x; work[d]=std::rotr(work[d]^work[a],16);
                work[c]+=work[d]; work[b]=std::rotr(work[b]^work[c],12);
                work[a]+=work[b]+y; work[d]=std::rotr(work[d]^work[a],8);
                work[c]+=work[d]; work[b]=std::rotr(work[b]^work[c],7);
            };
            for (auto const& s:detail::sigma) {
                mix(0,4,8,12,message[s[0]],message[s[1]]); mix(1,5,9,13,message[s[2]],message[s[3]]);
                mix(2,6,10,14,message[s[4]],message[s[5]]); mix(3,7,11,15,message[s[6]],message[s[7]]);
                mix(0,5,10,15,message[s[8]],message[s[9]]); mix(1,6,11,12,message[s[10]],message[s[11]]);
                mix(2,7,8,13,message[s[12]],message[s[13]]); mix(3,4,9,14,message[s[14]],message[s[15]]);
            }
            for (std::size_t i=0;i<8;++i) hash_[i]^=work[i]^work[i+8];
            detail::erase(message); detail::erase(work);
        }
        auto clear() noexcept -> void { detail::erase(hash_); detail::erase(block_); used_=0; compressed_=0; closed_=true; }
    public:
        State() noexcept : State(std::span<std::uint8_t const>{}) {}
        ~State() { clear(); }
        State(State const&)=delete;
        auto operator=(State const&) -> State& = delete;
        State(State&& other) noexcept : hash_(other.hash_),block_(other.block_),used_(other.used_),compressed_(other.compressed_),closed_(other.closed_) { other.clear(); }
        auto operator=(State&& other) noexcept -> State& {
            if (this!=&other) {
                clear(); hash_=other.hash_; block_=other.block_; used_=other.used_; compressed_=other.compressed_; closed_=other.closed_; other.clear();
            }
            return *this;
        }
        static auto keyed(std::span<std::uint8_t const> key) noexcept -> std::expected<State,Error> {
            if (key.size()>32) return std::unexpected(Error::invalid_key);
            return State(key);
        }
        auto update(std::span<std::uint8_t const> input) noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);
            if (input.size()>std::numeric_limits<std::uint64_t>::max()-compressed_-used_) return std::unexpected(Error::too_large);
            while (!input.empty()) {
                if (used_==block_.size()) { compressed_+=block_.size(); compress(false); used_=0; }
                auto size=std::min(input.size(),block_.size()-used_);
                std::copy_n(input.begin(),size,block_.begin()+used_); used_+=size; input=input.subspan(size);
            }
            return {};
        }
        auto finish_to(std::span<std::uint8_t,Size> output) noexcept -> std::expected<void,Error> {
            if (closed_) return std::unexpected(Error::closed);
            compressed_+=used_; std::fill(block_.begin()+used_,block_.end(),0); compress(true);
            for (std::size_t i=0;i<Size;++i) output[i]=static_cast<std::uint8_t>(hash_[i/4]>>(8*(i%4)));
            clear(); return {};
        }
        auto finish() noexcept -> std::expected<std::array<std::uint8_t,Size>,Error> {
            std::array<std::uint8_t,Size> result{};
            auto finished=finish_to(result); if (!finished) return std::unexpected(finished.error()); return result;
        }
    };
    // Secret derivations write directly into their owner's erasing storage;
    // no security guarantee depends on array return-value copy elision.
    template<std::size_t Size> requires (Size>0 && Size<=32)
    [[nodiscard]] auto digest_to(std::span<std::uint8_t,Size> output,std::span<std::uint8_t const> input,std::span<std::uint8_t const> key={}) noexcept
        -> std::expected<void,Error> {
        auto state=State<Size>::keyed(key); if (!state) return std::unexpected(state.error());
        auto updated=state->update(input); if (!updated) return std::unexpected(updated.error());
        return state->finish_to(output);
    }
    template<std::size_t Size> requires (Size>0 && Size<=32)
    [[nodiscard]] auto digest_parts_to(std::span<std::uint8_t,Size> output,std::initializer_list<std::span<std::uint8_t const>> input,
        std::span<std::uint8_t const> key={}) noexcept -> std::expected<void,Error> {
        auto state=State<Size>::keyed(key); if (!state) return std::unexpected(state.error());
        for (auto part:input) { auto updated=state->update(part); if (!updated) return std::unexpected(updated.error()); }
        return state->finish_to(output);
    }
    template<std::size_t Size=32> requires (Size>0 && Size<=32)
    [[nodiscard]] auto digest(std::span<std::uint8_t const> input,std::span<std::uint8_t const> key={}) noexcept
        -> std::expected<std::array<std::uint8_t,Size>,Error> {
        auto state=State<Size>::keyed(key); if (!state) return std::unexpected(state.error());
        auto updated=state->update(input); if (!updated) return std::unexpected(updated.error());
        return state->finish();
    }
    template<std::size_t Size=32> requires (Size>0 && Size<=32)
    [[nodiscard]] auto digest_parts(std::initializer_list<std::span<std::uint8_t const>> input,std::span<std::uint8_t const> key={}) noexcept
        -> std::expected<std::array<std::uint8_t,Size>,Error> {
        auto state=State<Size>::keyed(key); if (!state) return std::unexpected(state.error());
        for (auto part:input) { auto updated=state->update(part); if (!updated) return std::unexpected(updated.error()); }
        return state->finish();
    }
    // WireGuard's HKDF uses HMAC-BLAKE2s, while its MAC1/MAC2 use native keyed
    // BLAKE2s-128. The two constructions are intentionally separate.
    [[nodiscard]] inline auto hmac_to(std::span<std::uint8_t,32> output,std::span<std::uint8_t const> key,
        std::initializer_list<std::span<std::uint8_t const>> input) noexcept -> std::expected<void,Error> {
        std::array<std::uint8_t,64> pad{};
        detail::Erase erase{pad};
        if (key.size()>pad.size()) {
            auto hash=digest_to(std::span(pad).first<32>(),key); if (!hash) return std::unexpected(hash.error());
        } else std::ranges::copy(key,pad.begin());
        for (auto& byte:pad) byte^=0x36;
        State state;
        auto updated=state.update(pad); if (!updated) return std::unexpected(updated.error());
        for (auto part:input) { updated=state.update(part); if (!updated) return std::unexpected(updated.error()); }
        std::array<std::uint8_t,32> inner{};
        detail::Erase erase_inner{inner};
        auto finished=state.finish_to(inner); if (!finished) return std::unexpected(finished.error());
        for (auto& byte:pad) byte^=0x36^0x5c;
        return digest_parts_to(output,{pad,inner});
    }
    [[nodiscard]] inline auto hmac(std::span<std::uint8_t const> key,std::initializer_list<std::span<std::uint8_t const>> input) noexcept
        -> std::expected<std::array<std::uint8_t,32>,Error> {
        std::array<std::uint8_t,32> result{};
        auto finished=hmac_to(result,key,input); if (!finished) return std::unexpected(finished.error()); return result;
    }
}
