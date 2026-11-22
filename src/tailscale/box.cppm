export module tailscale.box;
import std;
import crypto;

export namespace tailscale::box {
    inline constexpr std::size_t nonce_size=24,tag_size=16,max_message_size=1024*1024;
    enum class Error { invalid_key,invalid_nonce,invalid_length,capacity,overlap,authentication,peer,backend };
    namespace detail {
        template<class T,std::size_t N>
        struct Erase {
            std::array<T,N>& bytes;
            ~Erase() { crypto::cleanse({reinterpret_cast<std::uint8_t*>(bytes.data()),sizeof(bytes)}); }
        };
        inline auto load(std::span<std::uint8_t const> bytes) noexcept -> std::uint32_t {
            return std::uint32_t(bytes[0])|(std::uint32_t(bytes[1])<<8)|(std::uint32_t(bytes[2])<<16)|(std::uint32_t(bytes[3])<<24);
        }
        inline auto store(std::span<std::uint8_t> output,std::uint32_t value) noexcept -> void {
            for (unsigned i=0;i<4;++i) output[i]=static_cast<std::uint8_t>(value>>(i*8));
        }
        inline auto quarter(std::uint32_t& a,std::uint32_t& b,std::uint32_t& c,std::uint32_t& d) noexcept -> void {
            b^=std::rotl(a+d,7); c^=std::rotl(b+a,9); d^=std::rotl(c+b,13); a^=std::rotl(d+c,18);
        }
        inline auto initialize(std::array<std::uint32_t,16>& state,std::span<std::uint8_t const,32> key,
            std::span<std::uint8_t const,16> input) noexcept -> void {
            state[0]=0x61707865; state[5]=0x3320646e; state[10]=0x79622d32; state[15]=0x6b206574;
            for (unsigned i=0;i<4;++i) { state[1+i]=load(key.subspan(i*4)); state[11+i]=load(key.subspan(16+i*4)); state[6+i]=load(input.subspan(i*4)); }
        }
        inline auto permute(std::array<std::uint32_t,16>& words) noexcept -> void {
            for (unsigned i=0;i<10;++i) {
                quarter(words[0],words[4],words[8],words[12]); quarter(words[5],words[9],words[13],words[1]);
                quarter(words[10],words[14],words[2],words[6]); quarter(words[15],words[3],words[7],words[11]);
                quarter(words[0],words[1],words[2],words[3]); quarter(words[5],words[6],words[7],words[4]);
                quarter(words[10],words[11],words[8],words[9]); quarter(words[15],words[12],words[13],words[14]);
            }
        }
        inline auto hsalsa(std::span<std::uint8_t,32> output,std::span<std::uint8_t const,32> key,
            std::span<std::uint8_t const,16> input) noexcept -> void {
            std::array<std::uint32_t,16> words{}; Erase guard{words};
            initialize(words,key,input); permute(words);
            constexpr std::array<unsigned,8> indexes{0,5,10,15,6,7,8,9};
            for (unsigned i=0;i<indexes.size();++i) store(output.subspan(i*4),words[indexes[i]]);
        }
        struct Cipher {
            std::array<std::uint8_t,32> subkey{};
            std::array<std::uint8_t,16> counter{};
            explicit Cipher(std::span<std::uint8_t const,32> key,std::span<std::uint8_t const,24> nonce) noexcept {
                hsalsa(subkey,key,nonce.first<16>()); std::copy_n(nonce.begin()+16,8,counter.begin());
            }
            ~Cipher() { crypto::cleanse(subkey); crypto::cleanse(counter); }
            Cipher(Cipher const&)=delete;
            auto operator=(Cipher const&) -> Cipher& = delete;
            auto block(std::span<std::uint8_t,64> output,std::uint64_t number) const noexcept -> void {
                std::array<std::uint32_t,16> initial{},words{};
                Erase one{initial}; Erase two{words};
                initialize(initial,subkey,counter);
                initial[8]=static_cast<std::uint32_t>(number); initial[9]=static_cast<std::uint32_t>(number>>32); words=initial;
                permute(words);
                for (unsigned i=0;i<words.size();++i) store(output.subspan(i*4),words[i]+initial[i]);
            }
            auto apply(std::span<std::uint8_t> output,std::span<std::uint8_t const> input,
                std::span<std::uint8_t const,64> first) const noexcept -> void {
                auto size=std::min(std::size_t{32},input.size());
                for (std::size_t i=0;i<size;++i) output[i]=input[i]^first[32+i];
                output=output.subspan(size); input=input.subspan(size);
                std::array<std::uint8_t,64> stream{}; Erase guard{stream};
                for (std::uint64_t count=1;!input.empty();++count) {
                    block(stream,count); size=std::min(stream.size(),input.size());
                    for (std::size_t i=0;i<size;++i) output[i]=input[i]^stream[i];
                    output=output.subspan(size); input=input.subspan(size);
                }
            }
        };
        inline auto overlaps(std::span<std::uint8_t> output,std::span<std::uint8_t const> input) noexcept -> bool {
            if (output.empty() || input.empty()) return false;
            auto first=reinterpret_cast<std::uintptr_t>(output.data()),second=reinterpret_cast<std::uintptr_t>(input.data());
            return first<=second ? second-first<output.size() : first-second<input.size();
        }
    }
    // The node owner supplies a unique nonce per peer/shared key and distinct
    // message, and keeps caller buffers alive. Inputs and output must not
    // overlap. This is NaCl box compatibility, separate from TLS AEAD choices.
    class SharedKey {
        std::array<std::uint8_t,32> bytes_{};
        bool valid_=false;
        SharedKey()=default;
    public:
        ~SharedKey() { clear(); }
        SharedKey(SharedKey const&)=delete;
        auto operator=(SharedKey const&) -> SharedKey& = delete;
        SharedKey(SharedKey&& other) noexcept : bytes_(other.bytes_),valid_(other.valid_) { other.clear(); }
        auto operator=(SharedKey&& other) noexcept -> SharedKey& {
            if (this!=&other) { clear(); bytes_=other.bytes_; valid_=other.valid_; other.clear(); } return *this;
        }
        auto clear() noexcept -> void { crypto::cleanse(bytes_); valid_=false; }
        auto valid() const noexcept -> bool { return valid_; }
        // key is the final XSalsa20 secretbox key. For public-key boxes it
        // must be HSalsa20(X25519(local,peer),zero16), never the raw DH result.
        // A directly shared secretbox key is also defined by NaCl. The caller
        // owns and cleans this input; derive() is preferred for node keys.
        static auto from_secretbox_key(std::span<std::uint8_t const> key) noexcept -> std::expected<SharedKey,Error> {
            if (key.size()!=32) return std::unexpected(Error::invalid_key);
            SharedKey result; std::copy_n(key.begin(),32,result.bytes_.begin()); result.valid_=true; return result;
        }
        static auto derive(crypto::X25519Private const& local,std::span<std::uint8_t const> remote) -> std::expected<SharedKey,Error> {
            auto shared=local.agree(remote);
            if (!shared) return std::unexpected(shared.error()==crypto::Error::invalid_peer ? Error::peer :
                shared.error()==crypto::Error::invalid_key || shared.error()==crypto::Error::invalid_state ? Error::invalid_key : Error::backend);
            SharedKey result;
            constexpr std::array<std::uint8_t,16> zeros{};
            detail::hsalsa(result.bytes_,shared->view(),zeros); result.valid_=true; return result;
        }
        auto seal_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,std::span<std::uint8_t const> plaintext) const noexcept
            -> std::expected<std::size_t,Error> {
            if (!valid_) return std::unexpected(Error::invalid_key);
            if (nonce.size()!=nonce_size) return std::unexpected(Error::invalid_nonce);
            if (plaintext.size()>max_message_size) return std::unexpected(Error::invalid_length);
            if (output.size()<plaintext.size()+tag_size) return std::unexpected(Error::capacity);
            auto destination=output.first(plaintext.size()+tag_size);
            if (detail::overlaps(destination,plaintext)) return std::unexpected(Error::overlap);
            detail::Cipher cipher(bytes_,std::span<std::uint8_t const,24>(nonce.data(),24));
            std::array<std::uint8_t,64> first{}; detail::Erase guard{first}; cipher.block(first,0);
            auto ciphertext=destination.subspan(tag_size);
            cipher.apply(ciphertext,plaintext,first);
            crypto::poly1305_to(std::span<std::uint8_t,16>(destination.data(),16),std::span(first).first<32>(),ciphertext);
            return destination.size();
        }
        auto open_to(std::span<std::uint8_t> output,std::span<std::uint8_t const> nonce,std::span<std::uint8_t const> sealed) const noexcept
            -> std::expected<std::size_t,Error> {
            if (!valid_) return std::unexpected(Error::invalid_key);
            if (nonce.size()!=nonce_size) return std::unexpected(Error::invalid_nonce);
            if (sealed.size()<tag_size || sealed.size()-tag_size>max_message_size) return std::unexpected(Error::invalid_length);
            auto size=sealed.size()-tag_size;
            if (output.size()<size) return std::unexpected(Error::capacity);
            auto destination=output.first(size);
            if (detail::overlaps(destination,sealed)) return std::unexpected(Error::overlap);
            detail::Cipher cipher(bytes_,std::span<std::uint8_t const,24>(nonce.data(),24));
            std::array<std::uint8_t,64> first{}; std::array<std::uint8_t,16> tag{};
            detail::Erase one{first}; detail::Erase two{tag}; cipher.block(first,0);
            auto ciphertext=sealed.subspan(tag_size);
            crypto::poly1305_to(tag,std::span(first).first<32>(),ciphertext);
            if (!crypto::constant_time_equal(tag,sealed.first(tag_size))) return std::unexpected(Error::authentication);
            cipher.apply(destination,ciphertext,first);
            return size;
        }
    };
}

