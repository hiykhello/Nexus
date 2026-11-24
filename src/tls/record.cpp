module tls.record;
import std;

namespace tls {
    namespace {
        auto valid_type(ContentType t) -> bool { return t==ContentType::alert || t==ContentType::handshake || t==ContentType::application_data; }
    }
    RecordLayer::RecordLayer(crypto::Aead algorithm, crypto::Bytes key, std::unique_ptr<crypto::AeadContext> aead, std::array<std::uint8_t,12> iv, RecordDirection direction, std::uint64_t send_limit)
        : algorithm_(algorithm), key_(std::move(key)), aead_(std::move(aead)), iv_(iv), send_limit_(send_limit), direction_(direction) {}
    RecordLayer::~RecordLayer() { aead_.reset(); crypto::cleanse(key_); crypto::cleanse(iv_); }
    RecordLayer::RecordLayer(RecordLayer&& other) noexcept
        : algorithm_(other.algorithm_), key_(std::move(other.key_)), aead_(std::move(other.aead_)), iv_(other.iv_), sequence_(other.sequence_), send_limit_(other.send_limit_), direction_(other.direction_), active_(other.active_), legacy_(other.legacy_) {
        other.aead_.reset(); other.active_=false; crypto::cleanse(other.iv_); crypto::cleanse(other.key_);
    }
    auto RecordLayer::operator=(RecordLayer&& other) noexcept -> RecordLayer& {
        if (this != &other) {
            aead_.reset(); crypto::cleanse(key_); crypto::cleanse(iv_);
            algorithm_=other.algorithm_; key_=std::move(other.key_); aead_=std::move(other.aead_); iv_=other.iv_; sequence_=other.sequence_; send_limit_=other.send_limit_; direction_=other.direction_; active_=other.active_; legacy_=other.legacy_;
            other.aead_.reset(); other.active_=false; crypto::cleanse(other.iv_); crypto::cleanse(other.key_);
        }
        return *this;
    }
    auto RecordLayer::create(RecordDirection direction, crypto::Aead algorithm, std::span<std::uint8_t const> key,
                             std::span<std::uint8_t const> iv, std::uint64_t send_limit) -> std::expected<RecordLayer,RecordError> {
        std::size_t size=0;
        switch (algorithm) {
            case crypto::Aead::aes_128_gcm: size=16; break;
            case crypto::Aead::aes_256_gcm: case crypto::Aead::chacha20_poly1305: size=32; break;
            default: return std::unexpected(RecordError::invalid_key);
        }
        if (key.size()!=size || iv.size()!=12 || send_limit==0 || send_limit>(1u << 24)) return std::unexpected(RecordError::invalid_key);
        auto aead=std::make_unique<crypto::AeadContext>();
        if (!aead->reset(algorithm,key)) return std::unexpected(RecordError::invalid_key);
        std::array<std::uint8_t,12> copy{}; std::ranges::copy(iv,copy.begin());
        return RecordLayer(algorithm,crypto::Bytes(key.begin(),key.end()),std::move(aead),copy,direction,send_limit);
    }
    auto RecordLayer::nonce() const -> std::array<std::uint8_t,12> {
        auto result=iv_;
        for (std::size_t i=0;i<8;++i) result[11-i]^=static_cast<std::uint8_t>(sequence_>>(8*i));
        return result;
    }
    auto RecordLayer::advance() noexcept -> void {
        if (sequence_==std::numeric_limits<std::uint64_t>::max()) active_=false; else ++sequence_;
    }
    auto RecordLayer::seal(ContentType type, std::span<std::uint8_t const> content, std::size_t padding)
        -> std::expected<crypto::Bytes,RecordError> {
        if (!active_ || !aead_) return std::unexpected(RecordError::invalid_state);
        if (direction_!=RecordDirection::send) return std::unexpected(RecordError::invalid_state);
        if (sequence_>=send_limit_) return std::unexpected(RecordError::key_usage_limit);
        if (!valid_type(type) || (content.empty() && type!=ContentType::application_data) || content.size()>16384 || padding>16384-content.size()) return std::unexpected(RecordError::invalid_input);
        if (legacy_) {
            if (padding) return std::unexpected(RecordError::invalid_input);
            return seal_tls12(type,content);
        }
        crypto::Bytes inner; inner.reserve(content.size()+1+padding);
        inner.insert(inner.end(),content.begin(),content.end());
        struct Cleanse { crypto::Bytes& bytes; ~Cleanse() { crypto::cleanse(bytes); } } cleanse{inner};
        inner.push_back(static_cast<std::uint8_t>(type)); inner.resize(inner.size()+padding,0);
        auto length=inner.size()+16;
        auto current_nonce=nonce(); advance(); active_=false;
        crypto::Bytes result(5+length);
        result[0]=23; result[1]=3; result[2]=3;
        result[3]=static_cast<std::uint8_t>(length>>8);
        result[4]=static_cast<std::uint8_t>(length);
        auto written=aead_->seal_to(std::span{result}.subspan(5),current_nonce,inner,std::span<std::uint8_t const>{result}.first(5));
        if (!written || *written!=length) { active_=false; return std::unexpected(RecordError::crypto_error); }
        active_=true;
        return result;
    }
    auto RecordLayer::open(std::span<std::uint8_t const> record) -> std::expected<PlaintextRecord,RecordError> {
        if (!active_ || !aead_ || direction_!=RecordDirection::receive) return std::unexpected(RecordError::invalid_state);
        if (legacy_) return open_tls12(record);
        auto fail=[this](RecordError e) -> std::expected<PlaintextRecord,RecordError> { active_=false; return std::unexpected(e); };
        if (record.size()<5 || record[0]!=23 || record[1]!=3 || record[2]!=3) return fail(RecordError::invalid_record);
        auto length=(std::size_t{record[3]}<<8)|record[4];
        if (length<17 || length>16640 || record.size()!=length+5) return fail(RecordError::invalid_record);
        auto current_nonce=nonce(); active_=false;
        crypto::Bytes inner(record.size()-5-16);
        auto written=aead_->open_to(inner,current_nonce,record.subspan(5),record.first(5));
        if (!written) return fail(written.error()==crypto::Error::authentication_failed ? RecordError::authentication_failed : RecordError::crypto_error);
        inner.resize(*written);
        if (inner.size()>16385) { crypto::cleanse(inner); return fail(RecordError::invalid_record); }
        while (!inner.empty() && inner.back()==0) inner.pop_back();
        if (inner.empty() || !valid_type(static_cast<ContentType>(inner.back()))) { crypto::cleanse(inner); return fail(RecordError::invalid_record); }
        auto type=static_cast<ContentType>(inner.back()); inner.pop_back();
        if (inner.empty() && type!=ContentType::application_data) return fail(RecordError::invalid_record);
        active_=true; advance();
        return PlaintextRecord{type,std::move(inner)};
    }
    auto RecordLayer::seal_into(ContentType type, std::span<std::uint8_t const> content, std::span<std::uint8_t> out)
        -> std::expected<std::size_t,RecordError> {
        if (!active_ || !aead_ || direction_!=RecordDirection::send) return std::unexpected(RecordError::invalid_state);
        if (sequence_>=send_limit_) return std::unexpected(RecordError::key_usage_limit);
        if (!valid_type(type) || (content.empty() && type!=ContentType::application_data) || content.size()>16384)
            return std::unexpected(RecordError::invalid_input);
        if (legacy_) return seal_tls12_into(type,content,out);
        auto const length=content.size()+17;
        auto const total=5+length;
        if (out.size()<total) return std::unexpected(RecordError::invalid_input);
        auto current_nonce=nonce(); advance(); active_=false;
        out[0]=23; out[1]=3; out[2]=3;
        out[3]=static_cast<std::uint8_t>(length>>8);
        out[4]=static_cast<std::uint8_t>(length);
        std::uint8_t const ct=static_cast<std::uint8_t>(type);
        auto written=aead_->seal_scatter_to(out.subspan(5,length),current_nonce,content,
            std::span<std::uint8_t const>{&ct,1},out.first(5));
        if (!written || *written!=length) { active_=false; return std::unexpected(RecordError::crypto_error); }
        active_=true;
        return total;
    }
    auto RecordLayer::open_into(std::span<std::uint8_t const> record, std::span<std::uint8_t> out)
        -> std::expected<OpenedRecord,RecordError> {
        if (!active_ || !aead_ || direction_!=RecordDirection::receive) return std::unexpected(RecordError::invalid_state);
        if (legacy_) return open_tls12_into(record,out);
        auto fail=[this](RecordError e) -> std::expected<OpenedRecord,RecordError> { active_=false; return std::unexpected(e); };
        if (record.size()<5 || record[0]!=23 || record[1]!=3 || record[2]!=3) return fail(RecordError::invalid_record);
        auto length=(std::size_t{record[3]}<<8)|record[4];
        if (length<17 || length>16640 || record.size()!=length+5) return fail(RecordError::invalid_record);
        auto const inner_cap=length-16;
        if (out.size()<inner_cap) return std::unexpected(RecordError::invalid_input);
        auto current_nonce=nonce(); active_=false;
        auto dst=out.first(inner_cap);
        auto written=aead_->open_to(dst,current_nonce,record.subspan(5),record.first(5));
        if (!written) return fail(written.error()==crypto::Error::authentication_failed ? RecordError::authentication_failed : RecordError::crypto_error);
        auto len=*written;
        if (len>16385) { crypto::cleanse(dst.first(len)); return fail(RecordError::invalid_record); }
        while (len>0 && dst[len-1]==0) --len;
        if (len==0 || !valid_type(static_cast<ContentType>(dst[len-1]))) {
            crypto::cleanse(dst.first(*written)); return fail(RecordError::invalid_record);
        }
        auto type=static_cast<ContentType>(dst[len-1]); --len;
        if (len==0 && type!=ContentType::application_data) {
            crypto::cleanse(dst.first(*written)); return fail(RecordError::invalid_record);
        }
        dst[len]=0;
        active_=true; advance();
        return OpenedRecord{type,len};
    }
    KtlsKeyMaterial::KtlsKeyMaterial(KtlsKeyMaterial&& other) noexcept
        : algorithm(other.algorithm), key(std::move(other.key)), iv(other.iv), sequence(other.sequence) {
        crypto::cleanse(other.iv); other.sequence = 0;
    }
    auto KtlsKeyMaterial::operator=(KtlsKeyMaterial&& other) noexcept -> KtlsKeyMaterial& {
        if (this != &other) {
            crypto::cleanse(key); crypto::cleanse(iv);
            algorithm = other.algorithm; key = std::move(other.key); iv = other.iv; sequence = other.sequence;
            crypto::cleanse(other.iv); other.sequence = 0;
        }
        return *this;
    }
    KtlsKeyMaterial::~KtlsKeyMaterial() { crypto::cleanse(key); crypto::cleanse(iv); }
    auto RecordLayer::export_ktls_material() -> std::optional<KtlsKeyMaterial> {
        if (!active_ || legacy_) return {};
        if (key_.size() != 16 && key_.size() != 32) return {};
        KtlsKeyMaterial out;
        out.algorithm = algorithm_;
        out.key = std::move(key_);
        out.iv = iv_;
        out.sequence = sequence_;
        active_ = false;
        aead_.reset();
        crypto::cleanse(key_);
        crypto::cleanse(iv_);
        sequence_ = 0;
        return out;
    }
}
