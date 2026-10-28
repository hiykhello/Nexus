module nexus.tls.record;
import std;

namespace nexus::tls {
    namespace {
        auto valid_type(ContentType t) -> bool { return t==ContentType::alert || t==ContentType::handshake || t==ContentType::application_data; }
    }
    RecordLayer::RecordLayer(crypto::Aead algorithm, crypto::Bytes key, std::array<std::uint8_t,12> iv, RecordDirection direction, std::uint64_t send_limit)
        : algorithm_(algorithm), key_(std::move(key)), iv_(iv), send_limit_(send_limit), direction_(direction) {}
    RecordLayer::~RecordLayer() { crypto::cleanse(key_); crypto::cleanse(iv_); }
    RecordLayer::RecordLayer(RecordLayer&& other) noexcept
        : algorithm_(other.algorithm_), key_(std::move(other.key_)), iv_(other.iv_), sequence_(other.sequence_), send_limit_(other.send_limit_), direction_(other.direction_), active_(other.active_) {
        other.active_=false; crypto::cleanse(other.iv_); crypto::cleanse(other.key_);
    }
    auto RecordLayer::operator=(RecordLayer&& other) noexcept -> RecordLayer& {
        if (this != &other) {
            crypto::cleanse(key_); crypto::cleanse(iv_);
            algorithm_=other.algorithm_; key_=std::move(other.key_); iv_=other.iv_; sequence_=other.sequence_; send_limit_=other.send_limit_; direction_=other.direction_; active_=other.active_;
            other.active_=false; crypto::cleanse(other.iv_); crypto::cleanse(other.key_);
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
        std::array<std::uint8_t,12> copy{}; std::ranges::copy(iv,copy.begin());
        return RecordLayer(algorithm,crypto::Bytes(key.begin(),key.end()),copy,direction,send_limit);
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
        if (!active_) return std::unexpected(RecordError::invalid_state);
        if (direction_!=RecordDirection::send) return std::unexpected(RecordError::invalid_state);
        if (sequence_>=send_limit_) return std::unexpected(RecordError::key_usage_limit);
        if (!valid_type(type) || (content.empty() && type!=ContentType::application_data) || content.size()>16384 || padding>16384-content.size()) return std::unexpected(RecordError::invalid_input);
        crypto::Bytes inner(content.begin(),content.end()); inner.push_back(static_cast<std::uint8_t>(type)); inner.resize(inner.size()+padding,0);
        auto length=inner.size()+16;
        std::array<std::uint8_t,5> header{23,3,3,static_cast<std::uint8_t>(length>>8),static_cast<std::uint8_t>(length)};
        auto current_nonce=nonce(); advance();
        auto encrypted=crypto::seal(algorithm_,key_,current_nonce,inner,header); crypto::cleanse(inner);
        if (!encrypted) { active_=false; return std::unexpected(RecordError::crypto_error); }
        crypto::Bytes result(header.begin(),header.end()); result.insert(result.end(),encrypted->begin(),encrypted->end());
        return result;
    }
    auto RecordLayer::open(std::span<std::uint8_t const> record) -> std::expected<PlaintextRecord,RecordError> {
        if (!active_ || direction_!=RecordDirection::receive) return std::unexpected(RecordError::invalid_state);
        auto fail=[this](RecordError e) -> std::expected<PlaintextRecord,RecordError> { active_=false; return std::unexpected(e); };
        if (record.size()<5 || record[0]!=23 || record[1]!=3 || record[2]!=3) return fail(RecordError::invalid_record);
        auto length=(std::size_t{record[3]}<<8)|record[4];
        if (length<17 || length>16640 || record.size()!=length+5) return fail(RecordError::invalid_record);
        auto current_nonce=nonce(); active_=false;
        auto inner=crypto::open(algorithm_,key_,current_nonce,record.subspan(5),record.first(5));
        if (!inner) return fail(inner.error()==crypto::Error::authentication_failed ? RecordError::authentication_failed : RecordError::crypto_error);
        if (inner->size()>16385) { crypto::cleanse(*inner); return fail(RecordError::invalid_record); }
        while (!inner->empty() && inner->back()==0) inner->pop_back();
        if (inner->empty() || !valid_type(static_cast<ContentType>(inner->back()))) { crypto::cleanse(*inner); return fail(RecordError::invalid_record); }
        auto type=static_cast<ContentType>(inner->back()); inner->pop_back();
        if (inner->empty() && type!=ContentType::application_data) return fail(RecordError::invalid_record);
        active_=true; advance();
        return PlaintextRecord{type,std::move(*inner)};
    }
}
