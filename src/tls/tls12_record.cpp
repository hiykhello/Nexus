module tls.record;
import std;

namespace tls {
    namespace {
        auto explicit_nonce(std::uint64_t sequence) noexcept -> std::array<std::uint8_t,8> {
            std::array<std::uint8_t,8> bytes{};
            for (std::size_t i=0;i<bytes.size();++i)
                bytes[bytes.size()-1-i]=static_cast<std::uint8_t>(sequence>>(8*i));
            return bytes;
        }

        auto legacy_aad(std::array<std::uint8_t,8> sequence,std::uint8_t type,std::size_t size)
            noexcept -> std::array<std::uint8_t,13> {
            std::array<std::uint8_t,13> result;
            std::ranges::copy(sequence,result.begin());
            result[8]=type;
            result[9]=3;
            result[10]=3;
            result[11]=static_cast<std::uint8_t>(size>>8);
            result[12]=static_cast<std::uint8_t>(size);
            return result;
        }
    }

    auto RecordLayer::create_tls12_gcm(RecordDirection direction,crypto::Aead algorithm,
        std::span<std::uint8_t const> key,std::span<std::uint8_t const,4> iv) -> std::expected<RecordLayer,RecordError> {
        if (algorithm!=crypto::Aead::aes_128_gcm && algorithm!=crypto::Aead::aes_256_gcm)
            return std::unexpected(RecordError::invalid_key);
        return create_tls12(direction,algorithm,key,iv);
    }

    auto RecordLayer::create_tls12(RecordDirection direction,crypto::Aead algorithm,
        std::span<std::uint8_t const> key,std::span<std::uint8_t const> iv) -> std::expected<RecordLayer,RecordError> {
        if (iv.size()!=(algorithm==crypto::Aead::chacha20_poly1305 ? 12u : 4u))
            return std::unexpected(RecordError::invalid_key);
        std::array<std::uint8_t,12> padded{};
        std::ranges::copy(iv,padded.begin());
        auto layer=create(direction,algorithm,key,padded);
        if (layer) layer->legacy_=true;
        return layer;
    }

    auto RecordLayer::seal_tls12(ContentType type,std::span<std::uint8_t const> content)
        -> std::expected<crypto::Bytes,RecordError> {
        auto counter=explicit_nonce(sequence_);
        auto explicit_size=tls12_overhead()-21;
        auto iv=nonce();
        if (explicit_size) std::ranges::copy(counter,iv.begin()+4);
        auto aad=legacy_aad(counter,static_cast<std::uint8_t>(type),content.size());
        advance();
        active_=false;
        auto cipher_size=content.size()+16;
        auto size=explicit_size+cipher_size;
        crypto::Bytes record(5+size);
        record[0]=static_cast<std::uint8_t>(type);
        record[1]=3;
        record[2]=3;
        record[3]=static_cast<std::uint8_t>(size>>8);
        record[4]=static_cast<std::uint8_t>(size);
        if (explicit_size) std::ranges::copy(counter.begin(),counter.begin()+explicit_size,record.begin()+5);
        auto written=aead_->seal_to(std::span{record}.subspan(5+explicit_size),iv,content,aad);
        if (!written || *written!=cipher_size) return std::unexpected(RecordError::crypto_error);
        active_=true;
        return record;
    }

    auto RecordLayer::open_tls12(std::span<std::uint8_t const> record) -> std::expected<PlaintextRecord,RecordError> {
        active_=false;
        auto overhead=tls12_overhead();
        if (record.size()<overhead || record.size()>overhead+16384 || record[1]!=3 || record[2]!=3 ||
            ((std::size_t{record[3]}<<8)|record[4])!=record.size()-5)
            return std::unexpected(RecordError::invalid_record);
        auto type=static_cast<ContentType>(record[0]);
        if ((type!=ContentType::application_data && type!=ContentType::handshake && type!=ContentType::alert) ||
            (record.size()==overhead && type!=ContentType::application_data))
            return std::unexpected(RecordError::invalid_record);
        auto iv=nonce();
        auto explicit_size=overhead-21;
        if (explicit_size) std::ranges::copy(record.subspan(5,explicit_size),iv.begin()+4);
        auto aad=legacy_aad(explicit_nonce(sequence_),record[0],record.size()-overhead);
        auto ciphertext=record.subspan(5+explicit_size);
        crypto::Bytes plain(ciphertext.size()-16);
        auto written=aead_->open_to(plain,iv,ciphertext,aad);
        if (!written)
            return std::unexpected(written.error()==crypto::Error::authentication_failed ? RecordError::authentication_failed : RecordError::crypto_error);
        plain.resize(*written);
        active_=true;
        advance();
        return PlaintextRecord{type,std::move(plain)};
    }

    auto RecordLayer::seal_tls12_into(ContentType type,std::span<std::uint8_t const> content,std::span<std::uint8_t> out)
        -> std::expected<std::size_t,RecordError> {
        auto explicit_size=tls12_overhead()-21;
        auto cipher_size=content.size()+16;
        auto size=explicit_size+cipher_size;
        auto total=5+size;
        if (out.size()<total) return std::unexpected(RecordError::invalid_input);
        auto counter=explicit_nonce(sequence_);
        auto iv=nonce();
        if (explicit_size) std::ranges::copy(counter,iv.begin()+4);
        auto aad=legacy_aad(counter,static_cast<std::uint8_t>(type),content.size());
        advance();
        active_=false;
        out[0]=static_cast<std::uint8_t>(type);
        out[1]=3;
        out[2]=3;
        out[3]=static_cast<std::uint8_t>(size>>8);
        out[4]=static_cast<std::uint8_t>(size);
        if (explicit_size) std::ranges::copy(counter.begin(),counter.begin()+explicit_size,out.begin()+5);
        auto written=aead_->seal_to(out.subspan(5+explicit_size,cipher_size),iv,content,aad);
        if (!written || *written!=cipher_size) return std::unexpected(RecordError::crypto_error);
        active_=true;
        return total;
    }

    auto RecordLayer::open_tls12_into(std::span<std::uint8_t const> record,std::span<std::uint8_t> out)
        -> std::expected<OpenedRecord,RecordError> {
        auto overhead=tls12_overhead();
        if (record.size()<overhead || record.size()>overhead+16384 || record[1]!=3 || record[2]!=3 ||
            ((std::size_t{record[3]}<<8)|record[4])!=record.size()-5) {
            active_=false; return std::unexpected(RecordError::invalid_record);
        }
        auto type=static_cast<ContentType>(record[0]);
        if ((type!=ContentType::application_data && type!=ContentType::handshake && type!=ContentType::alert) ||
            (record.size()==overhead && type!=ContentType::application_data)) {
            active_=false; return std::unexpected(RecordError::invalid_record);
        }
        auto explicit_size=overhead-21;
        auto ciphertext=record.subspan(5+explicit_size);
        auto plain_cap=ciphertext.size()-16;
        if (out.size()<plain_cap) return std::unexpected(RecordError::invalid_input);
        active_=false;
        auto iv=nonce();
        if (explicit_size) std::ranges::copy(record.subspan(5,explicit_size),iv.begin()+4);
        auto aad=legacy_aad(explicit_nonce(sequence_),record[0],record.size()-overhead);
        auto written=aead_->open_to(out.first(plain_cap),iv,ciphertext,aad);
        if (!written)
            return std::unexpected(written.error()==crypto::Error::authentication_failed ? RecordError::authentication_failed : RecordError::crypto_error);
        active_=true;
        advance();
        return OpenedRecord{type,*written};
    }
}
