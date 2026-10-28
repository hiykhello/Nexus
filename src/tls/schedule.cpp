module nexus.tls.schedule;
import std;

namespace nexus::tls {
    Secret::~Secret() { crypto::cleanse(bytes_); }
    Secret::Secret(Secret&& other) noexcept : bytes_(std::move(other.bytes_)) {}
    auto Secret::operator=(Secret&& other) noexcept -> Secret& {
        if (this != &other) { crypto::cleanse(bytes_); bytes_=std::move(other.bytes_); }
        return *this;
    }
    namespace {
        auto hash_size(crypto::Hash hash) -> std::optional<std::size_t> {
            switch (hash) { case crypto::Hash::sha256: return 32; case crypto::Hash::sha384: return 48; }
            return {};
        }
        auto wrap(std::expected<crypto::Bytes,crypto::Error> result) -> std::expected<Secret,crypto::Error> {
            if (!result) return std::unexpected(result.error());
            return Secret(std::move(*result));
        }
        auto next(crypto::Hash hash, std::span<std::uint8_t const> previous,
                  std::span<std::uint8_t const> ikm) -> std::expected<Secret,crypto::Error> {
            auto empty_hash=crypto::digest(hash,{});
            if (!empty_hash) return std::unexpected(empty_hash.error());
            auto derived=derive_secret(hash,previous,"derived",*empty_hash);
            if (!derived) return std::unexpected(derived.error());
            return wrap(crypto::hkdf_extract(hash,derived->view(),ikm));
        }
    }
    auto expand_label(crypto::Hash hash, std::span<std::uint8_t const> secret, std::string_view label,
                      std::span<std::uint8_t const> context, std::size_t length) -> std::expected<Secret,crypto::Error> {
        if (!hash_size(hash)) return std::unexpected(crypto::Error::unsupported_algorithm);
        if (label.empty() || label.size()>249 || context.size()>255 || length>65535) return std::unexpected(crypto::Error::invalid_length);
        crypto::Bytes info;
        info.reserve(2+1+6+label.size()+1+context.size());
        info.push_back(static_cast<std::uint8_t>(length>>8)); info.push_back(static_cast<std::uint8_t>(length));
        info.push_back(static_cast<std::uint8_t>(6+label.size()));
        constexpr std::string_view prefix="tls13 ";
        info.insert(info.end(),prefix.begin(),prefix.end()); info.insert(info.end(),label.begin(),label.end());
        info.push_back(static_cast<std::uint8_t>(context.size())); info.insert(info.end(),context.begin(),context.end());
        return wrap(crypto::hkdf_expand(hash,secret,info,length));
    }
    auto derive_secret(crypto::Hash hash, std::span<std::uint8_t const> secret, std::string_view label,
                       std::span<std::uint8_t const> transcript_hash) -> std::expected<Secret,crypto::Error> {
        auto size=hash_size(hash); if (!size) return std::unexpected(crypto::Error::unsupported_algorithm);
        if (secret.size()!=*size || transcript_hash.size()!=*size) return std::unexpected(crypto::Error::invalid_length);
        return expand_label(hash,secret,label,transcript_hash,*size);
    }
    auto early_secret(crypto::Hash hash, std::optional<std::span<std::uint8_t const>> psk) -> std::expected<Secret,crypto::Error> {
        auto size=hash_size(hash); if (!size) return std::unexpected(crypto::Error::unsupported_algorithm);
        if (psk && psk->empty()) return std::unexpected(crypto::Error::invalid_length);
        crypto::Bytes zeros(*size);
        return wrap(crypto::hkdf_extract(hash,zeros,psk ? *psk : std::span<std::uint8_t const>(zeros)));
    }
    auto handshake_secret(crypto::Hash hash, std::span<std::uint8_t const> early, std::span<std::uint8_t const> shared)
        -> std::expected<Secret,crypto::Error> {
        if (shared.empty()) return std::unexpected(crypto::Error::invalid_length);
        return next(hash,early,shared);
    }
    auto master_secret(crypto::Hash hash, std::span<std::uint8_t const> handshake) -> std::expected<Secret,crypto::Error> {
        auto size=hash_size(hash); if (!size) return std::unexpected(crypto::Error::unsupported_algorithm);
        crypto::Bytes zeros(*size); return next(hash,handshake,zeros);
    }
    auto finished_verify_data(crypto::Hash hash, std::span<std::uint8_t const> traffic_secret,
                              std::span<std::uint8_t const> transcript_hash) -> std::expected<Secret,crypto::Error> {
        auto size=hash_size(hash); if (!size) return std::unexpected(crypto::Error::unsupported_algorithm);
        if (traffic_secret.size()!=*size || transcript_hash.size()!=*size) return std::unexpected(crypto::Error::invalid_length);
        auto key=expand_label(hash,traffic_secret,"finished",{},*size);
        if (!key) return std::unexpected(key.error());
        return wrap(crypto::hmac(hash,key->view(),transcript_hash));
    }
}
