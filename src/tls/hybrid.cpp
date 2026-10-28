module nexus.tls.hybrid;
import std;

namespace nexus::tls {
    HybridSecret::~HybridSecret() { crypto::cleanse(bytes_); }
    HybridSecret::HybridSecret(HybridSecret&& other) noexcept : bytes_(other.bytes_) { crypto::cleanse(other.bytes_); }
    auto HybridSecret::operator=(HybridSecret&& other) noexcept -> HybridSecret& {
        if (this!=&other) { crypto::cleanse(bytes_); bytes_=other.bytes_; crypto::cleanse(other.bytes_); } return *this;
    }
    HybridClient::HybridClient(crypto::Mlkem768Private&& kem,crypto::X25519Private&& x25519) noexcept
        : kem_(std::move(kem)), x25519_(std::move(x25519)) {}
    HybridClient::HybridClient(HybridClient&& other) noexcept : kem_(std::move(other.kem_)), x25519_(std::move(other.x25519_)) {
        other.kem_.reset(); other.x25519_.reset();
    }
    auto HybridClient::operator=(HybridClient&& other) noexcept -> HybridClient& {
        if (this!=&other) { kem_=std::move(other.kem_); x25519_=std::move(other.x25519_); other.kem_.reset(); other.x25519_.reset(); } return *this;
    }
    auto HybridClient::generate() -> std::expected<HybridClient,HybridError> {
        auto kem=crypto::Mlkem768Private::generate(); auto x=crypto::X25519Private::generate();
        if (!kem || !x) return std::unexpected(HybridError::crypto_error); return HybridClient(std::move(*kem),std::move(*x));
    }
    auto HybridClient::from_keys(crypto::Mlkem768Private&& kem,crypto::X25519Private&& x) -> HybridClient { return HybridClient(std::move(kem),std::move(x)); }
    auto HybridClient::share() const -> std::expected<std::array<std::uint8_t,1216>,HybridError> {
        if (!kem_ || !x25519_) return std::unexpected(HybridError::invalid_state);
        auto kem=kem_->public_key(); auto x=x25519_->public_key();
        if (!kem || !x) return std::unexpected(HybridError::invalid_state);
        std::array<std::uint8_t,1216> result{}; std::ranges::copy(*kem,result.begin()); std::ranges::copy(*x,result.begin()+1184); return result;
    }
    auto HybridClient::finish(std::span<std::uint8_t const> share) -> std::expected<HybridSecret,HybridError> {
        if (!kem_ || !x25519_) return std::unexpected(HybridError::invalid_state);
        auto kem=std::move(*kem_); auto x=std::move(*x25519_); kem_.reset(); x25519_.reset();
        if (share.size()!=1120) return std::unexpected(HybridError::invalid_share);
        auto dh=x.agree(share.subspan(1088)); if (!dh) return std::unexpected(HybridError::invalid_public_key);
        auto pq=kem.decapsulate(share.first(1088)); if (!pq) return std::unexpected(HybridError::crypto_error);
        HybridSecret result; std::ranges::copy(pq->view(),result.bytes_.begin()); std::ranges::copy(dh->view(),result.bytes_.begin()+32); return result;
    }
    auto hybrid_server_accept(std::span<std::uint8_t const> share,crypto::X25519Private&& private_key) -> std::expected<HybridServerResult,HybridError> {
        auto x=std::move(private_key);
        if (share.size()!=1216) return std::unexpected(HybridError::invalid_share);
        auto public_key=x.public_key(); if (!public_key) return std::unexpected(HybridError::invalid_state);
        auto dh=x.agree(share.subspan(1184)); if (!dh) return std::unexpected(HybridError::invalid_public_key);
        auto pq=crypto::mlkem768_encapsulate(share.first(1184));
        if (!pq) return std::unexpected(pq.error()==crypto::MlkemError::invalid_key ? HybridError::invalid_public_key : HybridError::crypto_error);
        HybridServerResult result; std::ranges::copy(pq->ciphertext,result.share.begin()); std::ranges::copy(*public_key,result.share.begin()+1088);
        std::ranges::copy(pq->secret.view(),result.secret.bytes_.begin()); std::ranges::copy(dh->view(),result.secret.bytes_.begin()+32); return result;
    }
}
