module crypto.ecdh;
import crypto.backend_errors;
import std;

namespace crypto {
    using namespace nex::boringssl;
    EcSecret::~EcSecret() { cleanse(bytes_); }
    EcSecret::EcSecret(EcSecret&& other) noexcept : bytes_(other.bytes_),size_(other.size_) { cleanse(other.bytes_); other.size_=0; }
    auto EcSecret::operator=(EcSecret&& other) noexcept -> EcSecret& {
        if (this!=&other) { cleanse(bytes_); bytes_=other.bytes_; size_=other.size_; cleanse(other.bytes_); other.size_=0; } return *this;
    }
    EcPrivate::~EcPrivate() { EC_KEY_free(key_); }
    EcPrivate::EcPrivate(EcPrivate&& other) noexcept : key_(std::exchange(other.key_,nullptr)) {}
    auto EcPrivate::operator=(EcPrivate&& other) noexcept -> EcPrivate& {
        if (this!=&other) { EC_KEY_free(key_); key_=std::exchange(other.key_,nullptr); } return *this;
    }
    auto EcPrivate::generate(std::uint16_t group) -> std::expected<EcPrivate,Error> {
        auto curve=nist_curve(group); if (!curve) return std::unexpected(Error::unsupported_algorithm);
        EcPrivate key(EC_KEY_new_by_curve_name(curve->nid));
        if (!key.key_ || EC_KEY_generate_key(key.key_)!=1) return std::unexpected(Error::backend_failure);
        return key;
    }
    auto EcPrivate::group() const noexcept -> std::uint16_t {
        if (!key_) return 0;
        auto nid=EC_GROUP_get_curve_name(EC_KEY_get0_group(key_));
        for (auto group:{23,24,25}) if (nist_curve(group)->nid==nid) return static_cast<std::uint16_t>(group);
        return 0;
    }
    auto EcPrivate::public_key() const -> std::expected<EcPublic,Error> {
        auto curve=nist_curve(group()); if (!curve) return std::unexpected(Error::invalid_state);
        EcPublic result;
        auto count=EC_POINT_point2oct(EC_KEY_get0_group(key_),EC_KEY_get0_public_key(key_),point_conversion_uncompressed,result.bytes.data(),result.bytes.size(),nullptr);
        if (count!=curve->public_size()) return std::unexpected(Error::backend_failure);
        result.size=static_cast<std::uint8_t>(count); return result;
    }
    auto EcPrivate::agree(std::span<std::uint8_t const> peer) const -> std::expected<EcSecret,Error> {
        auto curve=nist_curve(group()); if (!curve) return std::unexpected(Error::invalid_state);
        if (peer.size()!=curve->public_size() || peer[0]!=4) return std::unexpected(Error::invalid_peer);
        BackendErrors backend_errors;
        auto group=EC_KEY_get0_group(key_);
        auto point=std::unique_ptr<EC_POINT,decltype(&EC_POINT_free)>(EC_POINT_new(group),&EC_POINT_free);
        if (!point) return std::unexpected(Error::backend_failure);
        if (EC_POINT_oct2point(group,point.get(),peer.data(),peer.size(),nullptr)!=1 ||
            EC_POINT_is_at_infinity(group,point.get()) || EC_POINT_is_on_curve(group,point.get(),nullptr)!=1) return std::unexpected(backend_errors.allocation_failed() ? Error::backend_failure : Error::invalid_peer);
        EcSecret result;
        auto count=ECDH_compute_key(result.bytes_.data(),curve->coordinate_size,point.get(),key_,nullptr);
        if (count!=curve->coordinate_size) return std::unexpected(Error::backend_failure);
        result.size_=curve->coordinate_size; return result;
    }
}
