module control_api.ssmapi_bridge;
import std;
import relay;
import blake3;
import crypto;
import encoding.base64_key;
import encoding.json;
import glaze;
import control_api.ssmapi;

namespace control_api {
    namespace detail {
        struct SsmBridgeWire {
            std::string username;
            std::string uPSK;
            bool enabled = true;
            std::uint64_t byteQuota = 0;
            ~SsmBridgeWire() {
                if (!uPSK.empty()) {
                    crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(uPSK.data()), uPSK.size()));
                    uPSK.clear();
                }
            }
        };
    }
    namespace {
        auto decode_ss2022_psk(std::string_view b64, std::array<std::uint8_t, 32>& key, std::uint8_t& len,
            std::array<std::uint8_t, 16>& hash) noexcept -> bool {
            std::span<char const> in(b64.data(), b64.size());
            if (encoding::decode_key(in, std::span(key).first<16>())) len = 16;
            else if (encoding::decode_key(in, std::span(key).first<32>())) len = 32;
            else return false;
            struct HashGuard {
                blake3::blake3_hasher h{};
                ~HashGuard() { crypto::cleanse(std::span{reinterpret_cast<std::uint8_t*>(&h), sizeof(h)}); }
            } hg;
            blake3::blake3_hasher_init(&hg.h);
            blake3::blake3_hasher_update(&hg.h, key.data(), len);
            blake3::blake3_hasher_finalize(&hg.h, hash.data(), hash.size());
            return true;
        }
    }

    struct SsmApiBridge::Impl {
        ssmapi::UserStore store;
        std::shared_ptr<relay::ShadowsocksUserDirectory> users;

        auto sync_stats() -> void {
            if (!users) return;
            users->drain_stats([&](std::string_view name, relay::ShadowsocksDynamicUser::StatDelta const& d) {
                if (d.up_bytes || d.down_bytes || d.up_packets || d.down_packets)
                    (void)store.record_traffic(name, d.up_bytes, d.down_bytes, d.up_packets, d.down_packets);
                (void)store.set_sessions(name, d.tcp_sessions, d.udp_sessions);
            });
        }
    };

    SsmApiBridge::SsmApiBridge() : impl_(std::make_unique<Impl>()) {}
    SsmApiBridge::~SsmApiBridge() = default;
    SsmApiBridge::SsmApiBridge(SsmApiBridge&&) noexcept = default;
    auto SsmApiBridge::operator=(SsmApiBridge&&) noexcept -> SsmApiBridge& = default;
    auto SsmApiBridge::attach_users(std::shared_ptr<relay::ShadowsocksUserDirectory> users) noexcept -> void {
        if (impl_) impl_->users = std::move(users);
    }

    auto SsmApiBridge::dispatch(std::string_view prefix, std::string_view method,
        std::string_view target, std::string_view body) -> std::optional<std::pair<int, std::string>> {
        if (!impl_ || prefix.empty()) return std::nullopt;
        auto q = target.find('?');
        auto path = q == std::string_view::npos ? target : target.substr(0, q);
        if (!path.starts_with(prefix)) return std::nullopt;
        auto rest = path.substr(prefix.size());
        if (!rest.empty() && !rest.starts_with('/')) return std::nullopt;
        std::string rewritten = "/v1/ssmapi";
        rewritten += rest;
        constexpr std::string_view uprefix = "/v1/ssmapi/users/";
        struct KeyWipe { std::array<std::uint8_t, 32> k{}; ~KeyWipe() { crypto::cleanse(k); } } kw;
        std::uint8_t klen = 0;
        std::array<std::uint8_t, 16> khash{};
        std::string prechecked_name;
        bool has_key = false;
        bool is_write = (method == "POST" && rewritten == "/v1/ssmapi/users") ||
            (method == "PUT" && rewritten.starts_with(uprefix) && rewritten.size() > uprefix.size());
        if (impl_->users && is_write) {
            detail::SsmBridgeWire wire{};
            if (glaze::read<glaze::opts{.error_on_unknown_keys = false}>(wire, body))
                return std::pair{400, std::string("{\"error\":\"invalid JSON body\"}")};
            if (!decode_ss2022_psk(wire.uPSK, kw.k, klen, khash))
                return std::pair{400, std::string("{\"error\":\"invalid ss2022 uPSK\"}")};
            prechecked_name = method == "PUT" ? rewritten.substr(uprefix.size()) : wire.username;
            has_key = true;
        }
        if (method == "GET" || method == "PUT") impl_->sync_stats();
        auto res = ssmapi::handle_http_request(impl_->store, method, rewritten, body);
        if (impl_->users) {
            if (method == "DELETE" && res.status == 204 && rewritten.starts_with(uprefix) && rewritten.size() > uprefix.size()) {
                (void)impl_->users->remove(rewritten.substr(uprefix.size()));
            } else if ((method == "POST" || method == "PUT") && (res.status == 200 || res.status == 201)) {
                impl_->sync_stats();
                auto name_it = !prechecked_name.empty() ? std::string_view(prechecked_name) :
                    (rewritten.starts_with(uprefix) ? std::string_view(rewritten).substr(uprefix.size()) : std::string_view{});
                std::optional<ssmapi::UserRecord> rec;
                if (!name_it.empty()) rec = impl_->store.get_user(name_it);
                else {
                    auto listed = impl_->store.list_users();
                    for (auto& u : listed) {
                        if (!rec && res.json.contains("\"username\":" + encoding::json_quote(u.username))) rec = std::move(u);
                        else crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(u.u_psk.data()), u.u_psk.size()));
                    }
                }
                if (rec) {
                    if (has_key || decode_ss2022_psk(rec->u_psk, kw.k, klen, khash)) {
                        impl_->users->upsert(rec->username, std::span(kw.k.data(), klen), khash, rec->enabled,
                            rec->byte_quota, rec->uplink_bytes, rec->downlink_bytes);
                    }
                    crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(rec->u_psk.data()), rec->u_psk.size()));
                }
            }
        }
        return std::pair{res.status, std::move(res.json)};
    }

    auto ssmapi_available() noexcept -> bool { return true; }
}
