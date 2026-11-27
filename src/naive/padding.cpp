module;
#include <string.h>

module naive.padding;
import std;
import crypto;
import encoding.base64;
import http.connect;
import http.header;
import socks5;

namespace naive {
    namespace {
        constexpr std::string_view kPaddingChars =
            "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";

        auto append_frame(std::vector<std::uint8_t>& out, std::span<std::uint8_t const> chunk, std::uint8_t pad_len) -> void {
            auto const old = out.size();
            out.resize(old + 3 + chunk.size() + pad_len);
            out[old] = static_cast<std::uint8_t>((chunk.size() >> 8) & 0xffu);
            out[old + 1] = static_cast<std::uint8_t>(chunk.size() & 0xffu);
            out[old + 2] = pad_len;
            if (!chunk.empty()) std::ranges::copy(chunk, out.begin() + static_cast<std::ptrdiff_t>(old + 3));
            if (pad_len) std::fill_n(out.begin() + static_cast<std::ptrdiff_t>(old + 3 + chunk.size()), pad_len, 0);
        }

        auto random_pad_len(std::size_t payload_len) -> std::uint8_t {
            std::array<std::uint8_t, 2> r{};
            (void)crypto::random_bytes(r);
            if (payload_len < kPaddingThreshold) {
                std::size_t lo = 255 - payload_len;
                std::size_t span = 255 - lo + 1;
                return static_cast<std::uint8_t>(lo + (r[0] % span));
            }
            return static_cast<std::uint8_t>(r[0] % 65u);
        }
    }

    UserCredential::~UserCredential() {
        if (!username.empty())
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(username.data()), username.size()));
        if (!password.empty())
            crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(password.data()), password.size()));
    }

    auto generate_padding_header() -> std::string {
        std::array<std::uint8_t, 33> rnd{};
        (void)crypto::random_bytes(rnd);
        std::size_t len = 16 + (rnd[0] % 17u);
        std::string out;
        out.reserve(len);
        for (std::size_t i = 0; i < len; ++i)
            out.push_back(kPaddingChars[rnd[i + 1] % kPaddingChars.size()]);
        return out;
    }

    auto make_basic_auth(std::string_view user, std::string_view pass) -> std::string {
        std::string raw;
        raw.reserve(user.size() + 1 + pass.size());
        raw.append(user);
        raw.push_back(':');
        raw.append(pass);
        auto b64 = encoding::encode_base64(std::span<std::uint8_t const>(
            reinterpret_cast<std::uint8_t const*>(raw.data()), raw.size()));
        crypto::cleanse(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(raw.data()), raw.size()));
        return "Basic " + std::move(b64);
    }

    namespace {
        auto hash_username(std::span<std::uint8_t const> u, std::uint64_t seed) noexcept -> std::uint64_t {
            std::uint64_t h = seed ^ 0xcbf29ce484222325ULL;
            for (auto b : u) { h ^= b; h *= 0x100000001b3ULL; }
            h ^= h >> 30; h *= 0xbf58476d1ce4e5b9ULL;
            h ^= h >> 27; h *= 0x94d049bb133111ebULL;
            return h ^ (h >> 31);
        }

        auto verify_basic_impl(std::string_view header, std::span<UserCredential const> users,
                               UserIndex const* index) noexcept -> std::optional<std::string_view> {
            auto trimmed = http::trim_header_ows(header);
            if (trimmed.size() < 6) return std::nullopt;
            auto ci = [](char a, char b) {
                return a == b || (a >= 'A' && a <= 'Z' && static_cast<char>(a - 'A' + 'a') == b);
            };
            if (!std::ranges::equal(trimmed.substr(0, 5), std::string_view("basic"), ci) || trimmed[5] != ' ')
                return std::nullopt;
            auto token = http::trim_header_ows(trimmed.substr(6));
            if (token.empty() || token.size() > 1024) return std::nullopt;
            std::array<std::uint8_t, 768> decoded{};
            struct Clean {
                std::array<std::uint8_t, 768>& buf;
                ~Clean() { crypto::cleanse(buf); }
            } clean{decoded};
            auto decoded_len = encoding::decode_base64_strict(token, std::span(decoded));
            if (!decoded_len) return std::nullopt;
            auto payload = std::span<std::uint8_t const>(decoded.data(), *decoded_len);
            auto colon = std::ranges::find(payload, static_cast<std::uint8_t>(':'));
            if (colon == payload.end()) return std::nullopt;
            auto u = payload.first(static_cast<std::size_t>(colon - payload.begin()));
            auto p = payload.subspan(u.size() + 1);
            if (index && !index->empty()) return index->verify(users, u, p);
            std::optional<std::string_view> matched;
            for (auto const& user : users) {
                auto eu = std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(user.username.data()), user.username.size());
                auto ep = std::span<std::uint8_t const>(reinterpret_cast<std::uint8_t const*>(user.password.data()), user.password.size());
                bool u_ok = (u.size() == eu.size()) && crypto::constant_time_equal(u, eu);
                bool p_ok = (p.size() == ep.size()) && crypto::constant_time_equal(p, ep);
                if (u_ok && p_ok && !matched) matched = user.name;
            }
            return matched;
        }
    }

    UserIndex::UserIndex(std::span<UserCredential const> users) {
        if (users.empty()) return;
        seed_ = 0x517cc1b727220a95ULL;
        (void)crypto::random_bytes(std::span<std::uint8_t>(reinterpret_cast<std::uint8_t*>(&seed_), sizeof(seed_)));
        std::size_t cap = 4;
        while (cap < users.size() * 2) cap <<= 1;
        buckets_.assign(cap, kEmpty);
        std::size_t const mask = cap - 1;
        for (std::size_t i = 0; i < users.size(); ++i) {
            auto eu = std::span<std::uint8_t const>(
                reinterpret_cast<std::uint8_t const*>(users[i].username.data()), users[i].username.size());
            auto slot = static_cast<std::size_t>(hash_username(eu, seed_)) & mask;
            while (buckets_[slot] != kEmpty) slot = (slot + 1) & mask;
            buckets_[slot] = static_cast<std::uint32_t>(i);
        }
    }

    auto UserIndex::verify(std::span<UserCredential const> users,
                           std::span<std::uint8_t const> username,
                           std::span<std::uint8_t const> password) const noexcept
        -> std::optional<std::string_view> {
        if (buckets_.empty() || users.empty()) return std::nullopt;
        std::size_t const mask = buckets_.size() - 1;
        auto slot = static_cast<std::size_t>(hash_username(username, seed_)) & mask;
        std::optional<std::string_view> matched;
        while (buckets_[slot] != kEmpty) {
            auto const idx = buckets_[slot];
            if (idx < users.size()) {
                auto const& user = users[idx];
                auto eu = std::span<std::uint8_t const>(
                    reinterpret_cast<std::uint8_t const*>(user.username.data()), user.username.size());
                auto ep = std::span<std::uint8_t const>(
                    reinterpret_cast<std::uint8_t const*>(user.password.data()), user.password.size());
                bool u_ok = (username.size() == eu.size()) && crypto::constant_time_equal(username, eu);
                bool p_ok = (password.size() == ep.size()) && crypto::constant_time_equal(password, ep);
                if (u_ok && p_ok && !matched) matched = user.name;
            }
            slot = (slot + 1) & mask;
        }
        return matched;
    }

    auto verify_basic_auth(std::string_view header, std::span<UserCredential const> users) noexcept
        -> std::optional<std::string_view> {
        return verify_basic_impl(header, users, nullptr);
    }

    auto verify_basic_auth(std::string_view header, std::span<UserCredential const> users,
                           UserIndex const& index) noexcept
        -> std::optional<std::string_view> {
        return verify_basic_impl(header, users, &index);
    }

    auto parse_padding_type_request(std::string_view value) noexcept -> bool {
        while (!value.empty()) {
            auto comma = value.find(',');
            auto token = http::trim_header_ows(comma == std::string_view::npos ? value : value.substr(0, comma));
            if (token == "1") return true;
            if (comma == std::string_view::npos) break;
            value.remove_prefix(comma + 1);
        }
        return false;
    }

    auto parse_padding_type_reply(std::string_view value) noexcept -> bool {
        return http::trim_header_ows(value) == "1";
    }

    auto parse_connect_authority(std::string_view authority) -> std::optional<socks5::Request> {
        if (authority.empty() || authority.size() > 300) return std::nullopt;
        auto parsed = http::parse_destination_authority(authority);
        if (parsed.status != http::ConnectStatus::accepted || !parsed.port) return std::nullopt;
        socks5::Request req{};
        req.status = socks5::Status::accepted;
        req.port = parsed.port;
        if (parsed.kind == http::HostKind::domain) {
            if (parsed.host.size() > 255) return std::nullopt;
            req.address_type = 3;
            req.address_length = static_cast<std::uint8_t>(parsed.host.size());
            std::ranges::copy(parsed.host, req.address.begin());
        } else if (parsed.kind == http::HostKind::ipv4) {
            req.address_type = 1;
            req.address_length = 4;
            std::copy_n(parsed.address.begin(), 4, req.address.begin());
        } else {
            req.address_type = 4;
            req.address_length = 16;
            std::copy_n(parsed.address.begin(), 16, req.address.begin());
        }
        return req;
    }

    auto decoy_html_body(std::uint16_t status) noexcept -> std::string_view {
        if (status == 200)
            return "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>\n";
        return "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n";
    }

    auto PaddingEncoder::encode(std::span<std::uint8_t const> payload, std::vector<std::uint8_t>& out) -> bool {
        if (in_passthrough()) {
            out.insert(out.end(), payload.begin(), payload.end());
            return true;
        }
        if (payload.empty()) {
            append_frame(out, {}, random_pad_len(0));
            ++frames_sent_;
            return true;
        }
        while (!payload.empty() && frames_sent_ < kFirstPaddings) {
            auto chunk = payload.first(std::min(payload.size(), kMaxPaddingPayload));
            append_frame(out, chunk, random_pad_len(chunk.size()));
            ++frames_sent_;
            payload = payload.subspan(chunk.size());
        }
        if (!payload.empty()) out.insert(out.end(), payload.begin(), payload.end());
        return true;
    }

    auto PaddingEncoder::encode_with_pad_len(std::span<std::uint8_t const> payload, std::uint8_t pad_len,
                                             std::vector<std::uint8_t>& out) -> bool {
        if (in_passthrough()) {
            out.insert(out.end(), payload.begin(), payload.end());
            return true;
        }
        if (payload.empty()) {
            append_frame(out, {}, pad_len);
            ++frames_sent_;
            return true;
        }
        while (!payload.empty() && frames_sent_ < kFirstPaddings) {
            auto chunk = payload.first(std::min(payload.size(), kMaxPaddingPayload));
            append_frame(out, chunk, pad_len);
            ++frames_sent_;
            payload = payload.subspan(chunk.size());
        }
        if (!payload.empty()) out.insert(out.end(), payload.begin(), payload.end());
        return true;
    }

    auto PaddingDecoder::finish_frame() noexcept -> void {
        if (frames_received_ < kFirstPaddings) ++frames_received_;
        state_ = (frames_received_ >= kFirstPaddings) ? State::passthrough : State::header_hi;
    }

    auto PaddingDecoder::feed(std::span<std::uint8_t const> in, std::vector<std::uint8_t>& out) -> bool {
        while (!in.empty()) {
            switch (state_) {
            case State::passthrough:
                out.insert(out.end(), in.begin(), in.end());
                return true;
            case State::header_hi:
                hi_ = in.front();
                in = in.subspan(1);
                state_ = State::header_lo;
                break;
            case State::header_lo:
                remaining_payload_ = (static_cast<std::size_t>(hi_) << 8) | in.front();
                in = in.subspan(1);
                state_ = State::pad_len;
                break;
            case State::pad_len:
                remaining_pad_ = in.front();
                in = in.subspan(1);
                if (remaining_payload_ > 0) state_ = State::payload;
                else if (remaining_pad_ > 0) state_ = State::padding;
                else finish_frame();
                break;
            case State::payload: {
                auto take = std::min(remaining_payload_, in.size());
                out.insert(out.end(), in.begin(), in.begin() + static_cast<std::ptrdiff_t>(take));
                in = in.subspan(take);
                remaining_payload_ -= take;
                if (remaining_payload_ == 0) {
                    if (remaining_pad_ > 0) state_ = State::padding;
                    else finish_frame();
                }
                break;
            }
            case State::padding: {
                auto take = std::min(remaining_pad_, in.size());
                in = in.subspan(take);
                remaining_pad_ -= take;
                if (remaining_pad_ == 0) finish_frame();
                break;
            }
            }
        }
        return true;
    }
}
