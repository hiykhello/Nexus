module tuic.wire;
import std;
import crypto;
import tls.schedule;

namespace tuic {
    namespace {
        auto write_u16(std::uint8_t* dst, std::uint16_t value) noexcept -> void {
            dst[0] = static_cast<std::uint8_t>(value >> 8);
            dst[1] = static_cast<std::uint8_t>(value);
        }
        auto read_u16(std::span<std::uint8_t const> src) noexcept -> std::uint16_t {
            return static_cast<std::uint16_t>((static_cast<std::uint16_t>(src[0]) << 8) | src[1]);
        }
        auto valid_header_version_cmd(std::span<std::uint8_t const> input, Command expected) noexcept -> WireError {
            if (input.size() < 2) return WireError::incomplete;
            if (input[0] != version) return WireError::unsupported_version;
            if (input[1] != static_cast<std::uint8_t>(expected)) return WireError::unsupported_command;
            return static_cast<WireError>(-1);
        }
    }

    auto parse_uuid(std::string_view text) noexcept -> std::optional<std::array<std::uint8_t, 16>> {
        if (text.size() != 36) return std::nullopt;
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        std::array<std::uint8_t, 16> out{};
        std::size_t j = 0;
        for (std::size_t i = 0; i < 36;) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (text[i++] != '-') return std::nullopt;
                continue;
            }
            if (i + 1 >= 36 || j >= 16) return std::nullopt;
            int hi = hex(text[i++]);
            int lo = hex(text[i++]);
            if (hi < 0 || lo < 0) return std::nullopt;
            out[j++] = static_cast<std::uint8_t>((hi << 4) | lo);
        }
        return j == 16 ? std::optional(out) : std::nullopt;
    }

    auto encoded_address_size(TargetAddress const& addr) noexcept -> std::optional<std::size_t> {
        switch (addr.type) {
            case AddressType::none: return 1;
            case AddressType::ipv4: return 1 + 4 + 2;
            case AddressType::ipv6: return 1 + 16 + 2;
            case AddressType::domain:
                if (addr.domain.empty() || addr.domain.size() > 255) return {};
                return 1 + 1 + addr.domain.size() + 2;
        }
        return {};
    }

    auto encode_address(TargetAddress const& addr, std::vector<std::uint8_t>& out) -> bool {
        auto len = encoded_address_size(addr);
        if (!len) return false;
        out.push_back(static_cast<std::uint8_t>(addr.type));
        switch (addr.type) {
            case AddressType::none:
                return true;
            case AddressType::ipv4:
                out.insert(out.end(), addr.address.begin(), addr.address.begin() + 4);
                break;
            case AddressType::ipv6:
                out.insert(out.end(), addr.address.begin(), addr.address.end());
                break;
            case AddressType::domain:
                out.push_back(static_cast<std::uint8_t>(addr.domain.size()));
                out.insert(out.end(), addr.domain.begin(), addr.domain.end());
                break;
        }
        out.push_back(static_cast<std::uint8_t>(addr.port >> 8));
        out.push_back(static_cast<std::uint8_t>(addr.port));
        return true;
    }

    auto decode_address(std::span<std::uint8_t const> input)
        -> std::expected<std::pair<TargetAddress, std::size_t>, WireError> {
        if (input.empty()) return std::unexpected(WireError::incomplete);
        TargetAddress addr;
        addr.type = static_cast<AddressType>(input[0]);
        std::size_t pos = 1;
        switch (addr.type) {
            case AddressType::none:
                return std::pair{std::move(addr), pos};
            case AddressType::ipv4:
                if (input.size() < pos + 4 + 2) return std::unexpected(WireError::incomplete);
                std::copy_n(input.begin() + pos, 4, addr.address.begin());
                pos += 4;
                addr.port = read_u16(input.subspan(pos, 2));
                return std::pair{std::move(addr), pos + 2};
            case AddressType::ipv6:
                if (input.size() < pos + 16 + 2) return std::unexpected(WireError::incomplete);
                std::copy_n(input.begin() + pos, 16, addr.address.begin());
                pos += 16;
                addr.port = read_u16(input.subspan(pos, 2));
                return std::pair{std::move(addr), pos + 2};
            case AddressType::domain: {
                if (input.size() < pos + 1) return std::unexpected(WireError::incomplete);
                auto dlen = static_cast<std::size_t>(input[pos++]);
                if (!dlen) return std::unexpected(WireError::invalid);
                if (input.size() < pos + dlen + 2) return std::unexpected(WireError::incomplete);
                addr.domain.assign(reinterpret_cast<char const*>(input.data() + pos), dlen);
                pos += dlen;
                addr.port = read_u16(input.subspan(pos, 2));
                return std::pair{std::move(addr), pos + 2};
            }
        }
        return std::unexpected(WireError::invalid);
    }

    auto derive_auth_token(
        crypto::Hash hash,
        std::span<std::uint8_t const> exporter_master,
        std::span<std::uint8_t const, 16> uuid,
        std::string_view password) -> std::expected<std::array<std::uint8_t, 32>, crypto::Error> {
        if (password.size() > 255) return std::unexpected(crypto::Error::invalid_length);
        std::string_view label(reinterpret_cast<char const*>(uuid.data()), uuid.size());
        std::span<std::uint8_t const> context(reinterpret_cast<std::uint8_t const*>(password.data()), password.size());
        auto secret = tls::export_keying_material(hash, exporter_master, label, context, 32);
        if (!secret) return std::unexpected(secret.error());
        if (secret->view().size() != 32) return std::unexpected(crypto::Error::backend_failure);
        std::array<std::uint8_t, 32> token{};
        std::copy_n(secret->view().begin(), 32, token.begin());
        return token;
    }

    auto encode_authenticate(Authenticate const& msg) -> std::array<std::uint8_t, authenticate_size> {
        std::array<std::uint8_t, authenticate_size> out{};
        out[0] = version;
        out[1] = static_cast<std::uint8_t>(Command::authenticate);
        std::ranges::copy(msg.uuid, out.begin() + 2);
        std::ranges::copy(msg.token, out.begin() + 18);
        return out;
    }

    auto decode_authenticate(std::span<std::uint8_t const> input)
        -> std::expected<Authenticate, WireError> {
        if (input.size() < 2) return std::unexpected(WireError::incomplete);
        if (input[0] != version) return std::unexpected(WireError::unsupported_version);
        if (input[1] != static_cast<std::uint8_t>(Command::authenticate)) return std::unexpected(WireError::unsupported_command);
        if (input.size() < authenticate_size) return std::unexpected(WireError::incomplete);
        Authenticate msg;
        std::copy_n(input.begin() + 2, 16, msg.uuid.begin());
        std::copy_n(input.begin() + 18, 32, msg.token.begin());
        return msg;
    }

    auto encode_connect(TargetAddress const& target) -> std::expected<std::vector<std::uint8_t>, WireError> {
        if (target.type == AddressType::none) return std::unexpected(WireError::invalid);
        std::vector<std::uint8_t> out{version, static_cast<std::uint8_t>(Command::connect)};
        if (!encode_address(target, out)) return std::unexpected(WireError::invalid);
        return out;
    }

    auto decode_connect(std::span<std::uint8_t const> input)
        -> std::expected<std::pair<TargetAddress, std::size_t>, WireError> {
        if (input.size() < 2) return std::unexpected(WireError::incomplete);
        if (input[0] != version) return std::unexpected(WireError::unsupported_version);
        if (input[1] != static_cast<std::uint8_t>(Command::connect)) return std::unexpected(WireError::unsupported_command);
        auto addr = decode_address(input.subspan(2));
        if (!addr) return std::unexpected(addr.error());
        if (addr->first.type == AddressType::none) return std::unexpected(WireError::invalid);
        return std::pair{std::move(addr->first), 2 + addr->second};
    }

    auto encode_dissociate(std::uint16_t assoc_id) noexcept -> std::array<std::uint8_t, dissociate_size> {
        return {version, static_cast<std::uint8_t>(Command::dissociate),
                static_cast<std::uint8_t>(assoc_id >> 8), static_cast<std::uint8_t>(assoc_id)};
    }

    auto decode_dissociate(std::span<std::uint8_t const> input) noexcept
        -> std::expected<std::uint16_t, WireError> {
        if (input.size() < 2) return std::unexpected(WireError::incomplete);
        if (input[0] != version) return std::unexpected(WireError::unsupported_version);
        if (input[1] != static_cast<std::uint8_t>(Command::dissociate)) return std::unexpected(WireError::unsupported_command);
        if (input.size() < dissociate_size) return std::unexpected(WireError::incomplete);
        return read_u16(input.subspan(2, 2));
    }

    auto encode_heartbeat() noexcept -> std::array<std::uint8_t, heartbeat_size> {
        return {version, static_cast<std::uint8_t>(Command::heartbeat)};
    }

    auto decode_heartbeat(std::span<std::uint8_t const> input) noexcept
        -> std::expected<void, WireError> {
        if (input.size() < 2) return std::unexpected(WireError::incomplete);
        if (input[0] != version) return std::unexpected(WireError::unsupported_version);
        if (input[1] != static_cast<std::uint8_t>(Command::heartbeat)) return std::unexpected(WireError::unsupported_command);
        return {};
    }

    auto encode_packet(
        std::uint16_t assoc_id,
        std::uint16_t packet_id,
        std::uint8_t frag_total,
        std::uint8_t frag_id,
        TargetAddress const& destination,
        std::span<std::uint8_t const> payload) -> std::expected<std::vector<std::uint8_t>, WireError> {
        if (!frag_total || frag_id >= frag_total || payload.size() > 65535) return std::unexpected(WireError::invalid);
        auto addr_len = encoded_address_size(destination);
        if (!addr_len) return std::unexpected(WireError::invalid);
        std::vector<std::uint8_t> out(10);
        out[0] = version;
        out[1] = static_cast<std::uint8_t>(Command::packet);
        write_u16(&out[2], assoc_id);
        write_u16(&out[4], packet_id);
        out[6] = frag_total;
        out[7] = frag_id;
        write_u16(&out[8], static_cast<std::uint16_t>(payload.size()));
        if (!encode_address(destination, out)) return std::unexpected(WireError::invalid);
        out.insert(out.end(), payload.begin(), payload.end());
        return out;
    }

    auto decode_packet(std::span<std::uint8_t const> input)
        -> std::expected<PacketView, WireError> {
        if (input.size() < 2) return std::unexpected(WireError::incomplete);
        if (input[0] != version) return std::unexpected(WireError::unsupported_version);
        if (input[1] != static_cast<std::uint8_t>(Command::packet)) return std::unexpected(WireError::unsupported_command);
        if (input.size() < 10) return std::unexpected(WireError::incomplete);
        PacketHeader header;
        header.assoc_id = read_u16(input.subspan(2, 2));
        header.packet_id = read_u16(input.subspan(4, 2));
        header.frag_total = input[6];
        header.frag_id = input[7];
        header.payload_size = read_u16(input.subspan(8, 2));
        if (!header.frag_total || header.frag_id >= header.frag_total) return std::unexpected(WireError::invalid);
        auto addr = decode_address(input.subspan(10));
        if (!addr) return std::unexpected(addr.error());
        header.destination = std::move(addr->first);
        std::size_t payload_off = 10 + addr->second;
        if (input.size() < payload_off + header.payload_size) return std::unexpected(WireError::incomplete);
        if (input.size() != payload_off + header.payload_size) return std::unexpected(WireError::invalid);
        return PacketView{std::move(header), input.subspan(payload_off, header.payload_size)};
    }

    auto fragment_udp_packet(
        std::uint16_t assoc_id,
        std::uint16_t packet_id,
        TargetAddress const& destination,
        std::span<std::uint8_t const> payload,
        std::size_t max_packet_size) -> std::expected<std::vector<std::vector<std::uint8_t>>, WireError> {
        if (payload.size() > max_defrag_packet_bytes) return std::unexpected(WireError::too_large);
        auto addr_len = encoded_address_size(destination);
        if (!addr_len) return std::unexpected(WireError::invalid);
        std::size_t header_bytes = 10 + *addr_len;
        if (max_packet_size <= header_bytes) return std::unexpected(WireError::too_large);
        std::size_t mtu = max_packet_size - header_bytes;
        if (payload.size() <= mtu) {
            auto pkt = encode_packet(assoc_id, packet_id, 1, 0, destination, payload);
            if (!pkt) return std::unexpected(pkt.error());
            std::vector<std::vector<std::uint8_t>> result;
            result.push_back(std::move(*pkt));
            return result;
        }
        std::size_t frag_count = (payload.size() + mtu - 1) / mtu;
        if (frag_count > max_defrag_fragments || frag_count > 255) return std::unexpected(WireError::too_large);
        std::vector<std::vector<std::uint8_t>> result;
        result.reserve(frag_count);
        // Only fragment 0 needs full destination; subsequent fragments may carry AddressType::none,
        // mirroring sing-quic/tuic (overhead stays predictable while keeping full-addr safe when small).
        std::size_t offset = 0;
        for (std::size_t i = 0; i < frag_count; ++i) {
            auto chunk = payload.subspan(offset, std::min(mtu, payload.size() - offset));
            auto pkt = encode_packet(assoc_id, packet_id, static_cast<std::uint8_t>(frag_count),
                                     static_cast<std::uint8_t>(i), destination, chunk);
            if (!pkt) return std::unexpected(pkt.error());
            result.push_back(std::move(*pkt));
            offset += chunk.size();
        }
        return result;
    }

    auto UdpDefragmenter::feed(PacketView const& packet) -> std::expected<std::optional<Completed>, WireError> {
        auto const& h = packet.header;
        if (!h.frag_total || h.frag_total > max_defrag_fragments || h.frag_id >= h.frag_total)
            return std::unexpected(WireError::invalid);
        if (h.frag_total == 1) {
            return Completed{h.assoc_id, h.packet_id, h.destination,
                             std::vector<std::uint8_t>(packet.payload.begin(), packet.payload.end())};
        }
        std::optional<Entry>* target = nullptr;
        std::optional<Entry>* empty = nullptr;
        std::optional<Entry>* oldest = &slots_[0];
        for (auto& slot : slots_) {
            if (slot) {
                if (slot->assoc_id == h.assoc_id && slot->packet_id == h.packet_id) { target = &slot; break; }
                if (!oldest || !*oldest || slot->stamp < (*oldest)->stamp) oldest = &slot;
            } else if (!empty) {
                empty = &slot;
            }
        }
        if (!target) {
            target = empty ? empty : oldest;
            target->emplace();
            (*target)->assoc_id = h.assoc_id;
            (*target)->packet_id = h.packet_id;
            (*target)->frag_total = h.frag_total;
            (*target)->destination = h.destination;
            (*target)->fragments.resize(h.frag_total);
        } else {
            if ((*target)->frag_total != h.frag_total) return std::unexpected(WireError::conflict);
            if (h.destination.type != AddressType::none) {
                if ((*target)->destination.type == AddressType::none) (*target)->destination = h.destination;
                else if ((*target)->destination != h.destination) return std::unexpected(WireError::conflict);
            }
            if (((*target)->received_mask >> h.frag_id) & 1u) return std::unexpected(WireError::duplicate);
        }
        auto& entry = **target;
        if (packet.payload.size() > max_defrag_packet_bytes - entry.total_bytes) {
            target->reset();
            return std::unexpected(WireError::too_large);
        }
        entry.stamp = ++clock_;
        entry.received_mask |= std::uint64_t{1} << h.frag_id;
        entry.fragments[h.frag_id].assign(packet.payload.begin(), packet.payload.end());
        entry.total_bytes += packet.payload.size();
        ++entry.received_count;
        if (entry.received_count < entry.frag_total) return std::optional<Completed>{};
        Completed completed;
        completed.assoc_id = entry.assoc_id;
        completed.packet_id = entry.packet_id;
        completed.destination = std::move(entry.destination);
        completed.payload.reserve(entry.total_bytes);
        for (auto const& part : entry.fragments) completed.payload.insert(completed.payload.end(), part.begin(), part.end());
        target->reset();
        return std::optional<Completed>{std::move(completed)};
    }

    auto UdpDefragmenter::active_entries() const noexcept -> std::size_t {
        std::size_t count = 0;
        for (auto const& slot : slots_) if (slot) ++count;
        return count;
    }

    auto UdpDefragmenter::clear_association(std::uint16_t assoc_id) noexcept -> void {
        for (auto& slot : slots_) if (slot && slot->assoc_id == assoc_id) slot.reset();
    }
}
