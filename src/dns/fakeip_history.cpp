module nexus.dns.fakeip_history;
import std;
import nexus.dns.fakeip_recovery;
import nexus.crypto;
namespace nexus::dns {
    namespace {
        constexpr std::size_t header=32, entry_size=16, tag_size=32, limit=256;
        constexpr std::array<std::uint8_t,4> magic{'N','F','H',1};
        auto put(std::vector<std::uint8_t>& out,std::uint64_t value,unsigned count) -> void {
            for (unsigned i=count;i>0;--i) out.push_back(static_cast<std::uint8_t>(value>>((i-1)*8)));
        }
        auto get(std::span<std::uint8_t const> in,std::size_t offset,unsigned count) -> std::uint64_t {
            std::uint64_t result=0;
            for (unsigned i=0;i<count;++i) result=(result<<8)|in[offset+i];
            return result;
        }
        auto valid(std::span<FakeIpHistoricalRange const> ranges) -> bool {
            if (ranges.empty() || ranges.size()>limit) return false;
            for (std::size_t i=0;i<ranges.size();++i) {
                auto const& r=ranges[i];
                if (r.first>r.last || r.protection.count()<=0 ||
                    r.protection>std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::duration::max())) return false;
                if (i && static_cast<std::uint64_t>(ranges[i-1].last)+1>=r.first) return false;
            }
            return true;
        }
    }
    auto encode_fakeip_history(FakeIpHistorySnapshot const& snapshot,
        std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key)
        -> std::expected<std::vector<std::uint8_t>,FakeIpHistoryError> {
        if (!snapshot.generation || !valid(snapshot.ranges)) return std::unexpected(FakeIpHistoryError::invalid);
        std::vector<std::uint8_t> wire; wire.reserve(header+entry_size*snapshot.ranges.size()+tag_size);
        wire.insert(wire.end(),magic.begin(),magic.end());
        wire.insert(wire.end(),instance.begin(),instance.end());
        put(wire,snapshot.ranges.size(),4); put(wire,snapshot.generation,8);
        for (auto const& r:snapshot.ranges) {
            put(wire,r.first,4); put(wire,r.last,4); put(wire,static_cast<std::uint64_t>(r.protection.count()),8);
        }
        auto mac=crypto::hmac(crypto::Hash::sha256,key,wire);
        if (!mac || mac->size()!=tag_size) return std::unexpected(FakeIpHistoryError::crypto);
        wire.insert(wire.end(),mac->begin(),mac->end());
        return wire;
    }
    auto decode_fakeip_history(std::span<std::uint8_t const> wire,
        std::span<std::uint8_t const,16> instance,std::span<std::uint8_t const,32> key)
        -> std::expected<FakeIpHistorySnapshot,FakeIpHistoryError> {
        if (wire.size()<header+entry_size+tag_size || wire.size()>header+limit*entry_size+tag_size ||
            !std::ranges::equal(wire.first(4),magic)) return std::unexpected(FakeIpHistoryError::invalid);
        auto count=get(wire,20,4), generation=get(wire,24,8);
        if (!count || count>limit || !generation || wire.size()!=header+count*entry_size+tag_size)
            return std::unexpected(FakeIpHistoryError::invalid);
        auto mac=crypto::hmac(crypto::Hash::sha256,key,wire.first(wire.size()-tag_size));
        if (!mac || mac->size()!=tag_size) return std::unexpected(FakeIpHistoryError::crypto);
        if (!crypto::constant_time_equal(*mac,wire.last(tag_size)) ||
            !crypto::constant_time_equal(instance,wire.subspan(4,16)))
            return std::unexpected(FakeIpHistoryError::authentication);
        std::vector<FakeIpHistoricalRange> ranges; ranges.reserve(count);
        for (std::size_t i=0;i<count;++i) {
            auto offset=header+i*entry_size;
            auto seconds=get(wire,offset+8,8);
            if (seconds>static_cast<std::uint64_t>(std::chrono::seconds::max().count()))
                return std::unexpected(FakeIpHistoryError::invalid);
            ranges.push_back({static_cast<std::uint32_t>(get(wire,offset,4)),
                              static_cast<std::uint32_t>(get(wire,offset+4,4)),std::chrono::seconds{seconds}});
        }
        if (!valid(ranges)) return std::unexpected(FakeIpHistoryError::invalid);
        return FakeIpHistorySnapshot{generation,std::move(ranges)};
    }
}
