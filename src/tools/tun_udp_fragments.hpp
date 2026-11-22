#pragma once

namespace cli::tun_enabled {
    // One TUN worker owns all sets. UDP is parsed after reassembly, including
    // the length and transport checksum. Overlapping fragments poison the set.
    class TunUdpFragments {
        using Clock=std::chrono::steady_clock;
        struct Key {
            std::array<std::uint8_t,32> addresses{};
            std::uint32_t id=0;
            std::uint8_t version=0;
            auto operator==(Key const&) const -> bool = default;
        };
        struct Fragment {
            Key key;
            std::span<std::uint8_t const> header,payload;
            std::size_t offset,next_header_field=0;
            std::uint8_t next_header=0;
            bool more=false;
        };
        struct Range {std::size_t begin,end;};
        struct Set {
            Key key;
            Clock::time_point expires;
            nexus::inplace_vector<Range,64> ranges;
            packet::Bytes header,bytes;
            std::size_t next_header_field=0;
            std::uint8_t next_header=0;
            std::optional<std::size_t> end;
            std::size_t received=0;
            bool rejected=false;
            auto reject() noexcept -> void {
                packet::Bytes{}.swap(bytes);
                packet::Bytes{}.swap(header);
                ranges.clear();
                rejected=true;
            }
        };

        nexus::inplace_vector<Set,32> sets_;

        static auto read16(std::span<std::uint8_t const> bytes,std::size_t offset) noexcept -> std::uint16_t {
            return (std::uint16_t(bytes[offset])<<8)|bytes[offset+1];
        }
        static auto write16(std::span<std::uint8_t> bytes,std::size_t offset,std::uint16_t value) noexcept -> void {
            bytes[offset]=static_cast<std::uint8_t>(value>>8);
            bytes[offset+1]=static_cast<std::uint8_t>(value);
        }
        static auto parse(std::span<std::uint8_t const> bytes) noexcept -> std::optional<Fragment> {
            if (bytes.size()<20 || bytes.size()>65535) return {};
            Key key;
            key.version=bytes[0]>>4;
            if (key.version==4) {
                auto flags=read16(bytes,6);
                if (bytes[0]!=0x45 || bytes[9]!=17 || read16(bytes,2)!=bytes.size() ||
                    flags&0xc000 || packet::internet_checksum(bytes.first(20))) return {};
                key.id=read16(bytes,4);
                std::ranges::copy(bytes.subspan(12,8),key.addresses.begin());
                return Fragment{.key=key,.header=bytes.first(20),.payload=bytes.subspan(20),.offset=std::size_t(flags&0x1fff)*8,.more=bool(flags&0x2000)};
            }
            auto fragment=packet::parse_udp6_fragment(bytes);
            if (!fragment) return {};
            key.id=fragment->identification;
            std::ranges::copy(bytes.subspan(8,32),key.addresses.begin());
            auto prefix=fragment->prefix_length;
            return Fragment{key,bytes.first(prefix),bytes.subspan(prefix+8),fragment->offset,
                fragment->next_header_field,bytes[prefix],fragment->more};
        }
        static auto finish(packet::Bytes bytes,std::span<std::uint8_t const> header,
            std::size_t next_header_field,std::uint8_t next_header) -> packet::Bytes {
            bytes.insert(bytes.begin(),header.begin(),header.end());
            if (header.front()>>4==6) {
                bytes[next_header_field]=next_header;
                write16(bytes,4,static_cast<std::uint16_t>(bytes.size()-40));
            } else {
                write16(bytes,2,static_cast<std::uint16_t>(bytes.size()));
                write16(bytes,6,0);
                write16(bytes,10,0);
                write16(bytes,10,packet::internet_checksum(std::span(bytes).first(20)));
            }
            return bytes;
        }
    public:
        auto expire(Clock::time_point now) noexcept -> void {
            if (!sets_.empty() && sets_.front().expires<=now)
                nexus::erase_if(sets_,[&](Set const& set) {return set.expires<=now;});
        }

        [[nodiscard]] static auto fragmented(std::span<std::uint8_t const> bytes) noexcept -> bool {
            return (bytes.size()>=20 && bytes[0]>>4==4 && (read16(bytes,6)&0x3fff)) ||
                (bytes.size()>=48 && bytes[0]>>4==6 && (bytes[6]==44 || (bytes[6]==0 && bytes[40]==44)));
        }
        auto feed(std::span<std::uint8_t const> bytes,Clock::time_point now) -> std::optional<packet::Bytes> {
            auto fragment=parse(bytes);
            if (!fragment || fragment->payload.empty() || (fragment->more && fragment->payload.size()%8)) return {};
            auto first=fragment->offset;
            auto end=first+fragment->payload.size();
            auto minimum_header=fragment->key.version==4 ? 20u : 40u;
            if (end>65535-minimum_header || (!first && end>65535-fragment->header.size())) return {};
            if (!first && !fragment->more) {
                packet::Bytes atomic(fragment->payload.begin(),fragment->payload.end());
                return finish(std::move(atomic),fragment->header,fragment->next_header_field,fragment->next_header);
            }

            expire(now);
            auto current=std::ranges::find(sets_,fragment->key,&Set::key);
            if (current==sets_.end()) {
                if (sets_.size()==sets_.capacity()) return {};
                sets_.emplace_back(Set{.key=fragment->key,.expires=now+std::chrono::seconds(15)});
                current=std::prev(sets_.end());
            }
            auto& set=*current;
            if (set.rejected) return {};
            if (set.ranges.size()==set.ranges.capacity() ||
                (set.end && (end>*set.end || (!fragment->more && end!=*set.end))) ||
                std::ranges::any_of(set.ranges,[&](Range const& range) {
                    return (range.begin<end && first<range.end) || (!fragment->more && range.end>end);
                })) {
                set.reject();
                return {};
            }
            if (!first) {
                set.header.assign(fragment->header.begin(),fragment->header.end());
                set.next_header_field=fragment->next_header_field;
                set.next_header=fragment->next_header;
            }
            if (!set.header.empty() && std::max(end,set.bytes.size())>65535-set.header.size()) {
                set.reject();
                return {};
            }
            if (set.bytes.size()<end) set.bytes.resize(end);
            std::ranges::copy(fragment->payload,set.bytes.begin()+first);
            set.ranges.push_back({first,end});
            set.received+=fragment->payload.size();
            if (!fragment->more) set.end=end;
            if (!set.end || set.received!=*set.end) return {};
            auto result=finish(std::move(set.bytes),set.header,set.next_header_field,set.next_header);
            sets_.erase(current);
            return result;
        }
    };
}
