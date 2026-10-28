#pragma once
// Included after import std; this checker admits only the experiment's BEVE
// snapshot shape and rejects duplicate object fields before Glaze decoding.
class SnapshotProfile {
    std::string_view input_;
    std::size_t offset_=0;
    bool byte(std::uint8_t& result) {
        if (offset_==input_.size()) return false;
        result=static_cast<std::uint8_t>(input_[offset_++]); return true;
    }
    bool tag(std::uint8_t expected) { std::uint8_t actual; return byte(actual) && actual==expected; }
    bool count(std::uint64_t& value) {
        if (offset_==input_.size()) return false;
        auto width=std::size_t{1} << (static_cast<std::uint8_t>(input_[offset_])&3U);
        if (width>input_.size()-offset_) return false;
        std::uint64_t packed=0;
        for (std::size_t i=0;i<width;++i) { std::uint8_t b; if (!byte(b)) return false; packed|=std::uint64_t{b}<<(8*i); }
        value=packed>>2; return true;
    }
    bool key(std::string_view& result) {
        std::uint64_t size;
        if (!count(size) || size>32 || size>input_.size()-offset_) return false;
        result=input_.substr(offset_,static_cast<std::size_t>(size)); offset_+=static_cast<std::size_t>(size); return true;
    }
    bool fixed(std::uint8_t expected,std::size_t size) {
        if (!tag(expected) || size>input_.size()-offset_) return false;
        offset_+=size; return true;
    }
    bool u8_array(std::size_t size) {
        std::uint64_t length;
        return tag(0x14) && count(length) && length==size &&
               size<=input_.size()-offset_ && ((offset_+=size),true);
    }
    bool entry() {
        std::uint64_t fields;
        if (!tag(3) || !count(fields) || fields!=2) return false;
        unsigned seen=0;
        for (unsigned i=0;i<2;++i) {
            std::string_view name;
            if (!key(name)) return false;
            unsigned bit=name=="id" ? 1U : name=="replay" ? 2U : 0U;
            if (!bit || (seen&bit)) return false;
            seen|=bit;
            if (!u8_array(bit==1 ? 8 : s::udp_replay_encoded_size)) return false;
        }
        return seen==3;
    }
    bool entries() {
        std::uint64_t size;
        if (!tag(5) || !count(size) || size>16) return false;
        for (std::uint64_t i=0;i<size;++i) if (!entry()) return false;
        return true;
    }
public:
    explicit SnapshotProfile(std::string_view input) : input_(input) {}
    bool valid() {
        std::uint64_t fields;
        if (!tag(3) || !count(fields) || fields!=5) return false;
        unsigned seen=0;
        for (unsigned i=0;i<5;++i) {
            std::string_view name;
            if (!key(name)) return false;
            unsigned bit=name=="version" ? 1U : name=="wall" ? 2U : name=="id_next" ? 4U :
                         name=="id_exhausted" ? 8U : name=="sessions" ? 16U : 0U;
            if (!bit || (seen&bit)) return false;
            seen|=bit;
            if (bit==1 && !fixed(0x51,4)) return false;
            if ((bit==2 || bit==4) && !fixed(0x71,8)) return false;
            if (bit==8) { std::uint8_t b; if (!byte(b) || (b!=0x08 && b!=0x18)) return false; }
            if (bit==16 && !entries()) return false;
        }
        return seen==31 && offset_==input_.size();
    }
};
