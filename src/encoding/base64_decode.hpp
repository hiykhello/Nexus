// Included by module units after importing std.
#pragma once

auto decode_base64_exact(std::span<char const> input,std::span<std::uint8_t> output) noexcept -> bool {
    if (input.size()!=((output.size()+2)/3)*4) return false;
    auto digit=[](char c) -> int {
        if (c>='A' && c<='Z') return c-'A';
        if (c>='a' && c<='z') return c-'a'+26;
        if (c>='0' && c<='9') return c-'0'+52;
        if (c=='+') return 62;
        if (c=='/') return 63;
        return -1;
    };
    std::size_t out=0;
    for (std::size_t i=0;i<input.size();i+=4) {
        int a=digit(input[i]), b=digit(input[i+1]);
        int c=input[i+2]=='=' ? -1 : digit(input[i+2]);
        int d=input[i+3]=='=' ? -1 : digit(input[i+3]);
        auto remaining=output.size()-out;
        if (a<0 || b<0 || (remaining>1 && c<0) || (remaining>2 && d<0) ||
            (remaining==1 && (input[i+2]!='=' || input[i+3]!='=' || (b&15))) ||
            (remaining==2 && (input[i+3]!='=' || (c&3)))) return false;
        output[out++]=static_cast<std::uint8_t>((a<<2)|(b>>4));
        if (remaining>1) output[out++]=static_cast<std::uint8_t>((b<<4)|(c>>2));
        if (remaining>2) output[out++]=static_cast<std::uint8_t>((c<<6)|d);
    }
    return true;
}
