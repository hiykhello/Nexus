module tls.post_handshake;
import tls.resumption_policy;
import std;
namespace tls {
    static auto read_ticket32(std::span<std::uint8_t const> body,std::size_t p) noexcept -> std::uint32_t {return (std::uint32_t{body[p]}<<24)|(std::uint32_t{body[p+1]}<<16)|(std::uint32_t{body[p+2]}<<8)|body[p+3];}
    template<bool Capture,bool Quic=false>
    [[gnu::always_inline]] static inline auto parse_ticket(std::span<std::uint8_t const> body) noexcept
        -> std::conditional_t<Capture,std::optional<NewSessionTicketView>,bool> {
        if (body.size()<13) return {};
        std::conditional_t<Capture,NewSessionTicketView,NoPsk> result;
        if constexpr(Capture) { result.lifetime=read_ticket32(body,0);result.age_add=read_ticket32(body,4); }
        std::size_t p=8, nonce=body[p++]; if (nonce>body.size()-p) return {};
        if constexpr(Capture) result.nonce=body.subspan(p,nonce);
        p+=nonce;
        if (body.size()-p<2) return {};
        auto ticket=(std::size_t{body[p]}<<8)|body[p+1]; p+=2;
        if (!ticket || ticket>body.size()-p) return {};
        if constexpr(Capture) result.ticket=body.subspan(p,ticket);
        p+=ticket;
        if (body.size()-p<2) return {};
        auto extensions=(std::size_t{body[p]}<<8)|body[p+1]; p+=2;
        if (extensions>65534 || extensions!=body.size()-p) return {};
        std::bitset<65536> seen;
        while (p<body.size()) {
            if (body.size()-p<4) return {};
            auto type=(std::size_t{body[p]}<<8)|body[p+1]; auto len=(std::size_t{body[p+2]}<<8)|body[p+3]; p+=4;
            if (len>body.size()-p || seen.test(type) || (type==42 && len!=4)) return {};
            if (type==42) {
                if constexpr(Quic) if (read_ticket32(body,p)!=0xffffffffu)return {};
                if constexpr(Capture) {result.max_early_data=read_ticket32(body,p);result.early_data=true;}
            }
            seen.set(type); p+=len;
        }
        if constexpr(Capture) return result; else return true;
    }
    auto parse_new_session_ticket(std::span<std::uint8_t const> body) noexcept -> std::optional<NewSessionTicketView> { return parse_ticket<true>(body); }
    auto valid_quic_new_session_ticket(std::span<std::uint8_t const> body) noexcept -> bool {return parse_ticket<false,true>(body);}
    auto valid_new_session_ticket(std::span<std::uint8_t const> body) noexcept -> bool { return parse_ticket<false>(body); }
}
