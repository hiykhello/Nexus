import std;
import anytls.settings;

auto main() -> int {
    using namespace anytls;
    constexpr std::string_view hash="0123456789abcdef0123456789abcdef";
    auto encoded=encode_client_settings(hash);
    if (!encoded) return 1;
    auto first=parse_settings(*encoded,true);
    if (!first || first->version!=2 || !first->client.empty() || first->padding_md5!=hash) return 2;
    auto named=encode_client_settings(hash,"deployment");
    if (!named) return 3;
    auto custom=parse_settings(*named,true);
    if (!custom || custom->client!="deployment") return 3;
    auto server=encode_server_settings();
    auto parsed=parse_settings(server,false);
    if (!parsed || parsed->version!=2 || parse_settings(server,true)) return 4;
    auto bytes=[](std::string_view text) { return std::span(reinterpret_cast<std::uint8_t const*>(text.data()),text.size()); };
    for (auto text:{"v=0","v=-1","v=4294967296","v=2x","v=","v=2\nv=1","v=2\nclient=a\nclient=b", "v=2\nmissing-equals", "v=2\n=empty-key", "v=2\r"})
        if (parse_settings(bytes(text),false)) return 5;
    for (auto text:{"padding-md5=0123456789abcdef0123456789abcdef", "v=2\npadding-md5=0", "v=2\npadding-md5=0123456789abcdef0123456789ABCDEF"})
        if (parse_settings(bytes(text),true)) return 6;
    auto future=std::string("unknown=kept-out-of-metadata\nv=3\n\nclient=\npadding-md5=")+std::string(hash)+"\n";
    auto compatible=parse_settings(bytes(future),true);
    if (!compatible || compatible->version!=3 || !compatible->client.empty()) return 7;
    if (encode_client_settings(hash,"line\nbreak") || encode_client_settings(hash,std::string(257,'a')) ||
        encode_client_settings("invalid",{}) || encode_client_settings(hash,std::string_view("a\0b",3))) return 8;
    auto long_settings=std::string("v=2\nunknown=")+std::string(8192,'a');
    if (parse_settings(bytes(long_settings),false)) return 9;
    std::string lines="v=2\n";
    for (int i=0;i<64;++i) lines+="x=y\n";
    if (parse_settings(bytes(lines),false)) return 10;
    std::println("AnyTLS settings version, optional empty metadata, padding fingerprint and bounded parsing passed");
}
