import std;
import trojan;
import trojan.auth;

auto main() -> int {
    constexpr std::string_view text="password";
    auto first=trojan::PasswordKey::from_password({reinterpret_cast<std::uint8_t const*>(text.data()),text.size()});
    if (!first) return 1;
    constexpr std::string_view expected="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";
    if (!std::ranges::equal(first->view(),expected)) return 2;
    auto second=trojan::PasswordKey::from_password(std::array<std::uint8_t,1>{'x'});
    if (!second) return 3;
    std::vector<trojan::PasswordKey> keys;
    keys.push_back(std::move(*second)); keys.push_back(std::move(*first));
    if (trojan::authenticate(keys,keys[1].view())!=1 || trojan::authenticate(keys,keys[0].view())!=0) return 4;
    trojan::Key wrong{}; std::ranges::fill(wrong,'0');
    if (trojan::authenticate(keys,wrong) || trojan::PasswordKey::from_password({}) ||
        trojan::PasswordKey::from_password(std::vector<std::uint8_t>(4097,'a'))) return 5;
    std::println("Trojan SHA-224 password vector, moved credentials, multiuser lookup and limits passed");
}
