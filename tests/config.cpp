import std;
import nexus.config;

static auto replace(std::string text, std::string_view before, std::string_view after) -> std::string {
    auto pos = text.find(before);
    if (pos == std::string::npos) throw std::runtime_error("missing test substring");
    text.replace(pos, before.size(), after);
    return text;
}

int main() {
    std::string const complete = R"(schema-version 1
role "client"
inbound "local" type="socks5" {
    listen host="127.0.0.1" port=1080
    authentication "none"
}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {
    rule-set "blocked" path="rules/blocked.kdl" format="kdl"
    rule kind="rule-set" value="blocked" outbound="reject"
    default-outbound "direct"
}
)";
    auto config = nexus::config::parse_kdl(complete);
    auto ipv6=nexus::config::parse_kdl(replace(complete,"listen host=\"127.0.0.1\"","listen host=\"::1\""));
    if (!ipv6 || !ipv6->listen_ipv6 || ipv6->inbounds.size()!=1 || !ipv6->inbounds[0].listen_ipv6) return 1;
    for (auto host : {"::", "::2", "::1%lo", "::ffff:127.0.0.1"})
        if (nexus::config::parse_kdl(replace(complete,"127.0.0.1",host))) return 1;
    auto ss=replace(complete,"outbound \"direct\" type=\"direct\"", R"(outbound "direct" type="direct"
outbound "ss" type="shadowsocks" { server host="127.0.0.1" port=8388; method "2022-blake3-aes-128-gcm"; key-file "/secret"; })");
    ss=replace(ss,"default-outbound \"direct\"","default-outbound \"ss\"");
    auto parsed_ss=nexus::config::parse_kdl(ss);
    if (!parsed_ss || parsed_ss->shadowsocks_outbounds.size()!=1 || parsed_ss->default_outbound!=2 ||
        parsed_ss->shadowsocks_outbounds[0].config.key_file!="/secret") return 1;
    for (auto bad : {replace(ss,"key-file \"/secret\"","key-file \"relative\""),
                     replace(ss,"2022-blake3-aes-128-gcm","aes-128-gcm"),
                     replace(ss,"outbound \"ss\"","outbound \"direct\""),
                     replace(ss,"default-outbound \"ss\"","default-outbound \"direct\"")})
        if (nexus::config::parse_kdl(bad)) return 1;
    auto ss_boot=replace(ss,"server host=\"127.0.0.1\"", "bootstrap-resolver \"boot\"; server host=\"edge.test\"");
    ss_boot="dns { server \"boot\" type=\"udp\" host=\"127.0.0.1\"; }\n"+ss_boot;
    auto parsed_ss_boot=nexus::config::parse_kdl(ss_boot);
    if (!parsed_ss_boot || parsed_ss_boot->shadowsocks_outbounds[0].config.bootstrap_index!=0 ||
        nexus::config::parse_kdl(replace(ss_boot,"bootstrap-resolver \"boot\"", "bootstrap-resolver \"missing\"")) ||
        nexus::config::parse_kdl(replace(ss_boot,"edge.test", "127.0.0.1")) ||
        nexus::config::parse_kdl(replace(ss_boot,"bootstrap-resolver \"boot\";", "bootstrap-resolver \"boot\"; bootstrap-resolver \"boot\";"))) return 1;
    if (!config || config->port != 1080 || !config->block_rules ||
        config->block_rules->path != "rules/blocked.kdl" ||
        config->block_rules->format != nexus::config::RuleFormat::kdl) {
        std::cerr << "valid configuration rejected\n"; return 1;
    }
    auto grouped=replace(complete,"inbound \"local\"", "inbounds {\n  inbound \"local\"");
    grouped=replace(grouped,"}\noutbound \"direct\"", "}\n}\noutbounds {\n  outbound \"direct\"");
    grouped=replace(grouped,"outbound \"reject\" type=\"block\"\nrouting", "outbound \"reject\" type=\"block\"\n}\nrouting");
    auto grouped_config=nexus::config::parse_kdl("dns { servers { server \"system\" type=\"local\"; server \"up\" type=\"udp\" host=\"127.0.0.1\"; }; final \"up\"; }\n"+grouped);
    if (!grouped_config || !grouped_config->dns || grouped_config->dns->servers.size()!=2 || grouped_config->dns->final!=1 ||
        grouped_config->port!=1080 || !grouped_config->block_rules) return 1;
    for (auto bad : {"inbounds {}\n", "outbounds {}\n", "inbounds { other; }\n", "outbounds { other; }\n",
                     "inbounds x=1 {}\n", "outbounds \"x\" {}\n"})
        if (nexus::config::parse_kdl(std::string(bad)+complete)) return 1;
    for (auto bad : {"dns { servers {}; }\n", "dns { servers { other; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; server \"b\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"local\"; servers { server \"b\" type=\"local\"; }; }\n",
                     "dns { servers { server \"a\" type=\"local\"; }; servers { server \"b\" type=\"local\"; }; }\n"})
        if (nexus::config::parse_kdl(std::string(bad)+complete)) return 1;
    for (auto bad : {"inbounds {}\n", "outbounds {}\n", "inbound \"extra\" type=\"socks5\" {}\n",
                     "outbound \"extra\" type=\"direct\"\n"})
        if (nexus::config::parse_kdl(grouped+bad)) return 1;
    auto multiple=replace(grouped,"outbounds {", R"(inbounds {}
outbounds {)");
    // A second inbound belongs inside the existing group, not a second block.
    auto second=replace(grouped,R"(}
}
outbounds {)", R"(}
  inbound "other" type="mixed" { listen host="127.0.0.1" port=1081; authentication "none"; }
}
outbounds {)");
    auto parsed_multi=nexus::config::parse_kdl(second);
    auto dual=replace(second,"listen host=\"127.0.0.1\" port=1081","listen host=\"::1\" port=1080");
    auto parsed_dual=nexus::config::parse_kdl(dual);
    if (!parsed_dual || parsed_dual->inbounds.size()!=2 || parsed_dual->inbounds[0].listen_ipv6 ||
        !parsed_dual->inbounds[1].listen_ipv6 || parsed_dual->inbounds[0].port!=parsed_dual->inbounds[1].port ||
        nexus::config::parse_kdl(replace(dual,"listen host=\"127.0.0.1\" port=1080","listen host=\"::1\" port=1080"))) return 1;
    if (!parsed_multi || parsed_multi->inbounds.size()!=2 || parsed_multi->inbounds[1].port!=1081 ||
        parsed_multi->inbounds[1].type!=nexus::config::Inbound::mixed || nexus::config::parse_kdl(multiple) ||
        nexus::config::parse_kdl(replace(second,"port=1081","port=1080")) ||
        nexus::config::parse_kdl(replace(second,"inbound \"other\"","inbound \"local\""))) return 1;
    auto typed=replace(grouped,"inbound \"local\" type=\"socks5\"", "socks5 \"local\"");
    typed=replace(typed,"outbound \"direct\" type=\"direct\"", "direct \"direct\"");
    typed=replace(typed,"outbound \"reject\" type=\"block\"", "block \"reject\"");
    auto ss_in=replace(typed,R"(socks5 "local" {
    listen host="127.0.0.1" port=1080
    authentication "none"
})",R"(shadowsocks "local" {
    listen host="127.0.0.1" port=1080
    method "2022-blake3-aes-128-gcm"
    key-file "/secret"
})");
    auto ss_in_config=nexus::config::parse_kdl(ss_in);
    if (!ss_in_config || ss_in_config->inbounds[0].type!=nexus::config::Inbound::shadowsocks ||
        !ss_in_config->inbounds[0].shadowsocks || ss_in_config->inbounds[0].shadowsocks->key_file!="/secret") return 1;
    for (auto bad : {replace(ss_in,"key-file \"/secret\"","key-file \"relative\""),
                     replace(ss_in,"2022-blake3-aes-128-gcm","aes-128-gcm"),
                     replace(ss_in,"key-file \"/secret\"","key-file \"/secret\"; key-file \"/secret\""),
                     replace(ss_in,"key-file \"/secret\"","authentication \"none\"; key-file \"/secret\"")})
        if (nexus::config::parse_kdl(bad)) return 1;
    typed=replace(typed,"rule kind=\"rule-set\" value=\"blocked\" outbound=\"reject\"", "rules { - kind=\"rule-set\" value=\"blocked\" outbound=\"reject\"; }");
    auto new_style=nexus::config::parse_kdl("dns { servers { local \"system\"; udp \"up\" host=\"127.0.0.1\"; }; rules { - domain=\"example.test\" server=\"up\"; }; }\n"+typed);
    if (!new_style || new_style->inbounds.size()!=1 || !new_style->dns || new_style->dns->rules.size()!=1 ||
        new_style->dns->rules[0].server!=1) return 1;
    for (auto bad : {"dns { servers { udp \"a\" type=\"udp\" host=\"127.0.0.1\"; }; }\n",
                     "dns { servers { local \"a\"; }; rules { rule domain=\"x.test\" server=\"a\"; }; }\n",
                     "dns { servers { local \"a\"; }; rules { - domain=\"x.test\" server=\"a\"; }; rule domain=\"y.test\" server=\"a\"; }\n"})
        if (nexus::config::parse_kdl(std::string(bad)+typed)) return 1;
    std::string many_inbounds="inbounds {\n";
    for (int i=0;i<16;++i)
        many_inbounds+="socks5 \"in"+std::to_string(i)+"\" { listen host=\"127.0.0.1\" port="+
                       std::to_string(20000+i)+"; authentication \"none\"; }\n";
    auto without_inbounds=grouped.substr(0,grouped.find("inbounds {"))+grouped.substr(grouped.find("outbounds {"));
    auto maximum=nexus::config::parse_kdl(many_inbounds+"}\n"+without_inbounds);
    if (!maximum || maximum->inbounds.size()!=16) return 1;
    many_inbounds+="socks5 \"overflow\" { listen host=\"127.0.0.1\" port=20016; authentication \"none\"; }\n";
    if (nexus::config::parse_kdl(many_inbounds+"}\n"+without_inbounds)) return 1;
    auto vless_in_config=replace(typed, R"(socks5 "local" {
    listen host="127.0.0.1" port=1080
    authentication "none"
})", R"(vless "local" {
    listen host="127.0.0.1" port=1080
    authentication { user "alice" uuid-file="/a"; user "bob" uuid-file="/b"; }
    tls { certificate-file "/cert.der"; private-key-file "/key.der"; }
})");
    auto incoming=nexus::config::parse_kdl(vless_in_config);
    if (!incoming || incoming->inbounds[0].type!=nexus::config::Inbound::vless || !incoming->inbounds[0].vless ||
        incoming->inbounds[0].vless->users.size()!=2 || incoming->inbounds[0].vless->private_key_file!="/key.der") return 1;
    for (auto bad : {replace(vless_in_config,"uuid-file=\"/a\"","uuid-file=\"relative\""),
                     replace(vless_in_config,"user \"bob\"","user \"alice\""),
                     replace(vless_in_config,"private-key-file \"/key.der\"","private-key-file \"key.der\""),
                     replace(vless_in_config,"certificate-file \"/cert.der\";", ""),
                     replace(vless_in_config,"user \"alice\" uuid-file=\"/a\"; user \"bob\" uuid-file=\"/b\";", "")})
        if (nexus::config::parse_kdl(bad)) return 1;
    if (config->workers!=1) return 1;
    auto dns=nexus::config::parse_kdl("dns-upstream host=\"127.0.0.1\" port=5353\n"+complete);
    if (!dns || !dns->dns_upstream || dns->dns_upstream->ipv6 || dns->dns_upstream->address[0]!=127 || dns->dns_upstream->address[3]!=1 ||
        dns->dns_upstream->port!=5353) return 1;
    auto dns6=nexus::config::parse_kdl("dns-upstream host=\"::1\" port=5353\n"+complete);
    if (!dns6 || !dns6->dns_upstream || !dns6->dns_upstream->ipv6 || dns6->dns_upstream->address[15]!=1) return 1;
    for (auto bad : {"dns-upstream host=\"localhost\" port=53\n", "dns-upstream host=\"127.00.0.1\" port=53\n",
                     "dns-upstream host=\"127.0.0.1\" port=0\n", "dns-upstream host=\"127.0.0.1\" port=65536\n",
                     "dns-upstream host=\"127.0.0.1\" port=53 extra=1\n", "dns-upstream host=\"::1%lo\" port=53\n",
                     "dns-upstream host=\"::1\\u{0}x\" port=53\n", "dns-upstream host=\"[::1]\" port=53\n"})
        if (nexus::config::parse_kdl(std::string(bad)+complete)) return 1;
    if (nexus::config::parse_kdl("dns-upstream host=\"127.0.0.1\" port=53\ndns-upstream host=\"127.0.0.1\" port=53\n"+complete)) return 1;
    auto servers=nexus::config::parse_kdl(R"(dns {
        server "system" type="local"
        server "remote" type="udp" host="::1" port=5353
        final "remote"
    }
)"+complete);
    if (!servers || !servers->dns || servers->dns->final!=1 || !servers->dns->servers[1].upstream ||
        !servers->dns->servers[1].upstream->ipv6 || servers->dns->servers[1].upstream->port!=5353) return 1;
    auto first=nexus::config::parse_kdl("dns { server \"remote\" type=\"udp\" host=\"127.0.0.1\"; server \"system\" type=\"local\"; }\n"+complete);
    if (!first || !first->dns || first->dns->final!=0 || first->dns->servers[0].upstream->port!=53) return 1;
    auto local=nexus::config::parse_kdl("dns { server \"remote\" type=\"udp\" host=\"127.0.0.1\"; server \"system\" type=\"local\"; final \"system\"; }\n"+complete);
    if (!local || !local->dns || local->dns->final!=1 || local->dns->servers[1].upstream) return 1;
    auto tcp=nexus::config::parse_kdl("dns { server \"tcp\" type=\"tcp\" host=\"::1\"; }\n"+complete);
    if (!tcp || !tcp->dns || !tcp->dns->servers[0].upstream || !tcp->dns->servers[0].upstream->tcp ||
        tcp->dns->servers[0].upstream->port!=53) return 1;
    for (auto const& [value, expected] : std::array{
        std::pair{"prefer_ipv4",nexus::config::DnsStrategy::prefer_ipv4},
        std::pair{"prefer_ipv6",nexus::config::DnsStrategy::prefer_ipv6},
        std::pair{"ipv4_only",nexus::config::DnsStrategy::ipv4_only},
        std::pair{"ipv6_only",nexus::config::DnsStrategy::ipv6_only}}) {
        auto parsed=nexus::config::parse_kdl("dns { server \"a\" type=\"local\"; strategy \""+std::string(value)+"\"; }\n"+complete);
        if (!parsed || !parsed->dns || parsed->dns->strategy!=expected) return 1;
    }
    auto dns_rules=nexus::config::parse_kdl("dns { rule domain-suffix=\"Example.COM\" server=\"remote\"; rule domain=\"host.example.com\" server=\"system\"; server \"system\" type=\"local\"; server \"remote\" type=\"udp\" host=\"127.0.0.1\"; }\n"+complete);
    if (!dns_rules || !dns_rules->dns || dns_rules->dns->rules.size()!=2 || dns_rules->dns->rules[0].domain!="example.com" ||
        !dns_rules->dns->rules[0].suffix || dns_rules->dns->rules[0].server!=1 || dns_rules->dns->rules[1].server!=0) return 1;
    auto bootstrap=nexus::config::parse_kdl("dns { server \"leaf\" type=\"tcp\" host=\"dns.example\" domain-resolver=\"middle\"; server \"middle\" type=\"udp\" host=\"next.example\" domain-resolver=\"root\"; server \"root\" type=\"local\"; }\n"+complete);
    if (!bootstrap || !bootstrap->dns || bootstrap->dns->servers[0].upstream->host!="dns.example" ||
        bootstrap->dns->servers[0].upstream->resolver!=1 || bootstrap->dns->servers[1].upstream->resolver!=2) return 1;
    auto no_cache=nexus::config::parse_kdl("dns { server \"a\" type=\"local\"; disable-cache #true; }\n"+complete);
    auto cache=nexus::config::parse_kdl("dns { server \"a\" type=\"local\"; disable-cache #false; }\n"+complete);
    if (!no_cache || !no_cache->dns || !no_cache->dns->disable_cache || !cache || !cache->dns || cache->dns->disable_cache) return 1;
    auto edns=nexus::config::parse_kdl("dns { server \"a\" type=\"local\"; edns #true; }\n"+complete);
    if (!edns || !edns->dns || !edns->dns->edns) return 1;
    for (auto bad : {"dns {}\n", "dns { final \"missing\"; server \"a\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"local\"; server \"a\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"local\" host=\"127.0.0.1\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"localhost\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"127.0.0.1\" extra=1; }\n",
                     "dns { server \"a\" type=\"tls\" host=\"127.0.0.1\"; }\n",
                     "dns { server \"a\" type=\"local\"; final \"a\"; final \"a\"; }\n",
                     "dns { server \"a\" type=\"local\"; rule domain=\"example.com\" server=\"missing\"; }\n",
                     "dns { server \"a\" type=\"local\"; rule domain=\"-bad.test\" server=\"a\"; }\n",
                     "dns { server \"a\" type=\"local\"; rule domain=\"a.test\" domain-suffix=\"a.test\" server=\"a\"; }\n",
                     "dns { server \"a\" type=\"local\"; strategy \"other\"; }\n",
                     "dns { server \"a\" type=\"local\"; strategy \"ipv4_only\"; strategy \"ipv6_only\"; }\n",
                     "dns { server \"a\" type=\"local\"; disable-cache \"true\"; }\n",
                     "dns { server \"a\" type=\"local\"; disable-cache #true; disable-cache #false; }\n",
                     "dns { server \"a\" type=\"local\"; edns \"true\"; }\n",
                     "dns { server \"a\" type=\"local\"; edns #true; edns #false; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"dns.example\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"dns.example\" domain-resolver=\"missing\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"dns.example\" domain-resolver=\"a\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"a.example\" domain-resolver=\"b\"; server \"b\" type=\"tcp\" host=\"b.example\" domain-resolver=\"a\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"127.00.0.1\" domain-resolver=\"b\"; server \"b\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"udp\" host=\"127.0.0.1\" domain-resolver=\"b\"; server \"b\" type=\"local\"; }\n",
                     "dns { server \"a\" type=\"local\"; }\ndns-upstream host=\"127.0.0.1\" port=53\n",
                     "dns-upstream host=\"127.0.0.1\" port=53\ndns { server \"a\" type=\"local\"; }\n"})
        if (nexus::config::parse_kdl(std::string(bad)+complete)) return 1;
    auto multi=nexus::config::parse_kdl("workers 2\n"+complete);
    if (!multi || multi->workers!=2 || nexus::config::parse_kdl("workers 0\n"+complete) ||
        nexus::config::parse_kdl("workers 17\n"+complete) ||
        nexus::config::parse_kdl("workers 1\nworkers 2\n"+complete)) return 1;
    auto mixed = nexus::config::parse_kdl(replace(complete, "type=\"socks5\"", "type=\"mixed\""));
    if (!mixed || mixed->inbound != nexus::config::Inbound::mixed) return 1;
    auto authenticated = replace(complete, "authentication \"none\"", "authentication \"password\" username=\"alice\" password-file=\"/tmp/password\"");
    auto auth = nexus::config::parse_kdl(authenticated);
    if (!auth || !auth->password_auth || auth->password_auth->username != "alice" ||
        auth->password_auth->password_file != "/tmp/password") return 1;
    auto binary = nexus::config::parse_kdl(replace(complete, "format=\"kdl\"", "format=\"beve\""));
    if (!binary || !binary->block_rules || binary->block_rules->format != nexus::config::RuleFormat::beve) return 1;
    std::string const direct = R"(schema-version 1
role "server"
inbound "local" type="socks5" {
    listen host="127.0.0.1" port=65535
    authentication "none"
}
outbound "direct" type="direct"
routing { default-outbound "direct"; }
)";
    auto minimal = nexus::config::parse_kdl(direct);
    if (!minimal || minimal->port != 65535 || minimal->block_rules) {
        std::cerr << "direct-only configuration rejected\n"; return 1;
    }
    std::string const vless_node = R"(outbound "edge" type="vless" {
    server host="127.0.0.1" port=443
    authentication { uuid-file "/tmp/edge.uuid"; }
    tls { server-name "edge.example"; ca-file "/tmp/ca.pem"; verify #true; }
}
)";
    auto vless_config=replace(complete, "routing {", vless_node + "routing {");
    vless_config=replace(vless_config, "default-outbound \"direct\"", "default-outbound \"edge\"");
    auto vless=nexus::config::parse_kdl(vless_config);
    auto combined=replace(vless_config,"routing {",R"(outbound "ss" type="shadowsocks" { server host="127.0.0.1" port=8388; method "2022-blake3-aes-256-gcm"; key-file "/secret"; }
routing {)");
    combined=replace(combined,"outbound=\"reject\"","outbound=\"ss\"");
    auto combined_config=nexus::config::parse_kdl(combined);
    if (!combined_config || combined_config->default_outbound!=2 || combined_config->routes[0].outbound!=3) return 1;
    if (!vless || !vless->vless || vless->vless->host!="127.0.0.1" || vless->vless->port!=443 ||
        vless->vless->uuid_file!="/tmp/edge.uuid" || vless->vless->server_name!="edge.example" || vless->vless->ca_file!="/tmp/ca.pem" ||
        vless->vless->key_exchange!=nexus::config::TlsKeyExchange::x25519) {
        std::cerr << "vless configuration rejected\n"; return 1;
    }
    auto hybrid_config=replace(vless_config,"verify #true", "verify #true; key-exchange \"x25519-mlkem768\"");
    auto hybrid=nexus::config::parse_kdl(hybrid_config);
    if (!hybrid || !hybrid->vless || hybrid->vless->key_exchange!=nexus::config::TlsKeyExchange::x25519_mlkem768) return 1;
    auto strict=nexus::config::parse_kdl(replace(vless_config,"verify #true", "verify #true; key-exchange \"x25519-mlkem768-only\""));
    if (!strict || !strict->vless || strict->vless->key_exchange!=nexus::config::TlsKeyExchange::x25519_mlkem768_only) return 1;
    auto classical=nexus::config::parse_kdl(replace(vless_config,"verify #true", "verify #true; key-exchange \"x25519\""));
    if (!classical || !classical->vless || classical->vless->key_exchange!=nexus::config::TlsKeyExchange::x25519) return 1;
    auto bootstrap_config=replace(vless_config,"server host=\"127.0.0.1\"", "bootstrap-resolver \"boot\"; server host=\"edge.example\"");
    bootstrap_config=replace(bootstrap_config,"routing {", "dns { server \"boot\" type=\"udp\" host=\"127.0.0.1\"; }\n routing {");
    auto vless_bootstrap=nexus::config::parse_kdl(bootstrap_config);
    if (!vless_bootstrap || !vless_bootstrap->vless || vless_bootstrap->vless->bootstrap_index!=0) { std::cerr << "bootstrap: " << (vless_bootstrap ? "missing index" : vless_bootstrap.error()) << "\n"; return 1; }
    if (nexus::config::parse_kdl(replace(bootstrap_config,"bootstrap-resolver \"boot\"", "bootstrap-resolver \"missing\""))) return 1;
    if (nexus::config::parse_kdl(replace(bootstrap_config,"edge.example", "127.0.0.1"))) return 1;
    if (nexus::config::parse_kdl(replace(bootstrap_config,"bootstrap-resolver \"boot\";", "bootstrap-resolver \"boot\"; bootstrap-resolver \"boot\";"))) return 1;
    auto route_direct=nexus::config::parse_kdl(replace(vless_config,"outbound=\"reject\"","outbound=\"direct\""));
    if (!route_direct || route_direct->rule_action!=nexus::config::RouteAction::direct ||
        route_direct->default_action!=nexus::config::RouteAction::vless) return 1;
    auto route_vless=nexus::config::parse_kdl(replace(replace(vless_config,"outbound=\"reject\"","outbound=\"edge\""),
                                                        "default-outbound \"edge\"","default-outbound \"direct\""));
    if (!route_vless || route_vless->rule_action!=nexus::config::RouteAction::vless ||
        route_vless->default_action!=nexus::config::RouteAction::direct) return 1;
    auto second_vless=replace(vless_node,"\"edge\"","\"edge2\"");
    auto multi_vless=replace(vless_config,"routing {",second_vless+"routing {");
    multi_vless=replace(multi_vless,"outbound=\"reject\"","outbound=\"edge2\"");
    auto multiple_vless=nexus::config::parse_kdl(multi_vless);
    if (!multiple_vless || multiple_vless->vless_outbounds.size()!=2 || multiple_vless->default_outbound!=2 ||
        multiple_vless->routes.size()!=1 || multiple_vless->routes[0].outbound!=3) return 1;
    if (nexus::config::parse_kdl(replace(multi_vless,"outbound \"edge2\"","outbound \"edge\""))) return 1;
    auto many=vless_config;
    for (int i=2;i<=16;++i) {
        auto name="edge"+std::to_string(i);
        auto node=replace(vless_node,"\"edge\"","\""+name+"\"");
        many=replace(many,"routing {",node+"routing {\n rule kind=\"rule-set\" value=\"blocked\" outbound=\""+name+"\"");
    }
    if (auto parsed=nexus::config::parse_kdl(many); !parsed || parsed->vless_outbounds.size()!=16) return 1;
    auto too_many=replace(many,"routing {",replace(vless_node,"\"edge\"","\"edge17\"")+"routing {");
    if (nexus::config::parse_kdl(too_many)) return 1;
    auto ordered=replace(complete,"routing {", "routing {\n    rule-set \"other\" path=\"other.beve\" format=\"beve\"\n    rule kind=\"rule-set\" value=\"other\" outbound=\"direct\"");
    auto ordered_config=nexus::config::parse_kdl(ordered);
    if (!ordered_config || ordered_config->routes.size()!=2 ||
        ordered_config->routes[0].file.path!="other.beve" || ordered_config->routes[0].file.format!=nexus::config::RuleFormat::beve ||
        ordered_config->routes[0].action!=nexus::config::RouteAction::direct ||
        ordered_config->routes[1].action!=nexus::config::RouteAction::block) return 1;
    std::vector<std::pair<std::string, std::string>> cases{
        {replace(vless_config, "verify #true", "verify #false"), "disabled TLS verification"},
        {replace(vless_config, "verify #true", ""), "missing TLS verification"},
        {replace(vless_config, "verify #true", "verify #true; verify #true"), "duplicate TLS verification"},
        {replace(vless_config, "verify #true", "verify #true; key-exchange \"unsupported\""), "unsupported TLS key exchange"},
        {replace(vless_config, "verify #true", "verify #true; key-exchange \"x25519\"; key-exchange \"x25519-mlkem768\""), "duplicate TLS key exchange"},
        {replace(vless_config, "uuid-file \"/tmp/edge.uuid\"", "uuid-file \"edge.uuid\""), "relative UUID file"},
        {replace(vless_config, "ca-file \"/tmp/ca.pem\"", "ca-file \"ca.pem\""), "relative CA file"},
        {replace(vless_config, "port=443", "port=0"), "zero VLESS server port"},
        {replace(vless_config, "server-name \"edge.example\"", "server-name \"\""), "empty TLS name"},
        {replace(vless_config, "default-outbound \"edge\"", "default-outbound \"direct\""), "unused VLESS outbound"},
        {replace(vless_config, "outbound \"edge\"", "outbound \"direct\""), "duplicate VLESS name"},
        {replace(vless_config, "server host=", "unsupported #true; server host="), "unknown VLESS node"},
        {replace(complete, "schema-version 1", "schema-version 2"), "wrong version"},
        {complete + "schema-version 1\n", "duplicate version"},
        {replace(complete, "role \"client\"", "role \"router\""), "wrong role"},
        {replace(complete, "type=\"socks5\"", "type=\"http\""), "unsupported inbound"},
        {replace(complete, "host=\"127.0.0.1\"", "host=\"0.0.0.0\""), "untrusted listener"},
        {replace(complete, "port=1080", "port=0"), "zero port"},
        {replace(complete, "port=1080", "port=65536"), "oversized port"},
        {replace(complete, "port=1080", "port=-1"), "negative port"},
        {replace(complete, "port=1080", "port=\"1080\""), "string port"},
        {replace(complete, "authentication \"none\"", "authentication \"password\""), "unsupported authentication"},
        {replace(authenticated, "type=\"socks5\"", "type=\"mixed\""), "mixed authentication bypass"},
        {replace(authenticated, "password-file=\"/tmp/password\"", "password-file=\"relative\""), "relative password"},
        {replace(authenticated, "username=\"alice\"", "username=\"\""), "empty username"},
        {replace(authenticated, "username=\"alice\"", "username=\"a\\u{0}b\""), "NUL username"},
        {replace(authenticated, "password-file=\"/tmp/password\"", "password-file=\"/tmp/x\\u{0}y\""), "NUL password path"},
        {replace(complete, "authentication \"none\"", ""), "missing authentication"},
        {replace(complete, "authentication \"none\"", "authentication \"none\"; authentication \"none\""), "duplicate authentication"},
        {replace(complete, "type=\"direct\"", "type=\"vless\""), "unsupported outbound"},
        {replace(complete, "outbound \"reject\"", "outbound \"direct\""), "duplicate names"},
        {replace(complete, "default-outbound \"direct\"", "default-outbound \"reject\""), "unsupported default"},
        {replace(complete, "value=\"blocked\"", "value=\"missing\""), "missing rule set"},
        {replace(complete, "outbound=\"reject\"", "outbound=\"missing\""), "unknown rule action"},
        {replace(complete, "format=\"kdl\"", "format=\"json\""), "unsupported format"},
        {replace(complete, "path=\"rules/blocked.kdl\"", "path=\"\""), "empty path"},
        {replace(complete, "path=\"rules/blocked.kdl\"", "path=\"rules\\u{0}x\""), "NUL path"},
        {replace(complete, "routing {", "routing {\n    rule-set \"blocked\" path=\"other.kdl\" format=\"kdl\""), "duplicate rule-set"},
        {replace(complete, "routing {", "routing {\n    rule-set \"unused\" path=\"other.kdl\" format=\"kdl\""), "unreferenced rule-set"},
        {replace(complete, "routing {", "routing {\n    sniff #true"), "unknown routing node"},
        {complete + "dns {}\n", "unsupported top-level node"},
        {replace(complete, "role \"client\"", "role (x)\"client\""), "tagged role"},
        {std::string(nexus::config::max_config_bytes + 1, ' '), "oversized input"},
    };
    for (auto const& [input, description] : cases) {
        if (nexus::config::parse_kdl(input)) {
            std::cerr << "invalid configuration accepted: " << description << '\n'; return 1;
        }
    }
    std::cout << "KDL configuration parsing and validation passed\n";
}
