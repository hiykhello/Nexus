import std;
import config;
import rules;

namespace {
    auto require(bool ok, std::string_view msg) -> void {
        if (!ok) {
            std::cerr << "FAIL: " << msg << '\n';
            std::exit(1);
        }
    }
}

int main() {
    // 1. Canonical vs ergonomic full equivalence (inbounds/outbounds/host:port/members/dns/routing).
    {
        constexpr std::string_view canonical_kdl = R"kdl(
schema-version 1
role "client"
workers 2
inbounds {
    inbound "socks-in" type="socks5" {
        listen host="127.0.0.1" port=1080
        authentication "none"
    }
    inbound "mixed-v6" type="mixed" {
        listen host="::1" port=1080
        authentication "none"
    }
}
outbounds {
    outbound "direct" type="direct"
    outbound "block" type="block"
    outbound "v6-peer" type="vless" {
        server host="edge.example.test" port=443
        authentication { uuid-file "/tmp/edge.uuid"; }
        tls { server-name "edge.example.test"; ca-file "/tmp/ca.pem"; verify #true; }
    }
    outbound "grp" type="selector" {
        member "v6-peer"
        member "direct"
        selected "v6-peer"
    }
}
dns {
    servers {
        local "sys"
        udp "cf" host="1.1.1.1" port=53
    }
    rules {
        - domain-suffix="internal.example" server="sys"
        - domain="one.one.one.one" server="sys"
    }
    final "cf"
}
routing {
    rulesets {
        geo-ads path="/tmp/ads.srs" format="srs"
    }
    tcp-program sniff-timeout-ms=300 unknown="skip" udp=#true {
        rule action="sniff"
        rule action="resolve" route-only=#true
        rule action="route" outbound="direct" {
            or {
                domain-suffix "lan"
                domain-suffix "local"
            }
        }
        rule action="route" rule-set="geo-ads" outbound="block"
        rule action="reject" method="drop" {
            domain "blocked.test"
        }
        rule action="hijack-dns" {
            port 53
        }
        rule action="bypass" outbound="direct" {
            dscp 46 48
        }
        rule action="route" outbound="direct" {
            source-port 5000
        }
    }
    final "grp"
}
)kdl";

        constexpr std::string_view ergonomic_kdl = R"kdl(
schema-version 1
role "client"
workers 2
inbounds {
    socks5 "socks-in" {
        listen "127.0.0.1:1080"
        authentication "none"
    }
    mixed "mixed-v6" {
        listen "[::1]:1080"
        authentication "none"
    }
}
outbounds {
    direct
    block
    vless "v6-peer" {
        server "edge.example.test:443"
        authentication { uuid-file "/tmp/edge.uuid"; }
        tls { server-name "edge.example.test"; ca-file "/tmp/ca.pem"; verify #true; }
    }
    selector "grp" {
        members "v6-peer" "direct"
        selected "v6-peer"
    }
}
dns {
    servers {
        local "sys"
        udp "cf" host="1.1.1.1" port=53
    }
    rules {
        - domain-suffix "internal.example" to="sys"
        - domain "one.one.one.one" to="sys"
    }
    final "cf"
}
routing {
    rulesets {
        geo-ads path="/tmp/ads.srs" format="srs"
    }
    rules sniff-timeout-ms=300 unknown="skip" udp=#true {
        - sniff
        - resolve route-only=#true
        - domain-suffix "lan" "local" to="direct"
        - rule-set "geo-ads" to="block"
        - domain "blocked.test" action="reject" method="drop"
        - port 53 action="hijack-dns"
        - dscp 46 48 action="bypass" to="direct"
        - to="direct" {
            source-port 5000
        }
        - final "grp"
    }
}
)kdl";

        auto c1 = config::parse_kdl(canonical_kdl);
        auto c2 = config::parse_kdl(ergonomic_kdl);
        require(c1.has_value(), c1 ? "" : "canonical: " + c1.error());
        require(c2.has_value(), c2 ? "" : "ergonomic: " + c2.error());

        require(c1->inbounds.size() == 2 && c2->inbounds.size() == 2, "2 inbounds");
        require(c2->inbounds[1].listen_ipv6 && c2->inbounds[1].port == 1080, "ipv6 bracket listen");
        require(c2->direct_outbound_name == "direct" && c2->block_outbound_name == std::optional<std::string>("block"),
            "auto direct/block names");
        require(c2->selectors.size() == 1 && c2->selectors[0].members.size() == 2 &&
            c2->selectors[0].members[0] == "v6-peer" && c2->selectors[0].members[1] == "direct", "members expansion");
        require(c2->default_outbound_name == "grp" && c2->default_outbound == 2, "lifted default outbound");
        require(c2->dns && c2->dns->rules.size() == 2 && c2->dns->rules[0].suffix &&
            c2->dns->rules[0].domain == "internal.example" && c2->dns->rules[0].server == 0, "dns shorthand");
        require(c2->ordered_tcp && c1->ordered_tcp &&
            c2->ordered_tcp->rules.size() == c1->ordered_tcp->rules.size() && c2->ordered_tcp->udp, "ordered rules count");
        require(c2->ordered_tcp->rules[2].predicates == c1->ordered_tcp->rules[2].predicates, "multi-value or predicates");
        require(c2->ordered_tcp->rules[3].set_tag == std::optional<std::string>("geo-ads") &&
            c2->ordered_tcp->rules[3].outbound == 1, "rule-set target");
        require(c2->ordered_tcp->rules[4].reject_method == rules::RejectMethod::drop, "reject method");
        require(c2->ordered_tcp->rules[6].predicates == c1->ordered_tcp->rules[6].predicates, "dscp multi-arg");

        auto id1 = config::reload_identity(canonical_kdl, config::ReloadIdentity::full);
        auto id2 = config::reload_identity(ergonomic_kdl, config::ReloadIdentity::full);
        require(id1.has_value() && id2.has_value() && *id1 == *id2,
            "reload_identity canonical == ergonomic mismatch:\n1:\n" + (id1 ? *id1 : id1.error()) +
            "\n2:\n" + (id2 ? *id2 : id2.error()));
    }

    // 2. Expanded typed group names (naive, shadowtls, tuic, masque, wireguard, ssh, reality fallback host:port).
    {
        constexpr std::string_view expanded_kdl = R"kdl(
schema-version 1
role "client"
inbounds {
    fixed-tcp "redir" {
        listen "127.0.0.1:1082"
        target "203.0.113.10:8080"
    }
    shadowtls "st-in" {
        listen "127.0.0.1:8443"
        handshake host="cover.test" port=443
        target "127.0.0.1:1080"
        authentication { user "u1" password-file="/tmp/pw"; }
    }
    tuic "tuic-in" {
        listen "127.0.0.1:9443"
        authentication { user "u1" uuid-file="/tmp/uuid" password-file="/tmp/pw"; }
        tls { certificate-file "/tmp/cert.pem"; private-key-file "/tmp/key.pem"; }
    }
}
outbounds {
    direct
    naive "n-out" {
        server "naive.example.test:443"
        authentication username="alice" password-file="/tmp/pw"
        tls { server-name "naive.example.test"; ca-file "/tmp/ca.pem"; verify #true; }
    }
    ssh "ssh-out" {
        server "ssh.example.test:2222"
        user "ops"
        private-key-file "/tmp/id"
        host-key-sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    }
    selector "mix" {
        members "n-out" "ssh-out"
    }
}
routing {
    final "mix"
}
)kdl";
        auto cfg = config::parse_kdl(expanded_kdl);
        require(cfg.has_value(), cfg ? "" : "expanded typed: " + cfg.error());
        require(cfg->inbounds.size() == 3 &&
            cfg->inbounds[0].fixed_tcp && cfg->inbounds[0].fixed_tcp->port == 8080 &&
            cfg->inbounds[1].type == config::Inbound::shadowtls &&
            cfg->inbounds[2].type == config::Inbound::tuic, "expanded inbound types + fixed-tcp target");
        require(cfg->naive_outbounds.size() == 1 && cfg->ssh_outbounds.size() == 1 &&
            cfg->ssh_outbounds[0].config.port == 2222, "expanded outbound types");
        require(cfg->default_outbound_name == "mix", "routing final outbound");
    }

    // 3. Negative / malformed shorthand rejection.
    {
        auto base = [](std::string_view extra) {
            return std::string("schema-version 1\nrole \"client\"\ninbounds { socks5 \"s\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\noutbounds { direct; }\n") + std::string(extra);
        };
        std::string const invalid_cases[] = {
            base("routing { rules { - sniff; }; tcp-program sniff-timeout-ms=100 unknown=\"skip\" {}; final \"direct\"; }\n"),
            base("routing { rules bad=1 { - sniff; }; final \"direct\"; }\n"),
            base("routing { rules { - domain \"a.test\" to=\"direct\" outbound=\"direct\"; }; final \"direct\"; }\n"),
            base("routing { rules { - unknownpred \"a.test\" to=\"direct\"; }; final \"direct\"; }\n"),
            base("routing { rules { - domain \"a.test\"; }; final \"direct\"; }\n"),
            base("routing { final \"direct\"; final \"direct\"; }\n"),
            base("routing { rulesets { s path=\"/tmp/s.kdl\" format=\"kdl\"; }; rule kind=\"rule-set\" value=\"s\" outbound=\"direct\"; final \"direct\"; }\n"),
            "schema-version 1\nrole \"client\"\ninbounds { socks5 \"s\" { listen \"::1:1080\"; authentication \"none\"; }; }\noutbounds { direct; }\nrouting { final \"direct\"; }\n",
            "schema-version 1\nrole \"client\"\ninbounds { socks5 \"s\" { listen \"127.0.0.1:0\"; authentication \"none\"; }; }\noutbounds { direct; }\nrouting { final \"direct\"; }\n",
            "schema-version 1\nrole \"client\"\ninbounds { socks5 \"s\" { listen \"[127.0.0.1]:1080\"; authentication \"none\"; }; }\noutbounds { direct; }\nrouting { final \"direct\"; }\n",
            "schema-version 1\nrole \"client\"\ndns { servers { local \"a\"; }; rules { - domain \"x.test\" to=\"a\" server=\"a\"; }; }\ninbounds { socks5 \"s\" { listen \"127.0.0.1:1080\"; authentication \"none\"; }; }\noutbounds { direct; }\nrouting { final \"direct\"; }\n",
        };
        for (std::size_t i = 0; i < std::size(invalid_cases); ++i) {
            require(!config::parse_kdl(invalid_cases[i]).has_value(),
                "invalid case " + std::to_string(i) + " unexpectedly accepted");
        }
    }

    std::cout << "BATCH 173 KDL ERGONOMICS UNIT TESTS PASSED\n";
    return 0;
}
