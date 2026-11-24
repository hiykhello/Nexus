import std;
import relay;

int main(int argc, char** argv) {
    if (argc!=3) return 1;
    relay::Server prepared;
    if (!prepared.prepare_vless("127.0.0.1",443,argv[1],"server.example",argv[2])) return 2;
    if (prepared.prepare_vless("127.0.0.1",443,argv[1],"server.example",argv[2],static_cast<relay::TlsKeyExchange>(99))) return 13;
    relay::Server hybrid;
    if (!hybrid.prepare_vless("127.0.0.1",443,argv[1],"server.example",argv[2],relay::TlsKeyExchange::x25519_mlkem768)) return 14;
    relay::Server strict;
    if (!strict.prepare_vless("127.0.0.1",443,argv[1],"server.example",argv[2],relay::TlsKeyExchange::x25519_mlkem768_only)) return 15;
    relay::Server bootstrap;
    if (bootstrap.prepare_vless("edge.example",443,argv[1],"server.example",argv[2],relay::TlsKeyExchange::x25519,0)) return 16;
    relay::DnsRouting dns;
    dns.servers.resize(2);
    if (!bootstrap.set_dns_routing(dns)) return 17;
    if (!bootstrap.prepare_vless("edge.example",443,argv[1],"server.example",argv[2],relay::TlsKeyExchange::x25519,1)) return 18;
    dns.servers.resize(1);
    if (bootstrap.set_dns_routing(dns)) return 19;
    if (!bootstrap.prepare_vless("edge.example",443,argv[1],"server.example",argv[2],relay::TlsKeyExchange::x25519,1)) return 23;
    if (!bootstrap.start(0)) return 20;
    bootstrap.stop();
    if (!bootstrap.prepare_vless("edge.example",443,argv[1],"server.example",argv[2])) return 21;
    if (!bootstrap.set_dns_routing(dns)) return 22;
    auto start=prepared.start(0);
    if (!start) return 3;
    if (prepared.prepare_vless("127.0.0.1",0,argv[1],"server.example",argv[2])) return 4;
    prepared.stop();
    if (prepared.prepare_vless("127.0.0.1",0,argv[1],"server.example",argv[2])) return 5;
    if (!prepared.start(0)) return 5; // Failed replacement must not discard the prepared profile.
    prepared.stop();
    relay::Server running;
    if (!running.start(0)) return 6;
    if (running.prepare_vless("127.0.0.1",443,argv[1],"server.example",argv[2])) return 7;
    running.stop();
    relay::Server indexed;
    for (std::size_t i=0;i<16;++i) {
        auto added=indexed.add_vless("127.0.0.1",443,argv[1],"server.example",argv[2]);
        if (!added || *added!=i+2) return 8;
    }
    if (indexed.add_vless("127.0.0.1",443,argv[1],"server.example",argv[2])) return 9;
    if (indexed.set_indexed_routes({},18) || !indexed.set_indexed_routes({},17)) return 10;
    if (!indexed.start(0)) return 11;
    if (indexed.add_vless("127.0.0.1",443,argv[1],"server.example",argv[2])) return 12;
    indexed.stop();
    std::cout << "VLESS preparation and server lifecycle passed\n";
}
