import std;
import quic.packet_keys;
import quic.packet_protection;
import quic.connection;
struct Handshake {};
struct Application {};
int main() {std::println("PacketKeys={} Protection={} Connection={}",sizeof(quic::PacketKeys),sizeof(quic::PacketProtection<>),sizeof(quic::Connection<Handshake,Application>));}
