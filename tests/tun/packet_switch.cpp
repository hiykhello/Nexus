import std;
import packet.mux;
namespace p = ::packet;
int main() {
    p::MemoryLink device({1500,1,1500}), tcp({1500,1,1500}), udp({1500,1,1500});
    p::MemorySwitch sw(device,tcp,udp);
    p::Bytes ip4tcp(20), ip4udp(20), ip6udp(40), invalid(20);
    ip4tcp[0]=0x45; ip4tcp[9]=6; ip4udp[0]=0x45; ip4udp[9]=17; ip6udp[0]=0x60; ip6udp[6]=17;
    invalid[0]=0x45; invalid[9]=1;
    auto pop=[](p::MemoryLink& link,p::Side side) -> std::optional<p::Bytes> {
        auto result=link.receive(side); if (!result || !*result) return {}; return std::move(**result);
    };
    if (!device.send(p::Side::first,ip4tcp)) return 1;
    auto one=sw.step(); if (!one || !one->input_delivered || pop(tcp,p::Side::second)!=ip4tcp) return 1;
    if (!udp.send(p::Side::first,ip4udp) || !device.send(p::Side::first,ip6udp)) return 1;
    auto blocked=sw.step(); if (!blocked || !blocked->input_backpressured) return 1;
    if (pop(udp,p::Side::second)!=ip4udp) return 1;
    auto retry=sw.step(); if (!retry || !retry->input_delivered || pop(udp,p::Side::second)!=ip6udp) return 1;
    if (!device.send(p::Side::first,invalid)) return 1;
    auto rejected=sw.step(); if (!rejected || rejected->rejected!=p::SwitchReject::unsupported_packet) return 1;
    p::Bytes tcp_reply{1}, udp_reply{2}, sentinel{3};
    if (!device.send(p::Side::second,sentinel) || !tcp.send(p::Side::second,tcp_reply) || !udp.send(p::Side::second,udp_reply)) return 1;
    auto output_blocked=sw.step(); if (!output_blocked || !output_blocked->output_backpressured) return 1;
    if (pop(device,p::Side::first)!=sentinel) return 1;
    auto first=sw.step(); if (!first || !first->output_delivered || pop(device,p::Side::first)!=tcp_reply) return 1;
    auto second=sw.step(); if (!second || !second->output_delivered || pop(device,p::Side::first)!=udp_reply) return 1;
    // A lone UDP reply must not steal TCP's turn when both become ready.
    if (!udp.send(p::Side::second,udp_reply)) return 1;
    auto lone=sw.step(); if (!lone || !lone->output_delivered || pop(device,p::Side::first)!=udp_reply) return 1;
    if (!tcp.send(p::Side::second,tcp_reply) || !udp.send(p::Side::second,udp_reply)) return 1;
    auto fair=sw.step(); if (!fair || !fair->output_delivered || pop(device,p::Side::first)!=tcp_reply) return 1;
    auto last=sw.step(); if (!last || !last->output_delivered || pop(device,p::Side::first)!=udp_reply) return 1;
    p::MemoryLink dual_device, dual4, dualudp, dual6;
    p::MemorySwitch dual(dual_device,dual4,dualudp,dual6);
    p::Bytes extended(56); extended[0]=0x60; extended[6]=0;
    extended[40]=60; extended[48]=6;
    if (!dual_device.send(p::Side::first,extended)) return 1;
    auto routed=dual.step();
    if (!routed || !routed->input_delivered || pop(dual6,p::Side::second)!=extended) return 1;
    extended[48]=17;
    if (!dual_device.send(p::Side::first,extended)) return 1;
    routed=dual.step();
    if (!routed || !routed->input_delivered || pop(dualudp,p::Side::second)!=extended) return 1;
    device.close(p::Side::first);
    auto closed=sw.step(); if (closed || closed.error()!=p::DeviceError::peer_closed) return 1;
    std::cout << "packet switch routing, fairness and backpressure passed\n";
}
