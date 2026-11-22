import std;
import tailscale.control;
import tailscale.control_messages;
import tailscale.snapshot;
import tailscale.map_session;
namespace c=tailscale::control;namespace m=tailscale::control_messages;
namespace s=tailscale::snapshot;namespace ms=tailscale::map_session;

auto require(bool condition,int code)->void {if(!condition) {std::println("failed {}",code);std::exit(code);}}
auto wrap(std::string_view json)->std::vector<std::uint8_t> {
    auto n=json.size();std::vector<std::uint8_t> out{std::uint8_t(n),std::uint8_t(n>>8),std::uint8_t(n>>16),std::uint8_t(n>>24)};
    out.insert(out.end(),json.begin(),json.end());return out;
}
auto main()->int {
    std::array<std::uint8_t,32> bytes{};bytes.fill(0x11);auto key=*c::NodePublic::from_bytes(bytes);
    auto state=std::make_unique<ms::State>();auto scratch=std::make_unique<s::Scratch>();
    auto candidate=std::make_unique<m::MapCandidate>();std::vector<std::uint8_t> buffer(m::max_json_bytes);
    auto node=std::format(R"({{"Node":{{"ID":1,"Key":"nodekey:{}"}},"Peers":[{{"ID":2,"Key":"nodekey:{}"}}]}})",std::string(64,'1'),std::string(64,'2'));
    auto node_filter=node.substr(0,node.size()-1)+R"(,"PacketFilter":[]})";
    auto node_bytes=std::span(reinterpret_cast<std::uint8_t const*>(node_filter.data()),node_filter.size());
    auto strict=m::parse_map(node_bytes,{key,1,1},*candidate);
    require(!strict && strict.error().error==m::Error::unsupported_security && !candidate->view(),1);
    {
        ms::Session stream({key,1,1},buffer,*candidate,*state,*scratch);
        require(stream.active(),2);
        auto initial=wrap(node);for(auto byte:initial) {auto r=stream.feed(std::span(&byte,1));require(!r.error && r.consumed==1,3);}
        require(!state->ready() && state->peers().empty() && state->policy_chunks().empty(),4);
        auto filter=wrap(R"({"PacketFilter":[]})");auto ok=stream.feed(filter);
        require(!ok.error && state->ready() && state->peers().size()==1 && state->policy_chunks().size()==1,5);
        auto delta=wrap(std::format(R"({{"PeersRemoved":[2],"PeersChanged":[{{"ID":3,"Key":"nodekey:{}"}}],"PacketFilters":{{"base":null,"new":[]}}}})",std::string(64,'3')));
        ok=stream.feed(delta);require(!ok.error && state->ready() && state->peers().size()==1 && state->peers()[0].id==3 && state->policy_chunks().size()==1 && state->policy_chunks()[0].name=="new",6);
        {ms::Session competing({key,2,1},buffer,*candidate,*state,*scratch);require(!competing.active(),7);}
        require(state->ready() && state->peers()[0].id==3,8);
        auto bad_policy=wrap(std::format(R"({{"PeersChanged":[{{"ID":4,"Key":"nodekey:{}"}}],"PacketFilter":[{{"SrcIPs":["cap:example"]}}]}})",std::string(64,'4')));
        auto failed=stream.feed(bad_policy);
        require(failed.error==ms::Error::policy && !stream.active() && !state->ready() && state->peers().empty() && state->policy_chunks().empty() && scratch->peers.empty(),9);
    }
    {
        ms::Session stream({key,1,2},buffer,*candidate,*state,*scratch);require(stream.active(),10);
        auto initial=wrap(node_filter);require(!stream.feed(initial).error && state->ready(),11);
        auto forbidden=wrap(R"({"TKAInfo":{}})");auto failed=stream.feed(forbidden);
        require(failed.error==ms::Error::parse && !state->ready() && state->peers().empty() && state->policy_chunks().empty(),12);
    }
    {
        ms::Session stream({key,1,3},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),13);
        auto bad_peer=wrap(std::format(R"({{"Node":{{"ID":9,"Key":"nodekey:{}"}},"PacketFilters":{{"added":[]}}}})",std::string(64,'1')));
        auto failed=stream.feed(bad_peer);require(failed.error==ms::Error::snapshot && !state->ready() && state->policy_chunks().empty(),14);
    }
    {
        ms::Session stream({key,1,4},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),15);
        auto keep=wrap(R"({"KeepAlive":true,"PacketFilter":[]})");require(stream.feed(keep).error==ms::Error::parse && !state->ready(),16);
    }
    {
        ms::Session stream({key,1,5},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),17);
        std::array<std::uint8_t,2> partial{2,0};require(!stream.feed(partial).error,18);
        require(!stream.eof() && !state->ready() && state->policy_chunks().empty(),19);
    }
    {
        ms::Session stream({key,1,6},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),20);
        require(bool(stream.eof()) && !state->ready() && state->peers().empty(),21);
    }
    {ms::Session stale({key,1,6},buffer,*candidate,*state,*scratch);require(!stale.active(),22);}
    {
        ms::Session stream({key,1,7},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),23);
        // Destruction while active must revoke with all borrowed owners alive.
    }
    require(!state->ready() && state->peers().empty() && state->policy_chunks().empty() && scratch->peers.empty(),24);
    {
        ms::Session stream({key,1,8},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        require(stream.active() && !stream.feed(initial).error && state->ready(),25);
        auto overlap=stream.feed(std::span(buffer).first(1));
        require(overlap.error==ms::Error::frame && overlap.consumed==0 && !state->ready(),26);
    }
    {
        ms::Session stream({key,1,9},buffer,*candidate,*state,*scratch);auto initial=wrap(node_filter);
        auto bad=wrap(R"({"TKAInfo":{}})");initial.insert(initial.end(),bad.begin(),bad.end());
        auto result=stream.feed(initial);
        require(result.error==ms::Error::parse && !state->ready() && state->peers().empty() && state->policy_chunks().empty(),27);
    }
    std::println("Tailscale Map policy projection, atomic revocation and strict security rejection passed");
}
