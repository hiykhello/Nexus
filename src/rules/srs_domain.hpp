// Included in rules.srs_payload's private namespace after Reader.
// SRS stores a breadth-first trie as zero-labelled edges and one terminator
// per node. Rebuild parent links once; never repeatedly scan the bitmap.
auto read_domain_set(Reader& reader,std::vector<Rule>& group) -> std::expected<void,Error> {
    auto initial_size=group.size();
    auto version=reader.byte();if(!version || *version!=0)return failure("unsupported SRS domain set version");
    auto words=[&]() -> std::expected<std::vector<std::uint64_t>,Error> {
        auto count=reader.varint();
        if(!count || *count>(reader.input.size()-reader.offset)/8)
            return failure("truncated SRS domain bitmap");
        std::vector<std::uint64_t> result;result.reserve(static_cast<std::size_t>(*count));
        for(std::uint64_t i=0;i<*count;++i) {
            std::uint64_t word=0;
            for(unsigned j=0;j<8;++j)word=(word<<8)|*reader.byte();
            result.push_back(word);
        }
        return result;
    };
    auto leaves=words();if(!leaves)return std::unexpected(std::move(leaves.error()));
    auto bitmap=words();if(!bitmap)return std::unexpected(std::move(bitmap.error()));
    auto count=reader.varint();
    if(!count || *count>reader.input.size()-reader.offset || *count>=max_input_bytes)
        return failure("invalid SRS domain labels");
    auto labels=reader.input.subspan(reader.offset,static_cast<std::size_t>(*count));
    reader.offset+=static_cast<std::size_t>(*count);
    if(labels.empty() || bitmap->empty())return failure("empty SRS domain trie");
    auto bit=[](std::vector<std::uint64_t> const& values,std::size_t index) {
        return index/64<values.size() && (values[index/64] & (std::uint64_t{1}<<(index%64)))!=0;
    };
    struct Node {std::uint32_t parent;std::uint16_t depth;std::uint8_t label;bool children=false;};
    std::vector<Node> nodes;nodes.reserve(labels.size()+1);nodes.push_back({0,0,0});
    std::size_t pos=0,edge=0;
    for(std::size_t parent=0;parent<nodes.size();++parent) {
        std::array<bool,256> seen{};
        while(pos<bitmap->size()*64 && !bit(*bitmap,pos)) {
            if(edge>=labels.size() || nodes[parent].depth>=254)return failure("invalid SRS domain trie topology");
            auto label=labels[edge++];
            if(seen[label])return failure("duplicate SRS domain edge");seen[label]=true;
            nodes[parent].children=true;
            nodes.push_back({static_cast<std::uint32_t>(parent),static_cast<std::uint16_t>(nodes[parent].depth+1),label});
            ++pos;
        }
        if(pos==bitmap->size()*64)return failure("unterminated SRS domain node");
        ++pos;
    }
    if(edge!=labels.size())return failure("unreachable SRS domain edges");
    for(auto i=pos;i<bitmap->size()*64;++i)if(bit(*bitmap,i))return failure("extra SRS domain nodes");
    for(auto i=nodes.size();i<leaves->size()*64;++i)if(bit(*leaves,i))return failure("extra SRS domain leaves");
    if(bit(*leaves,0))return failure("empty SRS domain");
    for(std::size_t i=1;i<nodes.size();++i) {
        if(!bit(*leaves,i))continue;
        std::string name;name.reserve(nodes[i].depth);
        for(auto cursor=i;cursor;cursor=nodes[cursor].parent)name.push_back(static_cast<char>(nodes[cursor].label));
        bool root=name.front()=='\n',subdomains=name.front()=='\r';
        if(root || subdomains) {
            if(nodes[i].children)return failure("nonterminal SRS suffix marker");
            name.erase(0,1);
            if(subdomains) {
                if(name.empty() || name.front()!='.')return failure("invalid SRS subdomain suffix");
                name.erase(0,1);
            }
        }
        if(!valid_domain(name) || std::ranges::any_of(name,[](char c){return c>='A' && c<='Z';}))
            return failure("unsupported SRS domain name or uppercase condition");
        if(!reader.take_node())return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
        Rule suffix{root || subdomains ? "domain-suffix" : "domain",name,{}};
        if(subdomains) {
            // A leading-dot suffix excludes the apex. Nexus suffix includes it.
            if(!reader.take_node() || !reader.take_node() || !reader.take_node())
                return std::unexpected(Error{ErrorCode::limit,"SRS rule count exceeds limit"});
            Rule exact{"domain",name,{}};
            Rule negated{"not",{},std::vector<Rule>{std::move(exact)}};
            group.push_back({"and",{},std::vector<Rule>{std::move(suffix),std::move(negated)}});
        } else group.push_back(std::move(suffix));
    }
    if(group.size()==initial_size)return failure("SRS domain set has no leaves");
    return {};
}
