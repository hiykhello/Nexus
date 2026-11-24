module tailscale.control_messages;
import std;
import containers.inplace_vector;
import crypto;
import glaze;
import corosio;

namespace tailscale::control_messages {
    namespace detail {
        using Raw=glaze::raw_json_view;
        struct EmptyObject {};
        struct RegisterJson {Raw User,Login,NodeKeyExpired,MachineAuthorized,AuthURL,NodeKeySignature,Error;};
        struct NodeJson {
            Raw ID,StableID,Name,User,Key,KeyExpiry,Machine,DiscoKey,Addresses,AllowedIPs,Endpoints,HomeDERP;
            Raw Hostinfo,Created,Cap,Tags,PrimaryRoutes,LastSeen,Online,MachineAuthorized,Expired;
            Raw KeySignature,Capabilities,CapMap,UnsignedPeerAPIOnly,SelfNodeV4MasqAddrForThisPeer,SelfNodeV6MasqAddrForThisPeer;
        };
        struct MapJson {
            Raw MapSessionHandle,Seq,KeepAlive,Node,DERPMap,Peers,PeersChanged,PeersRemoved,DNSConfig,Domain,ControlTime;
            Raw PacketFilter,PacketFilters,TKAInfo,PeersChangedPatch,PeerSeenChange,OnlineChange;
        };
        struct DerpMapJson {Raw HomeParams,Regions,omitDefaultRegions;};
        struct DerpRegionJson {Raw RegionID,RegionCode,RegionName,Latitude,Longitude,Avoid,NoMeasureNoHome,Nodes;};
        struct DerpNodeJson {Raw Name,RegionID,HostName,CertName,IPv4,IPv6,STUNPort,STUNOnly,DERPPort,InsecureForTests,STUNTestIP,CanPort80;};
    }
    namespace {
        using detail::Raw;
        using detail::EmptyObject;
        using detail::RegisterJson;
        using detail::NodeJson;
        using detail::MapJson;
        using detail::DerpMapJson;
        using detail::DerpRegionJson;
        using detail::DerpNodeJson;
        struct Options : glaze::opts {bool validate_trailing_whitespace=true,validate_skipped=true;};
        inline constexpr auto options=[] {Options value;value.null_terminated=false;value.error_on_unknown_keys=true;return value;}();
        auto failure(Error error,unsigned status=0) noexcept -> std::unexpected<Failure> {return std::unexpected(Failure{error,status});}
        auto bytes(std::span<std::uint8_t const> input) noexcept -> std::string_view {return {reinterpret_cast<char const*>(input.data()),input.size()};}
        auto trim(std::string_view text) noexcept -> std::string_view {
            auto space=[](char c) {return c==' ' || c=='\r' || c=='\n' || c=='\t';};
            while (!text.empty() && space(text.front())) text.remove_prefix(1);while (!text.empty() && space(text.back())) text.remove_suffix(1);return text;
        }
        auto field(Raw const& raw) noexcept -> JsonField {
            auto value=trim(raw.str);return {value.empty() ? Presence::missing : value=="null" ? Presence::null_value : Presence::value,value};
        }
        template<class T> auto read(T& value,std::string_view json) -> bool {return !glaze::read<options>(value,json);}
        auto unique_object(std::string_view json) -> std::expected<void,Failure> {
            // Go merges repeated map/object fields. Reject repeats rather
            // than lose an earlier security capability in a last raw slice.
            containers::inplace_vector<std::pair<std::string_view,Raw>,64> fields;
            if (!read(fields,json)) return failure(Error::json);
            for (std::size_t i=0;i<fields.size();++i) {
                if (fields[i].first.contains('\\')) return failure(Error::schema);
                for (std::size_t j=0;j<i;++j) if (fields[i].first==fields[j].first) return failure(Error::duplicate);
            }
            return {};
        }
        auto boolean(Raw const& raw,bool& value) -> bool {auto f=field(raw);return f.presence!=Presence::value || read(value,f.json);}
        auto string(Raw const& raw,std::size_t bound,bool escapes=false) -> std::expected<std::string_view,Failure> {
            auto f=field(raw);if (f.presence!=Presence::value) return std::string_view{};
            if (f.json.size()>bound+2) return failure(Error::limit);
            std::string_view value;if (!read(value,f.json) || (!escapes && value.contains('\\'))) return failure(Error::schema);return value;
        }
        auto nonzero(std::span<std::uint8_t const> value) noexcept -> bool {return std::ranges::any_of(value,[](auto byte) {return byte!=0;});}
        template<class Key> auto public_key(Raw const& raw,std::string_view prefix) -> std::expected<Key,Failure> {
            auto text=string(raw,prefix.size()+64);if (!text) return std::unexpected(text.error());
            if (text->size()!=prefix.size()+64 || !text->starts_with(prefix)) return failure(Error::identity);
            std::array<std::uint8_t,32> value{};
            auto hex=[](char c)->int {return c>='0' && c<='9' ? c-'0' : c>='a' && c<='f' ? c-'a'+10 : c>='A' && c<='F' ? c-'A'+10 : -1;};
            for (unsigned i=0;i<32;++i) {auto a=hex((*text)[prefix.size()+2*i]),b=hex((*text)[prefix.size()+2*i+1]);if (a<0 || b<0) return failure(Error::identity);value[i]=static_cast<std::uint8_t>(a*16+b);}
            if (!nonzero(value)) return failure(Error::identity);
            auto key=Key::from_bytes(value);if (!key) return failure(Error::identity);return *key;
        }
        auto active(Raw const& raw,std::string_view empty) -> bool {
            auto f=field(raw);if (f.presence!=Presence::value) return false;
            if (empty=="[]") {containers::inplace_vector<Raw,1> values;return !read(values,f.json) || !values.empty();}
            if (empty=="{}") {EmptyObject value;return !read(value,f.json);}
            if (empty=="\"\"") {std::string_view value;return !read(value,f.json) || !value.empty();}
            return true;
        }
        struct EraseOutput {std::span<std::uint8_t> output;bool success=false;~EraseOutput() {if (!success) crypto::cleanse(output);}};
        auto safe_text(std::string_view text,std::size_t maximum,bool required=true) noexcept -> bool {
            return (!required || !text.empty()) && text.size()<=maximum && std::ranges::none_of(text,[](unsigned char c) {return c<32 || c==127;});
        }
        auto overlaps(std::span<std::uint8_t> output,std::string_view input) noexcept -> bool {
            if (output.empty() || input.empty()) return false;
            auto one=reinterpret_cast<std::uintptr_t>(output.data()),two=reinterpret_cast<std::uintptr_t>(input.data());
            return one<=two ? two-one<output.size() : one-two<input.size();
        }
        auto endpoint_address(corosio::endpoint const& source) -> Endpoint {
            Endpoint result;result.family=source.is_v4() ? 4 : 6;result.port=source.port();
            if (source.is_v4()) {auto address=source.address().to_v4().to_bytes();std::ranges::copy(address,result.address.begin());}
            else {auto address=source.address().to_v6().to_bytes();std::ranges::copy(address,result.address.begin());}return result;
        }
        auto prefix(Raw const& raw) -> std::expected<Prefix,Failure> {
            auto text=string(raw,64);if (!text) return std::unexpected(text.error());
            auto slash=text->find('/');if (slash==text->npos || !slash || text->find('/',slash+1)!=text->npos) return failure(Error::address);
            auto address=text->substr(0,slash),suffix=text->substr(slash+1);unsigned bits=0;
            if (address.contains('%') || address.contains('[') || address.contains(']')) return failure(Error::address);
            auto parsed=std::from_chars(suffix.data(),suffix.data()+suffix.size(),bits);
            if (parsed.ec!=std::errc{} || parsed.ptr!=suffix.data()+suffix.size()) return failure(Error::address);
            auto format=corosio::detect_endpoint_format(address);
            if (format!=corosio::endpoint_format::ipv4_no_port && format!=corosio::endpoint_format::ipv6_no_port) return failure(Error::address);
            auto [error,source]=corosio::make_endpoint(address);if (error || bits>(source.is_v4() ? 32u : 128u)) return failure(Error::address);
            auto decoded=endpoint_address(source);Prefix result{decoded.address,decoded.family,static_cast<std::uint8_t>(bits)};
            auto whole=bits/8,part=bits%8;
            if (part && (result.address[whole]&((1u<<(8-part))-1))) return failure(Error::address);
            if (!std::ranges::all_of(std::span(result.address).subspan(whole+(part ? 1u : 0u)),[](auto c) {return c==0;})) return failure(Error::address);
            return result;
        }
        auto endpoint(Raw const& raw) -> std::expected<Endpoint,Failure> {
            auto text=string(raw,80);if (!text) return std::unexpected(text.error());if (text->contains('%')) return failure(Error::address);
            auto format=corosio::detect_endpoint_format(*text);
            if (format!=corosio::endpoint_format::ipv4_with_port && format!=corosio::endpoint_format::ipv6_bracketed) return failure(Error::address);
            auto [error,value]=corosio::make_endpoint(*text);
            if (error || !value.port() || value.address().is_unspecified() || value.address().is_multicast()) return failure(Error::address);
            return endpoint_address(value);
        }

        auto key_expiry(std::string_view value) -> std::expected<std::optional<std::chrono::sys_seconds>,Failure> {
            using namespace std::chrono;
            if (value.empty() || value == "0001-01-01T00:00:00Z") return std::optional<sys_seconds>{};
            if (value.size() < 20 || !value.ends_with('Z') || value[4] != '-' || value[7] != '-' ||
                value[10] != 'T' || value[13] != ':' || value[16] != ':') return failure(Error::schema);
            auto number = [value](std::size_t offset, std::size_t length) -> unsigned {
                auto part = value.substr(offset, length);
                if (!std::ranges::all_of(part, [](char c) { return c >= '0' && c <= '9'; })) return 10000;
                unsigned result = 0;
                for (auto c : part) result = result * 10 + static_cast<unsigned>(c - '0');
                return result;
            };
            auto year_value = number(0, 4);
            auto date = year(static_cast<int>(year_value)) / month(number(5, 2)) / day(number(8, 2));
            auto h = number(11, 2), m = number(14, 2), s = number(17, 2);
            if (!year_value || year_value > 9999 || !date.ok() || h > 23 || m > 59 || s > 59) return failure(Error::schema);
            if (value.size() > 20) {
                auto fraction = value.substr(20, value.size() - 21);
                if (value[19] != '.' || fraction.empty() || fraction.size() > 9 ||
                    !std::ranges::all_of(fraction, [](char c) { return c >= '0' && c <= '9'; })) return failure(Error::schema);
            }
            // Round down to the second so coarse precision cannot extend a key's lifetime.
            return std::optional<sys_seconds>{sys_days(date) + hours(h) + minutes(m) + seconds(s)};
        }
        template<std::size_t N,class T,class Parse>
        auto list(Raw const& raw,containers::inplace_vector<T,N>& output,Parse parse) -> std::expected<void,Failure> {
            if (field(raw).presence!=Presence::value) return {};
            containers::inplace_vector<Raw,N> input;if (!read(input,raw.str)) return failure(Error::schema);
            for (auto const& item:input) {
                auto value=parse(item);if (!value) return std::unexpected(value.error());
                if (std::ranges::find(output,*value)!=output.end()) return failure(Error::duplicate);
                output.push_back(std::move(*value));
            }
            return {};
        }
        auto node(Raw const& raw) -> std::expected<PeerCandidate,Failure> {
            if (auto unique=unique_object(raw.str);!unique) return std::unexpected(unique.error());
            NodeJson wire;if (!read(wire,raw.str)) return failure(Error::schema);PeerCandidate result;
            if (!read(result.id,wire.ID.str) || result.id<=0) return failure(Error::identity);
            auto key=public_key<control::NodePublic>(wire.Key,"nodekey:");if (!key) return std::unexpected(key.error());result.key=*key;
            if (active(wire.KeySignature,"\"\"") || active(wire.Capabilities,"[]") || active(wire.CapMap,"{}") ||
                active(wire.SelfNodeV4MasqAddrForThisPeer,"null") || active(wire.SelfNodeV6MasqAddrForThisPeer,"null")) return failure(Error::unsupported_security);
            bool peer_api_only=false;
            if (!boolean(wire.MachineAuthorized,result.machine_authorized) || !boolean(wire.Expired,result.expired) || !boolean(wire.UnsignedPeerAPIOnly,peer_api_only)) return failure(Error::schema);
            if (peer_api_only) return failure(Error::unsupported_security);
            std::int64_t capability=0;
            if (field(wire.Cap).presence==Presence::value && (!read(capability,wire.Cap.str) || capability<0)) return failure(Error::schema);
            if (capability>148) return failure(Error::unsupported_security);
            auto name=string(wire.Name,253),stable=string(wire.StableID,128),expiry=string(wire.KeyExpiry,64),disco=string(wire.DiscoKey,128);
            if (!name || !stable || !expiry || !disco) return failure(Error::schema);
            if(!disco->empty()) {
                if(!disco->starts_with("discokey:") || disco->size()!=73)return failure(Error::identity);
                DiscoKey decoded{};
                auto hex=disco->substr(9);
                for(auto& byte:decoded) {
                    auto [end,error]=std::from_chars(hex.data(),hex.data()+2,byte,16);
                    if(error!=std::errc{} || end!=hex.data()+2)return failure(Error::identity);
                    hex.remove_prefix(2);
                }
                if(nonzero(decoded))result.discovery=decoded;
            }
            auto expiration = key_expiry(*expiry);
            if (!expiration) return std::unexpected(expiration.error());
            result.not_after = *expiration;
            if (field(wire.Machine).presence==Presence::value) {auto machine=public_key<control::MachinePublic>(wire.Machine,"mkey:");if (!machine) return std::unexpected(machine.error());}
            if (field(wire.HomeDERP).presence==Presence::value && (!read(result.home_derp,wire.HomeDERP.str) || result.home_derp<0 || result.home_derp>65535)) return failure(Error::schema);
            result.original_node=field(raw);result.name=field(wire.Name);result.stable_id=field(wire.StableID);result.key_expiry=field(wire.KeyExpiry);result.disco_key=field(wire.DiscoKey);result.tags=field(wire.Tags);
            if (auto parsed=list(wire.Addresses,result.addresses,prefix);!parsed) return std::unexpected(parsed.error());
            result.allowed_ips_presence=field(wire.AllowedIPs).presence;
            if (result.allowed_ips_presence==Presence::value) {if (auto parsed=list(wire.AllowedIPs,result.allowed_ips,prefix);!parsed) return std::unexpected(parsed.error());}
            else for (auto const& address:result.addresses) result.allowed_ips.push_back(address);
            if (auto parsed=list(wire.Endpoints,result.endpoints,endpoint);!parsed) return std::unexpected(parsed.error());
            return result;
        }
        auto nodes(Raw const& raw,containers::inplace_vector<PeerCandidate,max_peers>& output,control::NodePublic const& self) -> std::expected<void,Failure> {
            if (field(raw).presence!=Presence::value) return {};
            containers::inplace_vector<Raw,max_peers> items;if (!read(items,raw.str)) return failure(Error::schema);
            for (auto const& item:items) {
                auto peer=node(item);if (!peer) return std::unexpected(peer.error());if (peer->key==self) return failure(Error::identity);
                for (auto const& existing:output) if (existing.id==peer->id || existing.key==peer->key) return failure(Error::duplicate);
                output.push_back(std::move(*peer));
            }
            return {};
        }
    }
    RegisterWire::RegisterWire(std::span<std::uint8_t> bytes) noexcept : bytes_(bytes) {}
    RegisterWire::~RegisterWire() {clear();}
    RegisterWire::RegisterWire(RegisterWire&& other) noexcept : bytes_(std::exchange(other.bytes_,{})) {}
    auto RegisterWire::operator=(RegisterWire&& other) noexcept -> RegisterWire& {if (this!=&other) {clear();bytes_=std::exchange(other.bytes_,{});}return *this;}
    auto RegisterWire::clear() noexcept -> void {crypto::cleanse(bytes_);bytes_={};}

    auto encode_map_request(control::NodePublic const& node, MapRequestMode mode,
                            std::span<const Endpoint> endpoints, std::optional<DiscoKey> const& disco) -> std::expected<std::string, Failure> {
        if (!nonzero(node.view()) || endpoints.size() > max_endpoints ||
            (mode == MapRequestMode::stream && !endpoints.empty())) return failure(Error::schema);
        std::string result = R"({"Version":148,"NodeKey":"nodekey:)";
        constexpr std::string_view digits = "0123456789abcdef";
        for (auto byte : node.view()) { result += digits[byte >> 4]; result += digits[byte & 15]; }
        if (disco) {
            if(!nonzero(*disco))return failure(Error::identity);
            result += R"(","DiscoKey":"discokey:)";
            for(auto byte:*disco) {result+=digits[byte>>4];result+=digits[byte&15];}
        }
        if (mode == MapRequestMode::stream) {
            result += R"(","Stream":true,"KeepAlive":true})";
            return result;
        }
        result += R"(","OmitPeers":true,"Endpoints":[)";
        for (std::size_t index = 0; index < endpoints.size(); ++index) {
            auto const& endpoint = endpoints[index];
            auto width = endpoint.family == 4 ? 4u : endpoint.family == 6 ? 16u : 0u;
            if (!width || !endpoint.port || !nonzero(std::span(endpoint.address).first(width))) return failure(Error::address);
            if (index) result += ',';
            if (width == 4) {
                corosio::ipv4_address::bytes_type ip{};
                std::copy_n(endpoint.address.begin(), ip.size(), ip.begin());
                result += std::format("\"{}:{}\"", corosio::ipv4_address(ip).to_string(), endpoint.port);
            } else {
                result += std::format("\"[{}]:{}\"", corosio::ipv6_address(endpoint.address).to_string(), endpoint.port);
            }
        }
        result += R"(],"EndpointTypes":[)";
        for (std::size_t index = 0; index < endpoints.size(); ++index) result += index ? ",1" : "1";
        result += "]}";
        return result;
    }

    auto encode_register(std::span<std::uint8_t> output,RegisterRequest const& request) noexcept -> std::expected<RegisterWire,Failure> {
        EraseOutput erase{output};
        try {
            if (output.size()>max_json_bytes || !nonzero(request.node.view()) || !safe_text(request.auth_key,4096) || !safe_text(request.hostname,253) ||
                !safe_text(request.os,64) || !safe_text(request.client_version,128)) return failure(Error::schema);
            for (auto text:{request.auth_key,request.hostname,request.os,request.client_version}) if (overlaps(output,text)) return failure(Error::overlap);
            std::array<char,72> node_text{};std::ranges::copy(std::string_view("nodekey:"),node_text.begin());
            for (unsigned i=0;i<32;++i) {node_text[8+2*i]="0123456789abcdef"[request.node.view()[i]>>4];node_text[9+2*i]="0123456789abcdef"[request.node.view()[i]&15];}
            // This fixed schema writes directly to the final caller buffer.
            // Controls are rejected; quote/backslash are escaped. Glaze then
            // validates the final JSON, including UTF-8, without a secret copy.
            constexpr std::array<std::string_view,6> parts{R"({"Version":148,"NodeKey":)",R"(,"Auth":{"AuthKey":)",
                R"(},"Hostinfo":{"Hostname":)",R"(,"OS":)",R"(,"IPNVersion":)",R"(},"Ephemeral":)"};
            std::array<std::string_view,5> values{{{node_text.data(),node_text.size()},request.auth_key,request.hostname,request.os,request.client_version}};
            auto ending=request.ephemeral ? std::string_view("true}") : std::string_view("false}");std::size_t size=ending.size();
            for (auto part:parts) size+=part.size();
            for (auto value:values) {size+=value.size()+2;for (auto c:value) if (c=='"' || c=='\\') ++size;}
            if (output.size()<size) return failure(Error::capacity);
            std::size_t used=0;auto append=[&](std::string_view value) {std::ranges::copy(value,output.begin()+used);used+=value.size();};
            for (std::size_t i=0;i<values.size();++i) {
                append(parts[i]);output[used++]='"';
                for (auto c:values[i]) {if (c=='"' || c=='\\') output[used++]='\\';output[used++]=static_cast<std::uint8_t>(c);}output[used++]='"';
            }
            append(parts.back());append(ending);Raw checked;
            if (!read(checked,bytes(std::span<std::uint8_t const>(output.first(used))))) return failure(Error::schema);
            erase.success=true;return RegisterWire(output.first(used));
        } catch (...) {return failure(Error::limit);}
    }
    auto parse_register(unsigned status,std::span<std::uint8_t const> input) noexcept -> std::expected<RegisterReply,Failure> {
        if (status!=200) return failure(Error::http_status,status);if (input.empty() || input.size()>max_json_bytes) return failure(Error::size);
        try {
            if (auto unique=unique_object(bytes(input));!unique) return std::unexpected(unique.error());
            RegisterJson wire;if (!trim(bytes(input)).starts_with('{') || !read(wire,bytes(input))) return failure(Error::json);
            bool expired=false,authorized=false;
            if (!boolean(wire.NodeKeyExpired,expired) || !boolean(wire.MachineAuthorized,authorized)) return failure(Error::schema);
            auto error=string(wire.Error,4096,true),url=string(wire.AuthURL,8192,true),signature=string(wire.NodeKeySignature,8192,true);
            if (!error || !url || !signature) return failure(Error::schema);
            RegisterReply result{RegistrationState::pending,authorized,field(wire.Error),field(wire.AuthURL),field(wire.User),field(wire.Login)};
            if (!error->empty()) result.state=RegistrationState::denied;
            else if (!signature->empty()) return failure(Error::unsupported_security);
            else if (expired) result.state=RegistrationState::expired;
            else if (!url->empty()) result.state=RegistrationState::pending;
            else if (authorized) result.state=RegistrationState::authorized;
            return result;
        } catch (...) {return failure(Error::limit);}
    }
    auto MapCandidate::clear() noexcept -> void {
        ready_=keep_alive_=false;origin_={};mode_=MapMode::unchanged;self_.reset();peers_.clear();changed_.clear();removed_.clear();
        original_map_=session_handle_=sequence_=derp_map_=dns_config_=domain_=control_time_={};
        self_presence_=peers_presence_=changed_presence_=removed_presence_=Presence::missing;
    }
    auto MapCandidate::view() const noexcept -> std::expected<MapView,Failure> {
        if (!ready_) return failure(Error::state);
        return MapView{origin_,mode_,keep_alive_,original_map_,session_handle_,sequence_,derp_map_,dns_config_,domain_,control_time_,self_presence_,peers_presence_,changed_presence_,removed_presence_,
            self_ ? &*self_ : nullptr,{peers_.data(),peers_.size()},{changed_.data(),changed_.size()},{removed_.data(),removed_.size()}};
    }
    auto MapCandidate::parse(std::span<std::uint8_t const> input,DecodeOrigin const& origin,FilterFields* filters) noexcept -> std::expected<void,Failure> {
        auto& output=*this;if(filters)*filters={};
        output.clear();
        struct Attempt {MapCandidate& output;bool complete=false;~Attempt() {if (!complete) output.clear();}} attempt{output};
        if (!origin.connection_generation || !origin.stream_generation || !nonzero(origin.local_node.view())) return failure(Error::state);
        if (input.empty() || input.size()>max_json_bytes) return failure(Error::size);
        try {
            if (auto unique=unique_object(bytes(input));!unique) return std::unexpected(unique.error());
            MapJson wire;if (!trim(bytes(input)).starts_with('{') || !read(wire,bytes(input))) return failure(Error::json);
            if ((!filters && (active(wire.PacketFilter,"null") || active(wire.PacketFilters,"null"))) || active(wire.TKAInfo,"null") || active(wire.PeersChangedPatch,"[]") ||
                active(wire.PeerSeenChange,"{}") || active(wire.OnlineChange,"{}")) return failure(Error::unsupported_security);
            if (!boolean(wire.KeepAlive,output.keep_alive_)) return failure(Error::schema);
            if (output.keep_alive_ && (active(wire.PacketFilter,"null") || active(wire.PacketFilters,"null"))) return failure(Error::unsupported_security);
            auto session=string(wire.MapSessionHandle,128),domain=string(wire.Domain,253),time=string(wire.ControlTime,64);
            if (!session || !domain || !time) return failure(Error::schema);
            std::int64_t sequence=0;if (field(wire.Seq).presence==Presence::value && (!read(sequence,wire.Seq.str) || sequence<0)) return failure(Error::schema);
            output.origin_=origin;output.original_map_={Presence::value,trim(bytes(input))};output.session_handle_=field(wire.MapSessionHandle);output.sequence_=field(wire.Seq);output.control_time_=field(wire.ControlTime);
            // Validate even fields ignored by KeepAlive; the local narrow
            // schema never hides unsupported capabilities in ignored data.
            {
                output.derp_map_=field(wire.DERPMap);output.dns_config_=field(wire.DNSConfig);output.domain_=field(wire.Domain);
                output.self_presence_=field(wire.Node).presence;output.peers_presence_=field(wire.Peers).presence;
                output.changed_presence_=field(wire.PeersChanged).presence;output.removed_presence_=field(wire.PeersRemoved).presence;
                if (output.self_presence_==Presence::value) {
                    auto self=node(wire.Node);if (!self) return std::unexpected(self.error());if (self->key!=origin.local_node) return failure(Error::identity);output.self_.emplace(std::move(*self));
                }
                if (auto parsed=nodes(wire.Peers,output.peers_,origin.local_node);!parsed) return parsed;
                if (auto parsed=nodes(wire.PeersChanged,output.changed_,origin.local_node);!parsed) return parsed;
                if (output.self_) for (auto const* peers:{&output.peers_,&output.changed_})
                    for (auto const& peer:*peers) if (peer.id==output.self_->id) return failure(Error::duplicate);
                if (field(wire.PeersRemoved).presence==Presence::value) {
                    if (!read(output.removed_,wire.PeersRemoved.str)) return failure(Error::schema);
                    for (std::size_t i=0;i<output.removed_.size();++i) {
                        if (output.removed_[i]<=0) return failure(Error::identity);
                        if (output.self_ && output.removed_[i]==output.self_->id) return failure(Error::duplicate);
                        for (std::size_t j=0;j<i;++j) if (output.removed_[i]==output.removed_[j]) return failure(Error::duplicate);
                    }
                }
                // Preserve Peers/PeersChanged/PeersRemoved verbatim for v148 wire
                // inspection; Snapshot::apply fails closed on mixed full+delta views.
                output.mode_=!output.peers_.empty() ? MapMode::full : (!output.changed_.empty() || !output.removed_.empty()) ? MapMode::delta : MapMode::unchanged;
            }
            if (output.keep_alive_) {
                output.self_.reset();output.peers_.clear();output.changed_.clear();output.removed_.clear();output.mode_=MapMode::unchanged;
                output.derp_map_=output.dns_config_=output.domain_={};
                output.self_presence_=output.peers_presence_=output.changed_presence_=output.removed_presence_=Presence::missing;
            }
            if(filters) {*filters={field(wire.PacketFilter),field(wire.PacketFilters)};}
            output.ready_=true;attempt.complete=true;return {};
        } catch (...) {return failure(Error::limit);}
    }
    auto parse_map(std::span<std::uint8_t const> input,DecodeOrigin const& origin,MapCandidate& output) noexcept -> std::expected<void,Failure> {
        return output.parse(input,origin,nullptr);
    }
    auto parse_map_projection(std::span<std::uint8_t const> input,DecodeOrigin const& origin,MapCandidate& output,FilterFields& filters) noexcept -> std::expected<void,Failure> {
        return output.parse(input,origin,&filters);
    }
    auto derp_nodes(JsonField input) noexcept -> std::expected<std::optional<DerpNodes>,Failure> {
        if(input.presence!=Presence::value)return std::nullopt;
        try {
            DerpMapJson map;
            if(!unique_object(input.json) || !read(map,input.json))return failure(Error::schema);
            auto regions_field=field(map.Regions);
            if(regions_field.presence!=Presence::value)return std::nullopt;
            containers::inplace_vector<std::pair<std::string_view,Raw>,64> regions;
            if(!unique_object(regions_field.json) || !read(regions,regions_field.json))return failure(Error::schema);
            DerpNodes output;
            for(auto const& [key,value]:regions) {
                std::uint16_t id=0, region_id=0;
                auto [end,ec]=std::from_chars(key.data(),key.data()+key.size(),id);
                if(ec!=std::errc{} || end!=key.data()+key.size() || !id || key.front()=='0')return failure(Error::schema);
                auto region_field=field(value);
                if(region_field.presence==Presence::null_value)continue;
                DerpRegionJson region;
                if(!unique_object(region_field.json) || !read(region,region_field.json) ||
                   !read(region_id,field(region.RegionID).json) || region_id!=id) return failure(Error::schema);
                auto nodes_field=field(region.Nodes);
                if(nodes_field.presence!=Presence::value)continue;
                containers::inplace_vector<Raw,16> nodes;
                if(!read(nodes,nodes_field.json))return failure(Error::schema);
                for(auto const& raw:nodes) {
                    auto node_field=field(raw);
                    if(node_field.presence!=Presence::value)continue;
                    DerpNodeJson node;
                    std::uint16_t node_id=0,port=0;
                    bool insecure=false,stun=false;
                    if(!unique_object(node_field.json) || !read(node,node_field.json) ||
                       !read(node_id,field(node.RegionID).json) || node_id!=id ||
                       !boolean(node.InsecureForTests,insecure) || !boolean(node.STUNOnly,stun))
                        return failure(Error::schema);
                    if(insecure || stun)continue;
                    if(field(node.DERPPort).presence==Presence::value && !read(port,field(node.DERPPort).json))
                        return failure(Error::schema);
                    auto host=string(node.HostName,253), cert=string(node.CertName,253);
                    auto ipv4=string(node.IPv4,64), ipv6=string(node.IPv6,64);
                    if(!host || host->empty() || !cert || !ipv4 || !ipv6)return failure(Error::schema);
                    if(!cert->empty() && *cert!=*host)continue;
                    if(output.size()==256)return failure(Error::limit);
                    output.push_back({id,port ? port : std::uint16_t{443},std::string(*host),std::string(*ipv4),std::string(*ipv6)});
                }
            }
            return std::optional(std::move(output));
        } catch(...) {return failure(Error::limit);}
    }
}
