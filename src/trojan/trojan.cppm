export module trojan;
export import net.datagram_frame;
import std;

export namespace trojan {
    using Address=net::ProxyAddress;
    using Family=net::ProxyAddressFamily;
    using Key=std::array<std::uint8_t,56>;
    enum class Command : std::uint8_t { tcp=1,udp=3 };
    enum class Status { incomplete,accepted,invalid_key,invalid_command,invalid_address,invalid_frame,too_large,closed };
    struct Request { Command command=Command::tcp; Address destination; };
    struct RequestResult { Status status=Status::incomplete; std::size_t consumed=0; Key key{}; Request request{}; };
    inline constexpr net::DatagramFraming datagram_framing{net::AddressWire::socks,false,true};
    inline auto valid_key(std::span<std::uint8_t const> key) noexcept -> bool {
        return key.size()==56 && std::ranges::all_of(key,[](auto c) { return (c>='0' && c<='9') || (c>='a' && c<='f'); });
    }
    inline auto valid_destination(Address const& address,bool require_port=true) noexcept -> bool {
        if ((require_port && !address.port) || !net::valid_proxy_address(address)) return false;
        if (address.family!=Family::domain) return true;
        return std::ranges::all_of(std::span(address.bytes).first(address.length),[](auto c) { return c>=33 && c<=126; });
    }
    inline auto encode_request(std::span<std::uint8_t const> key,Request const& request) -> std::expected<std::vector<std::uint8_t>,Status> {
        if (!valid_key(key)) return std::unexpected(Status::invalid_key);
        if (request.command!=Command::tcp && request.command!=Command::udp) return std::unexpected(Status::invalid_command);
        if (!valid_destination(request.destination,request.command==Command::tcp)) return std::unexpected(Status::invalid_address);
        std::vector<std::uint8_t> output;
        output.reserve(65+request.destination.length);
        output.insert(output.end(),key.begin(),key.end()); output.push_back('\r'); output.push_back('\n');
        output.push_back(static_cast<std::uint8_t>(request.command));
        (void)net::append_proxy_address(output,request.destination,net::AddressWire::socks);
        output.push_back('\r'); output.push_back('\n'); return output;
    }
    inline auto parse_request(std::span<std::uint8_t const> input) noexcept -> RequestResult {
        if (input.size()<58) return {};
        if (!valid_key(input.first(56))) return {Status::invalid_key};
        if (input[56]!='\r' || input[57]!='\n') return {Status::invalid_frame};
        if (input.size()<59) return {};
        auto command=static_cast<Command>(input[58]);
        if (command!=Command::tcp && command!=Command::udp) return {Status::invalid_command};
        auto address=net::parse_proxy_address(input.subspan(59),net::AddressWire::socks);
        if (address.status==net::DatagramStatus::incomplete) return {};
        if (address.status!=net::DatagramStatus::accepted || !valid_destination(address.address,command==Command::tcp)) return {Status::invalid_address};
        auto end=59+address.consumed;
        if (input.size()-end<2) return {};
        if (input[end]!='\r' || input[end+1]!='\n') return {Status::invalid_frame};
        RequestResult result{Status::accepted,end+2,{},Request{command,address.address}};
        std::copy_n(input.begin(),56,result.key.begin()); return result;
    }
    struct FeedResult { Status status=Status::incomplete; std::size_t consumed=0; };
    // Fixed header storage; payload remains with the caller. No socket, TLS,
    // allocation, routing or user lookup is part of this state machine.
    class RequestDecoder {
        std::array<std::uint8_t,320> input_{};
        std::size_t size_=0;
        RequestResult result_;
    public:
        RequestDecoder()=default;
        ~RequestDecoder() {
            // The wire authentication key is a reusable secret even though
            // this codec does not depend on a particular crypto provider.
            volatile std::uint8_t* input=input_.data();
            for (std::size_t i=0;i<input_.size();++i) input[i]=0;
            volatile std::uint8_t* key=result_.key.data();
            for (std::size_t i=0;i<result_.key.size();++i) key[i]=0;
        }
        RequestDecoder(RequestDecoder const&)=delete;
        auto operator=(RequestDecoder const&) -> RequestDecoder& = delete;
        auto feed(std::span<std::uint8_t const> input) noexcept -> FeedResult {
            if (result_.status!=Status::incomplete) return {result_.status,0};
            std::size_t consumed=0;
            while (consumed<input.size()) {
                input_[size_++]=input[consumed++];
                result_=parse_request(std::span(input_).first(size_));
                if (result_.status!=Status::incomplete) return {result_.status,consumed};
                if (size_==input_.size()) { result_.status=Status::too_large; return {result_.status,consumed}; }
            }
            return {result_.status,consumed};
        }
        auto request() const noexcept -> RequestResult const* { return result_.status==Status::accepted ? &result_ : nullptr; }
        auto close() noexcept -> void { result_.status=Status::closed; }
    };
}
