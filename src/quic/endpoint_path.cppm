export module quic.endpoint_path;
import std;
import ngtcp2;
import corosio;

export namespace quic {
    // Concrete endpoint/native conversion shared by every UDP QUIC owner.
    // The borrowed native view remains valid only while this value is alive.
    class EndpointPath {
        ngtcp2::ngtcp2_sockaddr_union local_{},remote_{};
        ngtcp2::ngtcp2_path value_{};
        static auto port(std::uint16_t value) noexcept -> std::uint16_t {
            return std::bit_cast<std::uint16_t>(std::array<std::uint8_t,2>{static_cast<std::uint8_t>(value>>8),static_cast<std::uint8_t>(value)});
        }
        static auto convert(ngtcp2::ngtcp2_sockaddr_union& output,corosio::endpoint const& input) noexcept -> ngtcp2::ngtcp2_addr {
            namespace n=::ngtcp2;
            if(input.address().is_v4()){
#if defined(__APPLE__)
                output.in.sin_len=sizeof(output.in);
#endif
                output.in.sin_family=n::af_inet;output.in.sin_port=port(input.port());auto bytes=input.address().to_v4().to_bytes();std::memcpy(&output.in.sin_addr.s_addr,bytes.data(),bytes.size());
                return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in),sizeof(output.in)};
            }
            auto address=input.address().to_v6();
#if defined(__APPLE__)
            output.in6.sin6_len=sizeof(output.in6);
#endif
            output.in6.sin6_family=n::af_inet6;output.in6.sin6_port=port(input.port());output.in6.sin6_scope_id=address.scope_id();auto bytes=address.to_bytes();std::memcpy(output.in6.sin6_addr.s6_addr,bytes.data(),bytes.size());
            return {reinterpret_cast<n::ngtcp2_sockaddr*>(&output.in6),sizeof(output.in6)};
        }
    public:
        EndpointPath(corosio::endpoint const& local,corosio::endpoint const& remote) noexcept {value_={convert(local_,local),convert(remote_,remote),nullptr};}
        EndpointPath(EndpointPath const&)=delete;
        auto operator=(EndpointPath const&) -> EndpointPath& = delete;
        auto native() const noexcept -> ngtcp2::ngtcp2_path const& {return value_;}
        static auto endpoint(ngtcp2::ngtcp2_addr const& address) noexcept -> std::optional<corosio::endpoint> {
            namespace n=::ngtcp2;namespace io=::corosio;
            if(!address.addr || address.addrlen<sizeof(address.addr->sa_family))return {};
            if(address.addr->sa_family==n::af_inet && address.addrlen>=sizeof(n::ngtcp2_sockaddr_in)){
                n::ngtcp2_sockaddr_in native{};std::memcpy(&native,address.addr,sizeof(native));std::array<std::uint8_t,4> bytes{};std::memcpy(bytes.data(),&native.sin_addr.s_addr,bytes.size());
                auto wire=std::bit_cast<std::array<std::uint8_t,2>>(native.sin_port);return io::endpoint(io::ipv4_address(bytes),static_cast<std::uint16_t>((wire[0]<<8)|wire[1]));
            }
            if(address.addr->sa_family==n::af_inet6 && address.addrlen>=sizeof(n::ngtcp2_sockaddr_in6)){
                n::ngtcp2_sockaddr_in6 native{};std::memcpy(&native,address.addr,sizeof(native));std::array<std::uint8_t,16> bytes{};std::memcpy(bytes.data(),native.sin6_addr.s6_addr,bytes.size());
                auto wire=std::bit_cast<std::array<std::uint8_t,2>>(native.sin6_port);return io::endpoint(io::ipv6_address(bytes,native.sin6_scope_id),static_cast<std::uint16_t>((wire[0]<<8)|wire[1]));
            }return {};
        }
    };
}
