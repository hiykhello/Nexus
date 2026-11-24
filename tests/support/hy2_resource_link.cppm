export module test.hy2_resource_link;
import std;
import tls.server_credential;
import corosio;
export namespace test::hy2_resource {
    auto phase(corosio::io_context& context,tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,bool* observed_clean=nullptr) -> bool;
}
