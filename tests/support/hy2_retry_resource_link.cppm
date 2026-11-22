export module nexus.test.hy2_retry_resource_link;
import std;
import tls.server_credential;
import nexus.thirdparty.corosio;
export namespace nexus::test::hy2_retry_resource {
    auto phase(nex::corosio::io_context& context,tls::ServerCredential const& credential,std::span<std::uint8_t const> cert,bool* observed_clean=nullptr) -> bool;
}
