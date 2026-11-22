module tls.hello_config;
import std;
import crypto;

namespace tls {
    auto repad_client_hello(ClientHello& hello,std::size_t target,std::size_t maximum) -> std::expected<void,HelloError> {
        if (target>maximum) return std::unexpected(HelloError::message_too_large);
        auto size=hello.encoding_size(); if (!size) return std::unexpected(size.error());
        auto padding=std::ranges::find(hello.extensions,std::uint16_t{21},&Extension::type);
        if (padding!=hello.extensions.end()) {
            auto base=*size-padding->data.size();
            if (base>maximum) return std::unexpected(HelloError::message_too_large);
            auto needed=target>base ? target-base : 0;
            padding->data.resize(needed); std::ranges::fill(padding->data,std::uint8_t{0});
        } else if (*size<target) {
            if (target-*size<4) return std::unexpected(HelloError::invalid_length);
            hello.extensions.push_back({21,std::vector<std::uint8_t>(target-*size-4)});
        }
        return hello.validate_encoding(maximum);
    }
    auto make_client_hello(std::optional<std::string_view> server_name, std::span<std::string_view const> alpn,
        std::span<std::uint16_t const> groups) -> std::expected<ClientHello,ClientHelloConfigError> {
        auto dns=[](std::string_view name) {
            if (name.empty() || name.size()>253) return false;
            bool only_numeric=true; std::size_t start=0;
            for (std::size_t i=0;i<=name.size();++i) {
                if (i==name.size() || name[i]=='.') {
                    auto label=name.substr(start,i-start);
                    if (label.empty() || label.size()>63 || label.front()=='-' || label.back()=='-') return false;
                    start=i+1; continue;
                }
                unsigned char c=name[i];
                if (!((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') || c=='-')) return false;
                if (!(c>='0' && c<='9')) only_numeric=false;
            }
            return !only_numeric;
        };
        if (server_name && !dns(*server_name)) return std::unexpected(ClientHelloConfigError::invalid_server_name);
        if (groups.empty() || groups.size()>5) return std::unexpected(ClientHelloConfigError::invalid_group);
        crypto::Bytes group_data{0,static_cast<std::uint8_t>(groups.size()*2)};
        for (std::size_t i=0;i<groups.size();++i) {
            auto group=groups[i];
            if ((group!=0x001d && group!=0x11ec && group!=23 && group!=24 && group!=25) || std::find(groups.begin(),groups.begin()+static_cast<std::ptrdiff_t>(i),group)!=groups.begin()+static_cast<std::ptrdiff_t>(i)) return std::unexpected(ClientHelloConfigError::invalid_group);
            group_data.push_back(static_cast<std::uint8_t>(group>>8)); group_data.push_back(static_cast<std::uint8_t>(group));
        }
        crypto::Bytes protocols; for (std::size_t i=0;i<alpn.size();++i) {
            auto id=alpn[i]; if (id.empty() || id.size()>255 || protocols.size()+id.size()+1>15000 || std::find(alpn.begin(),alpn.begin()+static_cast<std::ptrdiff_t>(i),id)!=alpn.begin()+static_cast<std::ptrdiff_t>(i)) return std::unexpected(ClientHelloConfigError::invalid_alpn);
            protocols.push_back(static_cast<std::uint8_t>(id.size())); protocols.insert(protocols.end(),id.begin(),id.end());
        }
        ClientHello hello; if (!crypto::random_bytes(hello.random)) return std::unexpected(ClientHelloConfigError::random_error);
        hello.cipher_suites={0x1301,0x1302,0x1303}; hello.compression_methods={0};
        if (server_name) {
            auto size=server_name->size(); crypto::Bytes data{static_cast<std::uint8_t>((size+3)>>8),static_cast<std::uint8_t>(size+3),0,static_cast<std::uint8_t>(size>>8),static_cast<std::uint8_t>(size)};
            data.insert(data.end(),server_name->begin(),server_name->end()); hello.extensions.push_back({0,std::move(data)});
        }
        hello.extensions.push_back({43,{2,3,4}}); hello.extensions.push_back({10,std::move(group_data)});
        hello.extensions.push_back({51,{0,0}}); hello.extensions.push_back({13,{0,6,8,4,4,3,8,7}});
        if (!protocols.empty()) {
            crypto::Bytes data{static_cast<std::uint8_t>(protocols.size()>>8),static_cast<std::uint8_t>(protocols.size())};
            data.insert(data.end(),protocols.begin(),protocols.end()); hello.extensions.push_back({16,std::move(data)});
        }
        return hello;
    }
}
