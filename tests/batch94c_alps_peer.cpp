#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <iostream>
#include <span>
#include <string_view>
#include <vector>

namespace {
    using Bytes=std::span<unsigned char>;

    auto read_exact(SSL* ssl,Bytes bytes) -> bool {
        while (!bytes.empty()) {
            int size=SSL_read(ssl,bytes.data(),static_cast<int>(bytes.size()));
            if (size<=0) return false;
            bytes=bytes.subspan(static_cast<std::size_t>(size));
        }
        return true;
    }

    auto frame(SSL* ssl,unsigned char type,unsigned char flags,unsigned char stream,
        std::span<unsigned char const> body={}) -> bool {
        auto size=body.size();
        std::vector<unsigned char> wire{static_cast<unsigned char>(size>>16),static_cast<unsigned char>(size>>8),
            static_cast<unsigned char>(size),type,flags,0,0,0,stream};
        wire.insert(wire.end(),body.begin(),body.end());
        return SSL_write(ssl,wire.data(),static_cast<int>(wire.size()))==static_cast<int>(wire.size());
    }

    auto exchange(SSL* ssl) -> bool {
        constexpr std::string_view preface="PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        std::array<unsigned char,preface.size()> received{};
        if (!read_exact(ssl,received) || std::string_view{reinterpret_cast<char const*>(received.data()),received.size()}!=preface ||
            !frame(ssl,4,0,0)) return false;
        for (int i=0;i<8;++i) {
            std::array<unsigned char,9> header{};
            if (!read_exact(ssl,header)) return false;
            auto size=(std::size_t{header[0]}<<16)|(std::size_t{header[1]}<<8)|header[2];
            if (size>16384) return false;
            std::vector<unsigned char> data(size);
            if (!read_exact(ssl,data)) return false;
            if (header[3]==4 && !(header[4]&1) && !frame(ssl,4,1,0)) return false;
            if (header[3]==1 && header[8]==1 && (header[4]&4)) {
                constexpr std::array<unsigned char,1> status{0x88};
                constexpr std::string_view rules="schema-version 2\nkind \"predicate\"\nrule type=\"domain\" value=\"alps.test\"\n";
                auto body=std::span(reinterpret_cast<unsigned char const*>(rules.data()),rules.size());
                return frame(ssl,1,4,1,status) && frame(ssl,0,1,1,body);
            }
        }
        return false;
    }

    auto select_alpn(SSL*,unsigned char const** selected,unsigned char* size,unsigned char const* offered,
        unsigned int length,void*) -> int {
        if (length!=3 || offered[0]!=2 || offered[1]!='h' || offered[2]!='2') return SSL_TLSEXT_ERR_ALERT_FATAL;
        *selected=offered+1;
        *size=2;
        return SSL_TLSEXT_ERR_OK;
    }

    auto fail() -> int {
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }
}

auto main(int argc,char** argv) -> int {
    if (argc!=3) return EXIT_FAILURE;
    bssl::UniquePtr<SSL_CTX> context(SSL_CTX_new(TLS_server_method()));
    if (!context || !SSL_CTX_set_min_proto_version(context.get(),TLS1_3_VERSION) ||
        !SSL_CTX_use_certificate_file(context.get(),argv[1],SSL_FILETYPE_PEM) ||
        !SSL_CTX_use_PrivateKey_file(context.get(),argv[2],SSL_FILETYPE_PEM)) return fail();
    SSL_CTX_set_alpn_select_cb(context.get(),select_alpn,nullptr);
    int listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    sockaddr_in address{};
    address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    socklen_t length=sizeof(address);
    if (listener<0 || bind(listener,reinterpret_cast<sockaddr*>(&address),length)<0 ||
        listen(listener,1)<0 || getsockname(listener,reinterpret_cast<sockaddr*>(&address),&length)<0) return fail();
    std::cout << ntohs(address.sin_port) << std::endl;
    int fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);
    close(listener);
    bssl::UniquePtr<SSL> tls(SSL_new(context.get()));
    constexpr std::array<unsigned char,2> h2{'h','2'};
    constexpr std::array<unsigned char,6> settings{0,3,0,0,0,64};
    if (fd<0 || !tls || !SSL_set_fd(tls.get(),fd) ||
        !SSL_add_application_settings(tls.get(),h2.data(),h2.size(),settings.data(),settings.size())) return fail();
    SSL_set_alps_use_new_codepoint(tls.get(),1);
    unsigned char const* peer_settings=nullptr;
    std::size_t size=0;
    if (SSL_accept(tls.get())!=1 || !SSL_has_application_settings(tls.get())) return fail();
    SSL_get0_peer_application_settings(tls.get(),&peer_settings,&size);
    if (size || !exchange(tls.get())) return fail();
    std::cout << "BoringSSL accepted 0x44cd ALPS, client EncryptedExtensions and Finished, then served HTTP/2" << std::endl;
    SSL_shutdown(tls.get());
    close(fd);
    return EXIT_SUCCESS;
}
