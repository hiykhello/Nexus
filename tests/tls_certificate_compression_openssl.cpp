#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <unistd.h>

namespace {
auto read_exact(SSL* stream,unsigned char* output,std::size_t count) -> bool {
    while (count) {
        std::size_t size=0;
        if (SSL_read_ex(stream,output,count,&size)!=1 || !size) return false;
        output+=size;
        count-=size;
    }
    return true;
}

auto message(int written,int,int type,void const* bytes,std::size_t size,SSL*,void*) -> void {
    if (written && type==SSL3_RT_HANDSHAKE && size>=6) {
        auto* data=static_cast<unsigned char const*>(bytes);
        if (data[0]==25) std::fprintf(stderr,"compressed algorithm=%d\n",data[4]*256+data[5]);
    }
}

auto select_h3(SSL*,unsigned char const** out,unsigned char* size,unsigned char const* offered,
    unsigned int length,void*) -> int {
    static constexpr unsigned char protocols[]{2,'h','3'};
    unsigned char* selected=nullptr;
    if (SSL_select_next_proto(&selected,size,protocols,sizeof(protocols),offered,length)!=OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out=selected;
    return SSL_TLSEXT_ERR_OK;
}

auto quic_handshake(SSL_CTX* context,int fd,bool report_cipher) -> int {
    SSL_CTX_set_alpn_select_cb(context,select_h3,nullptr);
    std::unique_ptr<SSL,decltype(&SSL_free)> listener(SSL_new_listener(context,0),SSL_free);
    if (!listener) return 10;
    auto* network=BIO_new_dgram(fd,BIO_NOCLOSE);
    if (!network) return 11;
    SSL_set_bio(listener.get(),network,network);
    if (!SSL_set_blocking_mode(listener.get(),1) || !SSL_listen(listener.get())) return 12;
    std::unique_ptr<SSL,decltype(&SSL_free)> connection(SSL_accept_connection(listener.get(),0),SSL_free);
    if (!connection || SSL_do_handshake(connection.get())!=1) return 13;
    if (report_cipher) std::fprintf(stderr,"QUIC cipher=%s\n",SSL_get_cipher_name(connection.get()));
    std::fprintf(stderr,"authenticated QUIC TLS\n");
    return 0;
}

auto compress_quic_certificate(SSL_CTX* context,char const* certificate,char const* key,int algorithm) -> bool {
    std::unique_ptr<SSL_CTX,decltype(&SSL_CTX_free)> tcp(SSL_CTX_new(TLS_server_method()),SSL_CTX_free);
    if (!tcp || !SSL_CTX_use_certificate_chain_file(tcp.get(),certificate) ||
        !SSL_CTX_use_PrivateKey_file(tcp.get(),key,SSL_FILETYPE_PEM) ||
        !SSL_CTX_compress_certs(tcp.get(),algorithm)) return false;
    unsigned char* compressed=nullptr;
    std::size_t original_size=0;
    auto size=SSL_CTX_get1_compressed_cert(tcp.get(),algorithm,&compressed,&original_size);
    auto installed=size && SSL_CTX_set1_compressed_cert(context,algorithm,compressed,size,original_size);
    OPENSSL_free(compressed);
    return installed;
}
}

auto main(int argc,char** argv) -> int {
    if (argc!=5 && argc!=6) return 2;
    int algorithm=std::atoi(argv[3]);
    auto quic=algorithm>=1000;
    if (quic) algorithm-=1000;
    auto* context=SSL_CTX_new(quic ? OSSL_QUIC_server_method() : TLS_server_method());
    auto ecdsa=algorithm==228 || algorithm==356 || algorithm==521;
    auto legacy=algorithm==128 || algorithm==256 || ecdsa;
    auto version=legacy ? TLS1_2_VERSION : TLS1_3_VERSION;
    if (!context || (!quic && !SSL_CTX_set_min_proto_version(context,version)) ||
        !SSL_CTX_use_certificate_chain_file(context,argv[1]) ||
        !SSL_CTX_use_PrivateKey_file(context,argv[2],SSL_FILETYPE_PEM)) return 3;
    if (legacy) {
        auto cipher=algorithm==128 ? "ECDHE-RSA-AES128-GCM-SHA256" : "ECDHE-RSA-AES256-GCM-SHA384";
        auto signature=algorithm==128 ? "rsa_pss_rsae_sha256" : "rsa_pkcs1_sha384";
        if (ecdsa) {
            auto group=algorithm==228 ? "P-256" : algorithm==356 ? "P-384" : "P-521";
            if (!SSL_CTX_set1_groups_list(context,group)) return 4;
            cipher=algorithm==228 ? "ECDHE-ECDSA-AES128-GCM-SHA256" : "ECDHE-ECDSA-AES256-GCM-SHA384";
            signature=algorithm==228 ? "ecdsa_secp256r1_sha256" :
                algorithm==356 ? "ecdsa_secp384r1_sha384" : "ecdsa_secp521r1_sha512";
        }
        if (!SSL_CTX_set_max_proto_version(context,version) ||
            !SSL_CTX_set_cipher_list(context,cipher) || !SSL_CTX_set1_sigalgs_list(context,signature)) return 4;
    } else if (algorithm) {
        if (!SSL_CTX_set1_cert_comp_preference(context,&algorithm,1)) return 4;
        auto compressed=quic ? compress_quic_certificate(context,argv[1],argv[2],algorithm) : SSL_CTX_compress_certs(context,algorithm);
        if (!compressed) return 4;
    } else SSL_CTX_set_options(context,SSL_OP_NO_TX_CERTIFICATE_COMPRESSION);
    SSL_CTX_set_msg_callback(context,message);
    if (argc==6 && (!quic || !SSL_CTX_set_ciphersuites(context,argv[5]))) return 4;
    if (quic) return quic_handshake(context,std::atoi(argv[4]),argc==6);
    auto* stream=SSL_new(context);
    if (!stream || !SSL_set_fd(stream,std::atoi(argv[4]))) return 5;
    if (SSL_accept(stream)!=1) return 6;
    if (legacy) std::fprintf(stderr,"TLS 1.2 %s\n",SSL_get_cipher_name(stream));
    unsigned char request[68];
    if (!read_exact(stream,request,sizeof(request)) || request[56]!='\r' || request[57]!='\n' ||
        request[58]!=1 || request[59]!=1 || request[66]!='\r' || request[67]!='\n') return 7;
    unsigned char payload[16];
    if (!read_exact(stream,payload,sizeof(payload))) return 8;
    std::size_t count=0;
    if (!SSL_write_ex(stream,payload,sizeof(payload),&count) || count!=sizeof(payload)) return 9;
    SSL_shutdown(stream);
    SSL_free(stream);
    SSL_CTX_free(context);
    return 0;
}
