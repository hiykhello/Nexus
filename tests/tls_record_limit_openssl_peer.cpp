#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
static int saw_offer=0,saw_alert=0,invalid_value=0;
static int parse(SSL*,unsigned int,unsigned int,const unsigned char* data,std::size_t n,X509*,std::size_t,int*,void*) {
    if(n!=2)return 0;saw_offer=(static_cast<int>(data[0])<<8)|data[1];return saw_offer>=64;
}
static int add(SSL*,unsigned int,unsigned int,const unsigned char** out,std::size_t* n,X509*,std::size_t,int*,void*) {
    static const unsigned char valid[]{2,0},invalid[]{0,63};*out=invalid_value ? invalid : valid;*n=2;return 1;
}
static void info(const SSL*,int where,int value) {if(where==SSL_CB_READ_ALERT)saw_alert=value&255;}
int main(int argc,char** argv) {
    if(argc!=4)return 1;bool proxy=std::strcmp(argv[3],"proxy")==0;bool overflow=std::strcmp(argv[3],"overflow")==0;invalid_value=std::strcmp(argv[3],"invalid")==0;bool failure=overflow || invalid_value;
    SSL_CTX* ctx=SSL_CTX_new(TLS_server_method());if(!ctx)return 2;
    if(!SSL_CTX_set_min_proto_version(ctx,TLS1_3_VERSION) || !SSL_CTX_set_max_proto_version(ctx,TLS1_3_VERSION) ||
       SSL_CTX_use_certificate_chain_file(ctx,argv[1])!=1 || SSL_CTX_use_PrivateKey_file(ctx,argv[2],SSL_FILETYPE_PEM)!=1 ||
       !SSL_CTX_set_max_send_fragment(ctx,512) ||
       !SSL_CTX_add_custom_ext(ctx,28,SSL_EXT_TLS_ONLY|SSL_EXT_TLS1_3_ONLY|SSL_EXT_CLIENT_HELLO|SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,add,nullptr,nullptr,parse,nullptr)) {
        ERR_print_errors_fp(stderr);SSL_CTX_free(ctx);return 3;
    }
    SSL_CTX_set_info_callback(ctx,info);SSL* ssl=SSL_new(ctx);if(!ssl){SSL_CTX_free(ctx);return 4;}
    SSL_set_fd(ssl,0);int accepted=SSL_accept(ssl);
    if(failure) {if(accepted==1 || saw_alert!=(overflow ? 22 : 47) || saw_offer!=(overflow ? 64 : 1024)){ERR_print_errors_fp(stderr);return 5;}SSL_free(ssl);SSL_CTX_free(ctx);return 0;}
    if(accepted!=1 || saw_offer!=1024){ERR_print_errors_fp(stderr);return 6;}
    if(proxy) {
        unsigned char header[68];std::size_t count=0;
        while(count<sizeof(header)){int n=SSL_read(ssl,header+count,static_cast<int>(sizeof(header)-count));if(n<=0)return 11;count+=static_cast<std::size_t>(n);}
        constexpr char digest[]="6b9e3db9e9648ade14cefd4d159ca5cbfdcde8fdda919fb54322d7bc";
        if(std::memcmp(header,digest,56)!=0 || header[56]!=13 || header[57]!=10 || header[58]!=1 ||
           header[59]!=1 || header[60]!=127 || header[61]!=0 || header[62]!=0 || header[63]!=1 ||
           header[64]!=0x30 || header[65]!=0x39 || header[66]!=13 || header[67]!=10) return 12;
    }
    unsigned char data[2048];std::size_t off=0;
    while(off<sizeof(data)){int n=SSL_read(ssl,data+off,static_cast<int>(sizeof(data)-off));if(n<=0)return 7;off+=static_cast<std::size_t>(n);}
    for(std::size_t i=0;i<sizeof(data);++i)if(data[i]!=static_cast<unsigned char>(i))return 8;
    off=0;while(off<sizeof(data)){int n=SSL_write(ssl,data+off,static_cast<int>(sizeof(data)-off));if(n<=0)return 9;off+=static_cast<std::size_t>(n);}
    int shutdown=SSL_shutdown(ssl);if(shutdown==0)shutdown=SSL_shutdown(ssl);if(shutdown!=1)return 10;SSL_free(ssl);SSL_CTX_free(ctx);return 0;
}
