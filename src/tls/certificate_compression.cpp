module;
#ifdef NEXUS_ENABLE_TLS_CERT_COMPRESSION
#include <brotli/decode.h>
#include <zlib.h>
#include <zstd.h>
#endif

module tls.certificate_compression;
import std;

namespace tls {
#ifdef NEXUS_ENABLE_TLS_CERT_COMPRESSION
    namespace {
        auto read_u24(std::span<std::uint8_t const> bytes,std::size_t offset) noexcept -> std::size_t {
            return (std::size_t{bytes[offset]}<<16)|(std::size_t{bytes[offset+1]}<<8)|bytes[offset+2];
        }

        auto offered(std::span<std::uint8_t const> offer,std::uint16_t algorithm) noexcept -> bool {
            if (offer.size()<3 || offer[0]!=offer.size()-1 || offer[0]%2) return false;
            for (std::size_t offset=1;offset<offer.size();offset+=2) {
                auto value=static_cast<std::uint16_t>((std::uint16_t{offer[offset]}<<8)|offer[offset+1]);
                if (value==algorithm) return true;
            }
            return false;
        }

        auto inflate(CertificateCompression algorithm,std::span<std::uint8_t const> input,
            std::span<std::uint8_t> output) noexcept -> bool {
            switch (algorithm) {
            case CertificateCompression::zlib: {
                auto input_size=static_cast<uLong>(input.size());
                auto output_size=static_cast<uLongf>(output.size());
                auto result=::uncompress2(output.data(),&output_size,input.data(),&input_size);
                return result==Z_OK && input_size==input.size() && output_size==output.size();
            }
            case CertificateCompression::brotli: {
                std::unique_ptr<BrotliDecoderState,decltype(&BrotliDecoderDestroyInstance)>
                    decoder(BrotliDecoderCreateInstance(nullptr,nullptr,nullptr),&BrotliDecoderDestroyInstance);
                if (!decoder) return false;
                auto* read=input.data();
                auto* write=output.data();
                auto remaining=input.size(),capacity=output.size();
                auto result=BrotliDecoderDecompressStream(decoder.get(),&remaining,&read,&capacity,&write,nullptr);
                return result==BROTLI_DECODER_RESULT_SUCCESS && remaining==0 && capacity==0;
            }
            case CertificateCompression::zstd: {
                auto size=ZSTD_decompress(output.data(),output.size(),input.data(),input.size());
                return !ZSTD_isError(size) && size==output.size();
            }
            }
            return false;
        }
    }
#endif

    auto expand_certificate(std::span<std::uint8_t const> message,std::span<std::uint8_t const> offer,
        std::size_t maximum_body) -> std::expected<std::vector<std::uint8_t>,CertificateCompressionError> {
#ifdef NEXUS_ENABLE_TLS_CERT_COMPRESSION
        constexpr std::size_t header=12;
        if (message.size()<=header || message.front()!=compressed_certificate_message ||
            read_u24(message,1)!=message.size()-4 || read_u24(message,9)!=message.size()-header)
            return std::unexpected(CertificateCompressionError::malformed);
        auto algorithm=static_cast<std::uint16_t>((std::uint16_t{message[4]}<<8)|message[5]);
        if (!offered(offer,algorithm)) return std::unexpected(CertificateCompressionError::unoffered);
        auto size=read_u24(message,6);
        if (size<4 || size>maximum_body) return std::unexpected(CertificateCompressionError::decompression);
        std::vector<std::uint8_t> result(4+size);
        if (!inflate(static_cast<CertificateCompression>(algorithm),message.subspan(header),std::span(result).subspan(4)))
            return std::unexpected(CertificateCompressionError::decompression);
        result[0]=11;
        result[1]=static_cast<std::uint8_t>(size>>16);
        result[2]=static_cast<std::uint8_t>(size>>8);
        result[3]=static_cast<std::uint8_t>(size);
        return result;
#else
        (void)message; (void)offer; (void)maximum_body;
        return std::unexpected(CertificateCompressionError::unoffered);
#endif
    }
}
