export module snell.credential_file;
import std;
import crypto;
import rulefile;
import snell.record;
import snell.owner;
export namespace snell {
    // Reuses project secure-file policy; values never enter diagnostics.
    [[nodiscard]] auto load_credential(std::string_view psk_file,std::optional<std::string_view> user_file)
      ->std::expected<Credential,std::string> {
        auto psk=rulefile::read_password_file(psk_file);if(!psk)return std::unexpected("Snell PSK file: "+psk.error());
        struct Clear {std::string& s;~Clear(){crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(s.data()),s.size()));}} clear{*psk};
        std::optional<std::string> user;
        struct ClearOptional {std::optional<std::string>& s;~ClearOptional(){if(s)crypto::cleanse(std::span(reinterpret_cast<std::uint8_t*>(s->data()),s->size()));}} clear_user{user};
        if(user_file){auto read=rulefile::read_password_file(*user_file);if(!read)return std::unexpected("Snell user key file: "+read.error());Clear clean_read{*read};user.emplace(*read);}
        Bytes secret(psk->begin(),psk->end());std::optional<Bytes> user_key;
        struct ClearBytes {Bytes& b;~ClearBytes(){crypto::cleanse(b);}} clear_secret{secret};
        if(user)user_key.emplace(user->begin(),user->end());
        auto credential=Credential::create(std::move(secret),std::move(user_key));
        if(!credential)return std::unexpected("invalid Snell credential");return std::move(*credential);
    }
}
