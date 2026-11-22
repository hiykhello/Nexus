export module anytls.settings;
import std;

export namespace anytls {
    enum class SettingsError { invalid,too_large,duplicate,version,metadata,padding_hash };
    struct SettingsView {
        std::uint32_t version=0;
        std::string_view client,padding_md5;
    };
    auto valid_padding_hash(std::string_view hash) noexcept -> bool;
    auto valid_client_metadata(std::string_view metadata) noexcept -> bool;
    // Views borrow the frame. Unknown keys are ignored for forward
    // compatibility; duplicate known keys cannot alter an earlier setting.
    auto parse_settings(std::span<std::uint8_t const> bytes,bool client) noexcept
        -> std::expected<SettingsView,SettingsError>;
    auto encode_client_settings(std::string_view padding_md5,std::string_view metadata={})
        -> std::expected<std::vector<std::uint8_t>,SettingsError>;
    auto encode_server_settings() -> std::vector<std::uint8_t>;
}

module :private;

namespace anytls {
    auto valid_padding_hash(std::string_view hash) noexcept -> bool {
        return hash.size()==32 && std::ranges::all_of(hash,[](auto c) { return (c>='0' && c<='9') || (c>='a' && c<='f'); });
    }
    auto valid_client_metadata(std::string_view metadata) noexcept -> bool {
        return metadata.size()<=256 && std::ranges::all_of(metadata,[](unsigned char c) { return c>=32 && c!=127; });
    }
    auto parse_settings(std::span<std::uint8_t const> bytes,bool client) noexcept
        -> std::expected<SettingsView,SettingsError> {
        if (bytes.empty()) return std::unexpected(SettingsError::invalid);
        if (bytes.size()>8192) return std::unexpected(SettingsError::too_large);
        auto input=std::string_view(reinterpret_cast<char const*>(bytes.data()),bytes.size());
        SettingsView result;
        bool version=false,metadata=false,padding=false;
        std::size_t lines=0;
        while (!input.empty()) {
            if (++lines>64) return std::unexpected(SettingsError::too_large);
            auto end=input.find('\n');
            auto line=input.substr(0,end);
            input=end==input.npos ? std::string_view{} : input.substr(end+1);
            if (line.empty()) continue;
            if (std::ranges::any_of(line,[](unsigned char c) { return c<32 || c==127; })) return std::unexpected(SettingsError::invalid);
            auto split=line.find('=');
            if (split==line.npos || !split || split>128) return std::unexpected(SettingsError::invalid);
            auto key=line.substr(0,split),value=line.substr(split+1);
            if (key=="v") {
                if (version) return std::unexpected(SettingsError::duplicate);
                auto parsed=std::from_chars(value.data(),value.data()+value.size(),result.version);
                if (value.empty() || parsed.ec!=std::errc{} || parsed.ptr!=value.data()+value.size() || !result.version)
                    return std::unexpected(SettingsError::version);
                version=true;
            } else if (key=="client") {
                if (metadata) return std::unexpected(SettingsError::duplicate);
                if (!valid_client_metadata(value)) return std::unexpected(SettingsError::metadata);
                metadata=true; result.client=value;
            } else if (key=="padding-md5") {
                if (padding) return std::unexpected(SettingsError::duplicate);
                if (!valid_padding_hash(value)) return std::unexpected(SettingsError::padding_hash);
                padding=true; result.padding_md5=value;
            }
        }
        if (!version) return std::unexpected(SettingsError::version);
        if (client && !padding) return std::unexpected(SettingsError::padding_hash);
        return result;
    }
    auto encode_client_settings(std::string_view padding_md5,std::string_view metadata)
        -> std::expected<std::vector<std::uint8_t>,SettingsError> {
        if (!valid_padding_hash(padding_md5)) return std::unexpected(SettingsError::padding_hash);
        if (!valid_client_metadata(metadata)) return std::unexpected(SettingsError::metadata);
        // Metadata stays empty unless the deployment explicitly provides it.
        std::string text="v=2\nclient=";
        text.append(metadata); text.append("\npadding-md5="); text.append(padding_md5);
        return std::vector<std::uint8_t>(text.begin(),text.end());
    }
    auto encode_server_settings() -> std::vector<std::uint8_t> { return {'v','=','2'}; }
}
