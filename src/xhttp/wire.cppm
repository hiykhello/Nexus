export module xhttp.wire;
import std;
import xhttp.config;

export namespace xhttp {
    enum class WireError { path, session, sequence, padding, header };
    using Field=std::pair<std::string,std::string>;

    [[nodiscard]] constexpr auto path_byte(char c) noexcept -> bool {
        return (c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9') ||
            c=='-' || c=='_' || c=='.' || c=='~';
    }

    [[nodiscard]] inline auto normalize_path(std::string_view path) -> std::expected<std::string,WireError> {
        if (path.empty() || path.front()!='/' || path.size()>1024) return std::unexpected(WireError::path);
        auto rest=path.substr(1);
        while (!rest.empty()) {
            auto split=rest.find('/');
            auto segment=rest.substr(0,split);
            if (segment.empty() || segment=="." || segment==".." || !std::ranges::all_of(segment,path_byte))
                return std::unexpected(WireError::path);
            if (split==rest.npos) break;
            rest.remove_prefix(split+1);
        }
        auto result=std::string(path);
        if (path.back()!='/') result.push_back('/');
        return result;
    }

    [[nodiscard]] constexpr auto valid_session(std::string_view value) noexcept -> bool {
        if (value.size()!=36 || value[14]!='4' || std::string_view("89ab").find(value[19])==value.npos) return false;
        for (std::size_t i=0;i<value.size();++i) {
            char c=value[i];
            if (i==8 || i==13 || i==18 || i==23) {
                if (c!='-') return false;
            } else if (!(c>='0' && c<='9') && !(c>='a' && c<='f')) return false;
        }
        return true;
    }

    [[nodiscard]] inline auto session_id(std::array<std::uint8_t,16> random) -> std::string {
        constexpr std::string_view hex="0123456789abcdef";
        random[6]=(random[6]&15)|64;
        random[8]=(random[8]&63)|128;
        std::string result;
        result.reserve(36);
        for (std::size_t i=0;i<random.size();++i) {
            if (i==4 || i==6 || i==8 || i==10) result.push_back('-');
            result.push_back(hex[random[i]>>4]);
            result.push_back(hex[random[i]&15]);
        }
        return result;
    }

    struct Metadata {
        std::string_view session;
        std::optional<std::uint64_t> sequence;
    };

    [[nodiscard]] inline auto metadata(std::string_view target,std::string_view prefix) noexcept
        -> std::expected<Metadata,WireError> {
        auto path=target.substr(0,target.find('?'));
        if (!path.starts_with(prefix)) return std::unexpected(WireError::path);
        auto rest=path.substr(prefix.size());
        if (rest.empty()) return Metadata{};
        auto separator=rest.find('/');
        auto id=rest.substr(0,separator);
        if (!valid_session(id)) return std::unexpected(WireError::session);
        if (separator==rest.npos) return Metadata{id,{}};
        auto seq=rest.substr(separator+1);
        if (seq.empty() || (seq.size()>1 && seq.front()=='0')) return std::unexpected(WireError::sequence);
        std::uint64_t number=0;
        auto [tail,error]=std::from_chars(seq.data(),seq.data()+seq.size(),number);
        if (error!=std::errc{} || tail!=seq.data()+seq.size() || number==std::numeric_limits<std::uint64_t>::max())
            return std::unexpected(WireError::sequence);
        return Metadata{id,number};
    }

    [[nodiscard]] inline auto valid_header(std::string_view name,std::string_view value) noexcept -> bool {
        constexpr std::string_view punctuation="!#$%&'*+-.^_`|~";
        constexpr std::array forbidden{"host","connection","transfer-encoding","content-length","upgrade",
            "keep-alive","proxy-connection","te","trailer","referer","x-padding","x-accel-buffering","cache-control"};
        return !name.empty() && name.size()<=64 && !std::ranges::contains(forbidden,name) &&
            std::ranges::all_of(name,[&](char c) {return (c>='a' && c<='z') ||
                (c>='0' && c<='9') || punctuation.contains(c);}) && value.size()<=2048 &&
            std::ranges::all_of(value,[](unsigned char c){return c>=32 && c<127;});
    }

    [[nodiscard]] inline auto valid_padding(Padding const& padding) noexcept -> bool {
        return padding.minimum<=padding.maximum && padding.maximum<=8192 &&
            (padding.placement!=Placement::header || padding.header=="x-padding" || valid_header(padding.header,""));
    }

    [[nodiscard]] inline auto padding_bytes(Padding const& settings,std::uint64_t uniform) -> std::string {
        auto width=std::uint64_t(settings.maximum)-settings.minimum+1;
        return std::string(settings.minimum+uniform%width,'X');
    }

    [[nodiscard]] inline auto query_padding(std::string_view target) noexcept -> std::optional<std::string_view> {
        auto index=target.find('?');
        if (index==target.npos) return {};
        target.remove_prefix(index+1);
        std::optional<std::string_view> result;
        while (!target.empty()) {
            auto separator=target.find('&');
            auto param=target.substr(0,separator);
            if (param.starts_with("x_padding=")) {
                if (result) return {};
                result=param.substr(10);
            }
            if (separator==target.npos) break;
            target.remove_prefix(separator+1);
        }
        return result;
    }

    [[nodiscard]] inline auto check_padding(Padding const& options,std::string_view target,
        std::span<Field const> fields) noexcept -> bool {
        std::optional<std::string_view> value;
        if (options.placement==Placement::query) value=query_padding(target);
        else {
            auto header=options.placement==Placement::referer ? std::string_view("referer") : std::string_view(options.header);
            for (auto const& [name,data]:fields) if (name==header) {
                if (value) return false;
                value=data;
            }
            if (value && options.placement==Placement::referer) value=query_padding(*value);
        }
        return (value || !options.minimum) && (!value || (value->size()>=options.minimum &&
            value->size()<=options.maximum && std::ranges::all_of(*value,[](char c){return c=='X';})));
    }
}
