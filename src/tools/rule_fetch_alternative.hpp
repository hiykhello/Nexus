// Authenticated HTTP/3 alternative state for a named rule watcher.
#pragma once

    struct Alternative {
        std::uint16_t port;
        Clock::time_point expires;
    };

    auto decimal(std::string_view value) noexcept -> std::optional<std::uint32_t> {
        if (value.empty()) return {};
        std::uint32_t number;
        auto [end,error]=std::from_chars(value.data(),value.data()+value.size(),number);
        return error==std::errc{} && end==value.data()+value.size() ? std::optional(number) : std::nullopt;
    }

    struct Advertisement {
        std::string values;
        std::optional<std::uint32_t> age;
        bool invalid=false;

        auto add(std::string_view name,std::string_view value) -> void {
            if (name=="age") {
                auto seconds=decimal(http::trim_header_ows(value));
                if (age || !seconds) invalid=true;
                age=seconds;
            } else if (name=="alt-svc") {
                if (value.size()+values.size()>=1024) {invalid=true;return;}
                if (!values.empty()) values.push_back(',');
                values.append(value);
            }
        }

        auto select(Clock::time_point start) const noexcept -> std::optional<Alternative> {
            if (invalid || values.contains('\\')) return {};
            std::string_view remaining(values);
            while (!remaining.empty()) {
                bool quoted=false;
                std::size_t end=0;
                for (;end<remaining.size();++end) {
                    if (remaining[end]=='"') quoted=!quoted;
                    if (!quoted && remaining[end]==',') break;
                }
                if (quoted) return {};
                auto item=http::trim_header_ows(remaining.substr(0,end));
                remaining.remove_prefix(std::min(end+1,remaining.size()));
                constexpr std::string_view prefix="h3=\":";
                if (!item.starts_with(prefix)) continue;
                item.remove_prefix(prefix.size());
                auto quote=item.find('"');
                if (quote==item.npos) continue;
                auto port=decimal(item.substr(0,quote));
                if (!port || !*port || *port>65535) continue;
                item=http::trim_header_ows(item.substr(quote+1));
                std::optional<std::uint32_t> max_age;
                bool valid=true;
                while (!item.empty()) {
                    if (item.front()!=';') {valid=false;break;}
                    item.remove_prefix(1);
                    auto separator=item.find(';');
                    auto parameter=http::trim_header_ows(item.substr(0,separator));
                    if (parameter.starts_with("ma=")) {
                        if (max_age) {valid=false;break;}
                        max_age=decimal(parameter.substr(3));
                        if (!max_age) {valid=false;break;}
                    }
                    if (separator==item.npos) break;
                    item.remove_prefix(separator);
                }
                if (!valid || max_age.value_or(86400)<=age.value_or(0)) continue;
                auto freshness=std::min(max_age.value_or(86400)-age.value_or(0),86400u);
                return Alternative{static_cast<std::uint16_t>(*port),start+std::chrono::seconds(freshness)};
            }
            return {};
        }
    };

    auto entity_tag(std::string_view value) noexcept -> std::string_view {
        if (value.starts_with("W/")) value.remove_prefix(2);
        if (value.size()<2 || value.front()!='"' || value.back()!='"') return {};
        auto opaque=value.substr(1,value.size()-2);
        for (unsigned char c:opaque) if (c<=0x20 || c=='"' || c==0x7f) return {};
        return value;
    }

    struct EntityTag {
        std::string value;
        bool seen=false,invalid=false;

        auto add(std::string_view name,std::string_view field) -> void {
            if (name!="etag") return;
            if (std::exchange(seen,true) || field.size()>512 || entity_tag(field).empty()) {
                invalid=true;
                return;
            }
            value=field;
        }
    };

    struct PublishedValidator {
        std::string tag,target;
        std::array<std::uint8_t,32> digest;
    };
