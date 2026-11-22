#pragma once

    struct Url {
        http::ConnectRequest destination;
        std::string authority,target;
    };

    auto parse_url(std::string_view text) -> std::optional<Url> {
        if(!text.starts_with("https://") || std::ranges::any_of(text,[](unsigned char c) {
            return c<=0x20 || c>=0x7f || c=='#' || c=='\\';
        })) return {};
        text.remove_prefix(8);
        auto separator=text.find_first_of("/?");
        auto authority=text.substr(0,separator);
        if(authority.empty() || authority.contains('@'))return {};
        auto address=std::string(authority);
        if(authority.ends_with(']') || !authority.contains(':'))address+=":443";
        auto destination=http::parse_destination_authority(address);
        if(destination.status!=http::ConnectStatus::accepted)return {};
        std::string target="/";
        if(separator!=text.npos) {
            if(text[separator]=='/')target.clear();
            target+=text.substr(separator);
        }
        return Url{std::move(destination),std::string(authority),std::move(target)};
    }


    auto same_origin(Url const& a,Url const& b) noexcept -> bool {
        auto const& x=a.destination;
        auto const& y=b.destination;
        if (x.kind!=y.kind || x.port!=y.port) return false;
        if (x.kind!=http::HostKind::domain) return x.address==y.address;
        auto lower=[](char c) {return c>='A' && c<='Z' ? static_cast<char>(c-'A'+'a') : c;};
        return std::ranges::equal(x.host,y.host,{},lower,lower);
    }

    auto normalize_redirect_target(std::string_view target) -> std::string {
        auto query=target.find('?');
        auto path=target.substr(1,query==target.npos ? query : query-1);
        std::vector<std::string_view> segments;
        for (;;) {
            auto slash=path.find('/');
            auto segment=path.substr(0,slash);
            auto final=slash==path.npos;
            if (segment=="..") {
                if (!segments.empty()) segments.pop_back();
                if (final) segments.emplace_back();
            } else if (segment!=".") segments.push_back(segment);
            else if (final) segments.emplace_back();
            if (final) break;
            path.remove_prefix(slash+1);
        }
        std::string result;
        for (auto segment:segments) result.append("/").append(segment);
        if (query!=target.npos) result.append(target.substr(query));
        return result;
    }

    auto redirect_target(Url const& current,std::string_view location) -> std::optional<std::string> {
        location=location.substr(0,location.find('#'));
        if (location.empty() || location.starts_with("//")) return {};
        std::string next;
        if (location.starts_with("https://")) next=location;
        else {
            // A colon in the first relative path segment introduces a scheme.
            if (location.substr(0,location.find_first_of("/?")).contains(':')) return {};
            next="https://"+current.authority;
            std::string_view path(current.target);
            path=path.substr(0,path.find('?'));
            if (location.starts_with('?')) next.append(path);
            else if (!location.starts_with('/')) next.append(path.substr(0,path.rfind('/')+1));
            next.append(location);
        }
        auto parsed=parse_url(next);
        if (!parsed || !same_origin(current,*parsed)) return {};
        auto target=normalize_redirect_target(parsed->target);
        if (target.starts_with("//")) return {};
        return target;
    }

    struct Location {
        std::optional<std::string> value;
        bool duplicate=false;

        auto add(std::string_view name,std::string_view field) -> void {
            if (name!="location") return;
            if (value || field.empty() || field.size()>2048) duplicate=true;
            else value=field;
        }

        auto follow(Url const& current) const -> std::optional<std::string> {
            if (duplicate || !value) return {};
            return redirect_target(current,*value);
        }
    };
