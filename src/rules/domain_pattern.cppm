export module rules.domain_pattern;
import std;

export namespace rules {
    enum class DomainPattern { exact, suffix, keyword, wildcard };

    // Patterns are normalized and validated by their configuration owner.
    // Inputs are borrowed ASCII names: traffic and DNS retain their own name
    // validation, while sharing the allocation-free matching algorithms.
    inline auto domain_suffix_matches(std::string_view name,std::string_view suffix) noexcept -> bool {
        if (name.size()<suffix.size()) return false;
        auto start=name.size()-suffix.size();
        if (start && name[start-1]!='.') return false;
        for (std::size_t i=0;i<suffix.size();++i) {
            auto c=name[start+i];
            if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            if (c!=suffix[i]) return false;
        }
        return true;
    }
    inline auto domain_keyword_matches(std::string_view name,std::string_view keyword) noexcept -> bool {
        if (keyword.empty() || keyword.size()>253 || keyword.size()>name.size()) return false;
        std::array<std::uint8_t,253> prefix{};
        for (std::size_t i=1,j=0;i<keyword.size();++i) {
            while (j && keyword[i]!=keyword[j]) j=prefix[j-1];
            if (keyword[i]==keyword[j]) ++j;
            prefix[i]=static_cast<std::uint8_t>(j);
        }
        std::size_t j=0;
        for (auto c:name) {
            if (c>='A' && c<='Z') c=static_cast<char>(c+('a'-'A'));
            while (j && c!=keyword[j]) j=prefix[j-1];
            if (c==keyword[j] && ++j==keyword.size()) return true;
        }
        return false;
    }
    inline auto domain_pattern_matches(DomainPattern kind,std::string_view name,std::string_view pattern) noexcept -> bool {
        switch (kind) {
        case DomainPattern::exact:
            return name.size()==pattern.size() && domain_suffix_matches(name,pattern);
        case DomainPattern::suffix:
            return domain_suffix_matches(name,pattern);
        case DomainPattern::keyword:
            return domain_keyword_matches(name,pattern);
        case DomainPattern::wildcard: {
            if (!pattern.starts_with("*.")) return false;
            auto suffix=pattern.substr(2);
            if (name.size()<=suffix.size()+1 || !domain_suffix_matches(name,suffix)) return false;
            return name.substr(0,name.size()-suffix.size()-1).find('.')==std::string_view::npos;
        }
        }
        return false;
    }
}
