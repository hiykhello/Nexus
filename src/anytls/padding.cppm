export module anytls.padding;
import std;
import anytls;

export namespace anytls {
    inline constexpr std::string_view default_padding_scheme=
        "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n"
        "3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";
    inline constexpr std::uint32_t max_padding_size=1024*1024;
    enum class PaddingError { invalid,too_large,duplicate };
    struct PaddingStep { bool check=false; std::uint32_t min=0,max=0; };
    class PaddingScheme {
        struct Record { std::uint32_t packet; std::vector<PaddingStep> steps; };
        std::string raw_;
        std::uint32_t stop_=0;
        std::vector<Record> records_;
        static auto number(std::string_view text) noexcept -> std::optional<std::uint32_t> {
            std::uint32_t result=0;
            auto parsed=std::from_chars(text.data(),text.data()+text.size(),result);
            if (text.empty() || parsed.ec!=std::errc{} || parsed.ptr!=text.data()+text.size()) return {};
            return result;
        }
    public:
        static auto parse(std::string_view raw) -> std::expected<PaddingScheme,PaddingError> {
            if (raw.empty()) return std::unexpected(PaddingError::invalid);
            if (raw.size()>65535) return std::unexpected(PaddingError::too_large);
            PaddingScheme result;
            result.raw_=raw;
            bool stopped=false;
            std::size_t lines=0,steps=0;
            while (!raw.empty()) {
                if (++lines>65) return std::unexpected(PaddingError::too_large);
                auto end=raw.find('\n'); auto line=raw.substr(0,end);
                raw=end==raw.npos ? std::string_view{} : raw.substr(end+1);
                if (line.ends_with('\r')) line.remove_suffix(1);
                if (line.empty()) continue;
                auto split=line.find('=');
                if (split==line.npos || !split) return std::unexpected(PaddingError::invalid);
                auto key=line.substr(0,split),value=line.substr(split+1);
                if (key=="stop") {
                    if (stopped) return std::unexpected(PaddingError::duplicate);
                    auto stop=number(value);
                    if (!stop) return std::unexpected(PaddingError::invalid);
                    result.stop_=*stop; stopped=true; continue;
                }
                auto packet=number(key);
                if (!packet || (key.size()>1 && key.front()=='0')) return std::unexpected(PaddingError::invalid);
                if (std::ranges::find(result.records_,*packet,&Record::packet)!=result.records_.end()) return std::unexpected(PaddingError::duplicate);
                if (result.records_.size()>=64) return std::unexpected(PaddingError::too_large);
                Record record{*packet,{}};
                for (;;) {
                    if (++steps>256) return std::unexpected(PaddingError::too_large);
                    auto comma=value.find(','); auto step=value.substr(0,comma);
                    if (step=="c") record.steps.push_back({true});
                    else {
                        auto dash=step.find('-');
                        if (dash==step.npos) return std::unexpected(PaddingError::invalid);
                        auto min=number(step.substr(0,dash)),max=number(step.substr(dash+1));
                        if (!min || !max) return std::unexpected(PaddingError::invalid);
                        if (*min>*max) std::swap(min,max);
                        if (!*min || *max>max_padding_size || (!*packet && *max>65535)) return std::unexpected(PaddingError::too_large);
                        record.steps.push_back({false,*min,*max});
                    }
                    if (comma==value.npos) break;
                    value=value.substr(comma+1);
                }
                result.records_.push_back(std::move(record));
            }
            if (!stopped) return std::unexpected(PaddingError::invalid);
            return result;
        }
        auto raw() const noexcept -> std::string_view { return raw_; }
        auto stop() const noexcept -> std::uint32_t { return stop_; }
        auto steps(std::uint32_t packet) const noexcept -> std::span<PaddingStep const> {
            if (packet && packet>=stop_) return {};
            auto record=std::ranges::find(records_,packet,&Record::packet);
            return record==records_.end() ? std::span<PaddingStep const>{} : std::span<PaddingStep const>(record->steps);
        }
    };
    // The caller supplies a fresh cryptographic random sample. Rejected
    // samples must be redrawn; modulo reduction alone would be biased.
    inline auto sample_padding(PaddingStep step,std::uint32_t random) noexcept -> std::optional<std::uint32_t> {
        if (step.check || !step.min || step.max<step.min || step.max>max_padding_size) return {};
        if (step.min==step.max) return step.min;
        auto range=step.max-step.min;
        auto threshold=std::uint32_t(0-range)%range;
        if (random<threshold) return {};
        return step.min+random%range;
    }
    // Input ends at a frame boundary. Match the reference's waste framing:
    // with data, fit waste headers inside size; without data, size counts
    // only waste payload and its headers are additional bytes.
    inline auto pad_packet(std::span<std::uint8_t const> input,std::size_t size)
        -> std::expected<std::vector<std::uint8_t>,PaddingError> {
        if (size>max_padding_size) return std::unexpected(PaddingError::too_large);
        if (input.size()>size) return std::unexpected(PaddingError::invalid);
        std::vector<std::uint8_t> result;
        result.reserve(size+((size+65534)/65535)*header_size);
        result.insert(result.end(),input.begin(),input.end());
        auto remaining=size-input.size();
        while (input.empty() ? remaining>0 : remaining>header_size) {
            auto length=std::min(input.empty() ? remaining : remaining-header_size,max_payload);
            append_header(result,{Command::waste,0,static_cast<std::uint16_t>(length)});
            result.resize(result.size()+length,0);
            remaining-=input.empty() ? length : header_size+length;
        }
        return result;
    }
}
