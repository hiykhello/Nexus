export module rules.regex;
import std;

export namespace rules {
    // A bounded Thompson NFA for byte patterns. Matching does not allocate,
    // backtrack or revisit a state at the same input position.
    class BoundedRegex {
        enum class Op { byte, branch, jump, begin, end, accept };
        using StateId = std::uint16_t;
        static constexpr StateId absent=std::numeric_limits<StateId>::max();
        static constexpr std::size_t max_states=192;
        using Alphabet = std::bitset<256>;

        struct State {
            Op op;
            StateId next=absent, alternative=absent;
            Alphabet bytes{};
        };
        struct Compiler;
        std::vector<State> states_;
        StateId first_=absent;
        BoundedRegex()=default;

    public:
        [[nodiscard]] static auto compile(std::string_view) -> std::expected<BoundedRegex,std::string_view>;
        [[nodiscard]] auto search(std::string_view,bool lowercase=false) const noexcept -> bool;
        [[nodiscard]] auto state_count() const noexcept -> std::size_t {return states_.size();}
    };
}

namespace rules {
    struct BoundedRegex::Compiler {
        struct Exit {StateId state; bool alternative=false;};
        struct Fragment {StateId first; std::vector<Exit> exits;};

        std::vector<State> states;
        std::string_view pattern;
        unsigned depth=0;
        std::string_view error="invalid regular expression";

        auto peek() const noexcept -> char {return pattern.empty() ? '\0' : pattern.front();}
        auto take(char wanted) noexcept -> bool {
            if (peek()!=wanted) return false;
            pattern.remove_prefix(1);
            return true;
        }
        auto emit(State state) -> StateId {
            if (states.size()==max_states) {
                error="regular expression exceeds state limit";
                return absent;
            }
            auto id=static_cast<StateId>(states.size());
            states.push_back(state);
            return id;
        }
        auto patch(std::span<Exit const> exits,StateId target) noexcept -> void {
            for (auto [state,alternative]:exits) {
                auto& instruction=states[state];
                (alternative ? instruction.alternative : instruction.next)=target;
            }
        }
        auto escaped(std::uint8_t& byte,Alphabet& mask) -> bool {
            if (pattern.empty()) return false;
            auto escaped_byte=static_cast<unsigned char>(pattern.front());
            pattern.remove_prefix(1);
            switch (escaped_byte) {
            case 'n': byte='\n'; return true;
            case 'r': byte='\r'; return true;
            case 't': byte='\t'; return true;
            case 'w':
                for (unsigned i='a';i<='z';++i) {mask.set(i);mask.set(i-'a'+'A');}
                mask.set('_');
                [[fallthrough]];
            case 'd':
                for (unsigned i='0';i<='9';++i) mask.set(i);
                return true;
            case 's':
                for (unsigned char c:std::string_view(" \t\n\r\f")) mask.set(c);
                return true;
            default:
                if (!std::string_view(R"(\.^$|?*+()[]{}-)").contains(static_cast<char>(escaped_byte))) return false;
                byte=escaped_byte;return true;
            }
        }
        auto class_member(std::uint8_t& byte,Alphabet& mask) -> bool {
            if (pattern.empty() || peek()==']' || peek()=='[') return false;
            if (take('\\')) return escaped(byte,mask);
            byte=static_cast<std::uint8_t>(pattern.front());
            pattern.remove_prefix(1);
            return true;
        }
        auto bracket() -> std::optional<Alphabet> {
            auto negated=take('^');
            Alphabet selected;
            while (peek()!=']') {
                std::uint8_t first=0;
                Alphabet generated;
                if (!class_member(first,generated)) return {};
                if (generated.any()) {
                    selected|=generated;
                    continue;
                }
                if (pattern.size()>=2 && peek()=='-' && pattern[1]!=']') {
                    pattern.remove_prefix(1);
                    std::uint8_t last=0;
                    if (!class_member(last,generated) || generated.any() || first>last) return {};
                    for (unsigned i=first;i<=last;++i) selected.set(i);
                } else selected.set(first);
            }
            pattern.remove_prefix(1);
            if (selected.none()) return {};
            if (negated) selected.flip();
            return selected;
        }
        auto atom() -> std::optional<Fragment> {
            if (take('(')) {
                if (++depth>16) {
                    error="regular expression exceeds group depth limit";
                    return {};
                }
                if (pattern.starts_with("?:")) pattern.remove_prefix(2);
                auto value=alternation();
                if (!value || !take(')')) return {};
                --depth;
                return value;
            }
            State state{Op::byte};
            if (take('^')) state.op=Op::begin;
            else if (take('$')) state.op=Op::end;
            else if (take('.')) state.bytes.set().reset('\n');
            else if (take('[')) {
                auto mask=bracket();
                if (!mask) return {};
                state.bytes=*mask;
            } else if (take('\\')) {
                std::uint8_t byte=0;
                if (!escaped(byte,state.bytes)) return {};
                if (state.bytes.none()) state.bytes.set(byte);
            } else {
                if (pattern.empty() || std::string_view("|)*+?{}]").contains(peek())) return {};
                state.bytes.set(static_cast<std::uint8_t>(pattern.front()));
                pattern.remove_prefix(1);
            }
            auto index=emit(state);
            if (index==absent) return {};
            return Fragment{index,{{index}}};
        }
        auto quantify(Fragment item,char quantifier) -> std::optional<Fragment> {
            auto split=emit({Op::branch,item.first,absent});
            if (split==absent) return {};
            if (quantifier=='?') item.exits.push_back({split,true});
            else {
                patch(item.exits,split);
                item.exits={{split,true}};
            }
            if (quantifier!='+') item.first=split;
            return item;
        }
        auto count() -> std::optional<unsigned> {
            unsigned value=0;
            auto [end,ec]=std::from_chars(pattern.data(),pattern.data()+pattern.size(),value);
            if (ec!=std::errc{}) return {};
            pattern.remove_prefix(end-pattern.data());
            return value;
        }
        auto counted(Fragment first,std::string_view atom_text,std::size_t first_state)
            -> std::optional<Fragment> {
            auto minimum=count();
            if (!minimum) return {};
            auto maximum=minimum;
            if (take(',')) maximum=count();
            if (!take('}') || (maximum && *maximum<*minimum)) return {};
            if (*minimum>=max_states || (maximum && *maximum>=max_states)) {
                error="regular expression exceeds state limit";
                return {};
            }
            if (maximum==0) {
                states.resize(first_state);
                auto pass=emit({Op::jump});
                if (pass==absent) return {};
                return Fragment{pass,{{pass}}};
            }
            auto copies=maximum.value_or(*minimum+1);
            std::optional<Fragment> combined;
            for (unsigned i=0;i<copies;++i) {
                std::optional<Fragment> next;
                if (i==0) next=std::move(first);
                else {
                    auto tail=std::exchange(pattern,atom_text);
                    next=atom();
                    pattern=tail;
                }
                if (!next) return {};
                if (i>=*minimum) next=quantify(std::move(*next),maximum ? '?' : '*');
                if (!next) return {};
                if (!combined) combined=std::move(next);
                else {
                    patch(combined->exits,next->first);
                    combined->exits=std::move(next->exits);
                }
            }
            return combined;
        }
        auto repetition() -> std::optional<Fragment> {
            auto start=pattern;
            auto first_state=states.size();
            auto assertion=peek()=='^' || peek()=='$';
            auto item=atom();
            if (!item || pattern.empty() || !std::string_view("*+?{").contains(peek())) return item;
            if (assertion) return {};
            auto quantifier=pattern.front();
            auto atom_text=start.substr(0,start.size()-pattern.size());
            pattern.remove_prefix(1);
            if (quantifier=='{') return counted(std::move(*item),atom_text,first_state);
            return quantify(std::move(*item),quantifier);
        }
        auto sequence() -> std::optional<Fragment> {
            auto combined=repetition();
            while (combined && !pattern.empty() && peek()!='|' && peek()!=')') {
                auto next=repetition();
                if (!next) return {};
                patch(combined->exits,next->first);
                combined->exits=std::move(next->exits);
            }
            return combined;
        }
        auto alternation() -> std::optional<Fragment> {
            auto combined=sequence();
            while (combined && take('|')) {
                auto right=sequence();
                if (!right) return {};
                auto split=emit({Op::branch,combined->first,right->first});
                if (split==absent) return {};
                combined->first=split;
                combined->exits.insert(combined->exits.end(),right->exits.begin(),right->exits.end());
            }
            return combined;
        }
    };

    auto BoundedRegex::compile(std::string_view pattern) -> std::expected<BoundedRegex,std::string_view> {
        if (pattern.empty() || pattern.contains('\0')) return std::unexpected("invalid regular expression");
        if (pattern.size()>255) return std::unexpected("regular expression exceeds byte limit");
        Compiler compiler{.states={},.pattern=pattern};
        auto expression=compiler.alternation();
        if (!expression || !compiler.pattern.empty()) return std::unexpected(compiler.error);
        auto accept=compiler.emit({Op::accept});
        if (accept==absent) return std::unexpected(compiler.error);
        compiler.patch(expression->exits,accept);
        BoundedRegex regex;
        regex.first_=expression->first;
        regex.states_=std::move(compiler.states);
        return regex;
    }

    auto BoundedRegex::search(std::string_view text,bool lowercase) const noexcept -> bool {
        struct StateSet {
            std::bitset<max_states> seen;
            std::array<StateId,max_states> pending;
            std::size_t size=0;
            auto add(StateId index) noexcept -> void {
                if (seen.test(index)) return;
                seen.set(index);
                pending[size++]=index;
            }
            auto clear() noexcept -> void {seen.reset();size=0;}
        };
        StateSet sets[2];
        auto* current=&sets[0];
        auto* next=&sets[1];
        for (std::size_t position=0;;++position) {
            auto at_end=position==text.size();
            auto byte=at_end ? 0 : static_cast<unsigned char>(text[position]);
            if (lowercase && byte>='A' && byte<='Z') byte+=('a'-'A');
            current->add(first_);
            for (std::size_t i=0;i<current->size;++i) {
                auto const& state=states_[current->pending[i]];
                switch (state.op) {
                case Op::accept:
                    return true;
                case Op::branch:
                    current->add(state.next);
                    current->add(state.alternative);
                    break;
                case Op::jump:
                    current->add(state.next);
                    break;
                case Op::begin:
                    if (position==0) current->add(state.next);
                    break;
                case Op::end:
                    if (at_end) current->add(state.next);
                    break;
                case Op::byte:
                    if (!at_end && state.bytes.test(byte)) next->add(state.next);
                    break;
                }
            }
            if (at_end) return false;
            current->clear();
            std::swap(current,next);
        }
    }
}
