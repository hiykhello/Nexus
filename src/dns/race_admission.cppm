export module dns.race_admission;
import std;

export namespace dns {
    // Shared across DNS message and address programs, workers and listeners.
    // Admission is nonblocking and a rejected request must fail explicitly.
    class RaceAdmission {
        static inline std::atomic<std::size_t> active_{0};
        bool held_=false;
    public:
        static constexpr std::size_t maximum=32;
        RaceAdmission() noexcept {
            auto current=active_.load(std::memory_order_relaxed);
            while(current<maximum) {
                if(active_.compare_exchange_weak(current,current+1,std::memory_order_acquire,std::memory_order_relaxed)) {held_=true;break;}
            }
        }
        RaceAdmission(RaceAdmission const&)=delete;
        auto operator=(RaceAdmission const&) -> RaceAdmission& = delete;
        ~RaceAdmission(){if(held_)active_.fetch_sub(1,std::memory_order_release);}
        [[nodiscard]] auto acquired() const noexcept -> bool {return held_;}
    };
}
