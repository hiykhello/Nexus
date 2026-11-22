// Experimental fixed-capacity table, not a complete DNS cache.
// Each registered reader is exclusive to one synchronous lookup at a time.
#pragma once
#include "table_types.hpp"
#include <array>
#include <atomic>
#include <cassert>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <utility>

namespace dns_hp_experiment {
#ifdef DNS_BOUNDED_TEST_HOOK
void before_protect_for_test();
void before_tag_publish_for_test();
#endif
template<class KeyType,class AnswerType,class HashType,class EqualType=std::equal_to<KeyType>>
class BoundedTable {
    using Key=KeyType;
    using Answer=AnswerType;
    using KeyHash=HashType;
    struct Node {
        Key key;
        Answer answer;
        Node* retired_next=nullptr; // Writer only, after removal from the table.
        bool counted;
        inline static std::atomic<std::size_t> live=0,peak=0;
        Node(Key k,Answer a,bool count=true) : key(std::move(k)),answer(std::move(a)),counted(count) {
            if (counted) {
                auto n=live.fetch_add(1,std::memory_order_relaxed)+1;
                auto p=peak.load(std::memory_order_relaxed);
                while (p<n && !peak.compare_exchange_weak(p,n,std::memory_order_relaxed)) {}
            }
        }
        ~Node() { if (counted) live.fetch_sub(1,std::memory_order_relaxed); }
    };
    // Distinct readers write different cache lines on the lookup path.
    struct alignas(64) Hazard { std::atomic<Node*> pointer=nullptr; std::atomic<bool> claimed=false; };
    // Fingerprints can be checked before publishing a hazard. Vacant slots
    // may be reused without tombstones: readers scan the entire table on miss.
    struct Slot { std::atomic<std::uint64_t> tag=0; std::atomic<Node*> pointer=nullptr; };
    static constexpr std::size_t slots=512,capacity=256;
    std::array<Slot,slots> table_{};
    std::unique_ptr<Hazard[]> hazards_;
    std::size_t hazard_count_;
    std::mutex writer_;
    std::size_t size_=0;
    Node* retired_=nullptr;
    static auto tag(std::size_t hash) noexcept -> std::uint64_t {
        return static_cast<std::uint64_t>(hash) | (std::uint64_t(1)<<63);
    }

    // All slot and hazard operations are sequentially consistent. If a scan
    // misses a new hazard, the reader's subsequent validation must observe the
    // removal before it may dereference the node. No allocation occurs here.
    auto collect() noexcept -> void {
        auto** link=&retired_;
        while (auto* node=*link) {
            bool protected_node=false;
            for (std::size_t i=0;i<hazard_count_;++i)
                if (hazards_[i].pointer.load()==node) { protected_node=true; break; }
            if (protected_node) link=&node->retired_next;
            else { *link=node->retired_next; delete node; }
        }
    }
    auto retire(Node* node) noexcept -> void {
        node->retired_next=retired_; retired_=node; collect();
    }
    [[nodiscard]] auto insert_prepared(std::unique_ptr<Node> replacement) -> bool {
        auto hash=KeyHash{}(replacement->key),start=hash%slots,wanted=tag(hash);
        std::size_t available=slots;
        for (std::size_t probe=0;probe<slots;++probe) {
            auto index=(start+probe)%slots;
            auto fingerprint=table_[index].tag.load();
            if (!fingerprint) { if (available==slots) available=index; continue; }
            if (fingerprint==wanted) {
                auto* node=table_[index].pointer.load();
                if (EqualType{}(node->key,replacement->key)) {
                    table_[index].pointer.store(replacement.release()); retire(node); return true;
                }
            }
        }
        if (size_==capacity || available==slots) return false;
        table_[available].pointer.store(replacement.release());
#ifdef DNS_BOUNDED_TEST_HOOK
        before_tag_publish_for_test();
#endif
        table_[available].tag.store(wanted); ++size_; return true;
    }
    [[nodiscard]] auto erase_locked(Key const& key) -> bool {
        auto hash=KeyHash{}(key),start=hash%slots,wanted=tag(hash);
        for (std::size_t probe=0;probe<slots;++probe) {
            auto& slot=table_[(start+probe)%slots];
            auto fingerprint=slot.tag.load();
            if (fingerprint==wanted) {
                auto* node=slot.pointer.load();
                if (EqualType{}(node->key,key)) {
                    slot.pointer.store(nullptr); slot.tag.store(0); --size_; retire(node); return true;
                }
            }
        }
        return false;
    }
public:
    class Prepared {
        std::unique_ptr<Node> node_;
        friend class BoundedTable;
        friend class Writer;
        explicit Prepared(std::unique_ptr<Node> node) : node_(std::move(node)) {}
    public:
        Prepared(Prepared const&)=delete;
        Prepared(Prepared&&)=default;
    };
    class Writer {
        BoundedTable* owner_;
        std::unique_lock<std::mutex> lock_;
        friend class BoundedTable;
        explicit Writer(BoundedTable& owner) : owner_(&owner),lock_(owner.writer_) {}
    public:
        Writer(Writer const&)=delete;
        Writer(Writer&&)=default;
        // Callers retaining prepared nodes are responsible for their bound.
        [[nodiscard]] auto prepare(Key key,Answer answer) -> Prepared {
            return Prepared(std::make_unique<Node>(std::move(key),std::move(answer)));
        }
        [[nodiscard]] auto put(Prepared prepared) -> bool { return owner_->insert_prepared(std::move(prepared.node_)); }
        [[nodiscard]] auto erase(Key const& key) -> bool { return owner_->erase_locked(key); }
    };
    class Reader {
        BoundedTable* owner_;
        Hazard* hazard_;
        friend class BoundedTable;
        Reader(BoundedTable& owner,std::size_t index) : owner_(&owner),hazard_(&owner.hazards_[index]) {
            if (hazard_->claimed.exchange(true)) throw std::logic_error("reader already registered");
        }
    public:
        Reader(Reader const&)=delete;
        auto operator=(Reader const&) -> Reader& = delete;
        Reader(Reader&& other) noexcept : owner_(std::exchange(other.owner_,nullptr)),hazard_(other.hazard_) {}
        ~Reader() {
            if (owner_) {
                assert(hazard_->pointer.load()==nullptr);
                hazard_->claimed.store(false);
            }
        }
        // Callback is synchronous, must not re-enter using this Reader, and
        // must not retain references to the value after it returns.
        template<class Function>
        auto visit(Key const& key,Function&& function) -> bool {
            struct Release { Hazard& h; ~Release() { h.pointer.store(nullptr); } } release{*hazard_};
            auto hash=KeyHash{}(key),start=hash%slots,wanted=tag(hash);
            for (std::size_t probe=0;probe<slots;++probe) {
                auto& slot=owner_->table_[(start+probe)%slots];
                auto fingerprint=slot.tag.load();
                if (fingerprint!=wanted) continue;
#ifdef DNS_BOUNDED_TEST_HOOK
                before_protect_for_test();
#endif
                Node* node;
                do { node=slot.pointer.load(); hazard_->pointer.store(node); } while (node!=slot.pointer.load());
                if (node && EqualType{}(node->key,key) && slot.tag.load()==wanted) {
                    std::forward<Function>(function)(node->answer); return true;
                }
            }
            return false;
        }
        [[nodiscard]] auto get(Key const& key) -> std::optional<Answer> {
            std::optional<Answer> result;
            (void)visit(key,[&](Answer const& answer) { result=answer; });
            return result;
        }
    };
    explicit BoundedTable(std::size_t readers=64) : hazards_(std::make_unique<Hazard[]>(readers)),hazard_count_(readers) {}
    BoundedTable(BoundedTable const&)=delete;
    ~BoundedTable() {
        // The caller must join all writers and destroy all readers first.
        for (std::size_t i=0;i<hazard_count_;++i) assert(!hazards_[i].claimed.load());
        for (auto& slot:table_) {
            auto* node=slot.pointer.load();
            if (node) delete node;
        }
        collect(); assert(!retired_);
    }
    [[nodiscard]] auto reader(std::size_t index) -> Reader {
        if (index>=hazard_count_) throw std::out_of_range("reader index");
        return Reader(*this,index);
    }
    [[nodiscard]] auto writer() -> Writer { return Writer(*this); }
    [[nodiscard]] auto put(Key key,Answer answer) -> bool {
        auto handle=writer();
        auto prepared=handle.prepare(std::move(key),std::move(answer));
        return handle.put(std::move(prepared));
    }
    [[nodiscard]] auto erase(Key const& key) -> bool {
        auto handle=writer(); return handle.erase(key);
    }
    [[nodiscard]] static auto live_nodes() noexcept -> std::size_t { return Node::live.load(std::memory_order_relaxed); }
    [[nodiscard]] static auto peak_nodes() noexcept -> std::size_t { return Node::peak.load(std::memory_order_relaxed); }
};
using HazardTable=BoundedTable<Key,Answer,KeyHash>;
}
