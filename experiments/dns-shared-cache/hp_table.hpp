// Experimental only: fixed-capacity storage, not a complete DNS cache.
// The mm_hp checkout is supplied separately to the build script.
#pragma once
#include "table_types.hpp"
#ifdef DNS_HP_XENIUM
#include <xenium/reclamation/hazard_pointer.hpp>
#else
#include "mm_hp.hpp"
#endif
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace dns_hp_experiment {
#ifdef DNS_HP_XENIUM
using Reclaimer=xenium::reclamation::hazard_pointer<>;
#endif
// A published node is immutable. Writers serialize probing, replacement and
// deletion; readers hold one hazard pointer while copying a single slot.
// Destruction requires all readers and writers to have joined.
class HazardTable {
    struct Node :
#ifdef DNS_HP_XENIUM
        Reclaimer::enable_concurrent_ptr<Node> {
#else
        std::hazard_pointer_obj_base<Node> {
#endif
        Key key;
        Answer answer;
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
    static constexpr std::size_t slots=1024,capacity=256;
#ifdef DNS_HP_XENIUM
    using Slot=Reclaimer::concurrent_ptr<Node>;
    using Guard=Slot::guard_ptr;
#else
    using Slot=std::atomic<Node*>;
    using Guard=std::hazard_pointer;
#endif
    std::array<Slot,slots> table_{};
    Node tombstone_{{0,"",0},{},false};
    std::mutex writer_;
    std::size_t size_=0;
    static auto hash(Key const& key) noexcept -> std::size_t { return KeyHash{}(key)%slots; }
    static auto load(Slot const& slot) noexcept -> Node* {
#ifdef DNS_HP_XENIUM
        return slot.load(std::memory_order_acquire).get();
#else
        return slot.load(std::memory_order_acquire);
#endif
    }
    static auto store(Slot& slot,Node* value) noexcept -> void { slot.store(value,std::memory_order_release); }
    static auto protect(Guard& guard,Slot const& slot) -> Node* {
#ifdef DNS_HP_XENIUM
        guard.acquire(slot,std::memory_order_acquire); return guard.get();
#else
        return guard.protect(slot);
#endif
    }
    // Prepare the Xenium guard before changing the slot: acquiring a guard may
    // throw. Retiring may still allocate internally; this prototype does not
    // claim recoverability when that library's noexcept scan runs out of memory.
    static auto replace(Slot& slot,Node* old,Node* value) -> void {
#ifdef DNS_HP_XENIUM
        Guard guard{Slot::marked_ptr(old)};
        store(slot,value); guard.reclaim();
#else
        store(slot,value); old->retire();
#endif
    }
public:
    HazardTable()=default;
    HazardTable(HazardTable const&)=delete;
    ~HazardTable() {
        for (auto& slot:table_) {
            auto* node=load(slot);
            if (node && node!=&tombstone_) replace(slot,node,nullptr);
        }
    }
    [[nodiscard]] auto get(Key const& key) const -> std::optional<Answer> {
#ifdef DNS_HP_XENIUM
        Guard guard;
#else
        auto guard=std::make_hazard_pointer();
#endif
        auto start=hash(key);
        for (std::size_t probe=0;probe<slots;++probe) {
            auto* node=protect(guard,table_[(start+probe)%slots]);
            if (!node) return {};
            if (node!=&tombstone_ && node->key==key) return node->answer;
        }
        return {};
    }
    [[nodiscard]] auto put(Key key,Answer answer) -> bool {
        auto replacement=std::make_unique<Node>(std::move(key),std::move(answer));
        std::lock_guard lock(writer_);
        auto start=hash(replacement->key);
        std::size_t available=slots;
        for (std::size_t probe=0;probe<slots;++probe) {
            auto index=(start+probe)%slots;
            auto* node=load(table_[index]);
            if (node==&tombstone_) { if (available==slots) available=index; continue; }
            if (!node) { if (available==slots) available=index; break; }
            if (node->key==replacement->key) {
                replace(table_[index],node,replacement.get());
                (void)replacement.release(); return true;
            }
        }
        if (size_==capacity || available==slots) return false;
        store(table_[available],replacement.release());
        ++size_; return true;
    }
    [[nodiscard]] auto erase(Key const& key) -> bool {
        std::lock_guard lock(writer_);
        auto start=hash(key);
        for (std::size_t probe=0;probe<slots;++probe) {
            auto& slot=table_[(start+probe)%slots];
            auto* node=load(slot);
            if (!node) return false;
            if (node!=&tombstone_ && node->key==key) {
                replace(slot,node,&tombstone_);
                --size_; return true;
            }
        }
        return false;
    }
    [[nodiscard]] static auto live_nodes() noexcept -> std::size_t { return Node::live.load(std::memory_order_relaxed); }
    [[nodiscard]] static auto peak_nodes() noexcept -> std::size_t { return Node::peak.load(std::memory_order_relaxed); }
};
}
