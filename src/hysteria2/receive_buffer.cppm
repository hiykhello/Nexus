export module hysteria2.receive_buffer;
import std;
import nexus.thirdparty.nghttp3;

export namespace hysteria2 {
    // Receive bytes have no borrowed readers. Free consumed blocks promptly,
    // and charge every block to the connection's QUIC/HTTP3 allocator.
    class ReceiveBuffer {
        struct Block {
            Block* next;
            std::array<std::uint8_t,16384> data;
        };
        nex::nghttp3::nghttp3_mem memory_;
        Block* head_=nullptr;
        Block* tail_=nullptr;
        std::size_t limit_,size_=0,read_=0,written_=0;

        auto discard_head() noexcept -> void {
            auto* old=head_;
            head_=old->next;
            std::destroy_at(old);
            memory_.free(old,memory_.user_data);
            read_=0;
            if (!head_) {tail_=nullptr;written_=0;}
        }
    public:
        explicit ReceiveBuffer(nex::nghttp3::nghttp3_mem memory,std::size_t limit) noexcept
            :memory_(memory),limit_(limit) {}
        ReceiveBuffer(ReceiveBuffer const&)=delete;
        auto operator=(ReceiveBuffer const&) -> ReceiveBuffer& = delete;
        ~ReceiveBuffer() {clear();}
        [[nodiscard]] auto size() const noexcept -> std::size_t {return size_;}
        auto clear() noexcept -> void {
            while (head_) discard_head();
            size_=0;
        }

        auto append(std::span<std::uint8_t const> bytes) noexcept -> bool {
            if (bytes.size()>limit_-size_) return false;
            while (!bytes.empty()) {
                if (!tail_ || written_==tail_->data.size()) {
                    auto* storage=memory_.malloc(sizeof(Block),memory_.user_data);
                    if (!storage) return false;
                    auto* block=::new(storage) Block;
                    block->next=nullptr;
                    if (tail_) tail_->next=block;
                    else head_=block;
                    tail_=block;
                    written_=0;
                }
                auto count=std::min(bytes.size(),tail_->data.size()-written_);
                std::ranges::copy(bytes.first(count),tail_->data.begin()+written_);
                written_+=count;
                size_+=count;
                bytes=bytes.subspan(count);
            }
            return true;
        }
        auto pull(std::span<std::uint8_t> output) noexcept -> std::size_t {
            auto total=std::min(output.size(),size_);
            output=output.first(total);
            while (!output.empty()) {
                auto end=head_==tail_ ? written_ : head_->data.size();
                auto count=std::min(output.size(),end-read_);
                std::ranges::copy(std::span(head_->data).subspan(read_,count),output.begin());
                read_+=count;
                if (read_==end) discard_head();
                output=output.subspan(count);
            }
            size_-=total;
            return total;
        }
    };
}
