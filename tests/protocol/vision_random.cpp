// This test uses assertions for both its checks and state transitions.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
import std;
import vision;
import vision.random;
int main() {
    for (auto bound:{256u,500u}) {
        for (int i=0;i<1000;++i) {
            auto value=vision::secure_padding_random(bound);
            assert(value && *value<bound);
        }
    }
    assert(!vision::secure_padding_random(0));
    vision::UserId user{}; vision::Sender sender(user); vision::TrafficFilter filter;
    auto initial=vision::prepare_secure(sender,filter,{},true);
    assert(initial && initial->wire.size()>=921 && initial->wire.size()<=1420 && sender.commit(true));
    std::array<std::uint8_t,1> payload{42};
    auto block=vision::prepare_secure(sender,filter,payload);
    assert(block && block->padded && sender.commit(true));
    std::vector<std::uint8_t> oversized(8172);
    auto bad=vision::prepare_secure(sender,filter,oversized);
    assert(!bad && bad.error().send==vision::SendError::invalid_size && !bad.error().random);
    std::vector<std::uint8_t> large(8192,42);
    auto prepared=vision::prepare_large_secure(sender,filter,large);
    assert(prepared && prepared->padded && sender.commit(true));
}
