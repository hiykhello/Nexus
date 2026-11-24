#include <boost/corosio/backend.hpp>
import std;
import capy;
import corosio;

namespace io = ::corosio;
using namespace std::chrono_literals;

auto exchange(io::local_stream_socket& first, io::local_stream_socket& second, bool& done) -> capy::task<> {
    std::array<char,4> sent{'p','i','n','g'}, received{};
    auto [write_error,written]=co_await first.write_some(capy::const_buffer(sent.data(),sent.size()));
    if (write_error || written!=sent.size()) co_return;
    auto [read_error,read]=co_await second.read_some(capy::mutable_buffer(received.data(),received.size()));
    done=!read_error && read==received.size() && received==sent;
}
int main() {
#if BOOST_COROSIO_HAVE_LIBURING
    io::io_context context{io::uring};
#else
    io::io_context context{io::epoll};
#endif
    io::local_stream_socket first{context},second{context};
    if (io::connect_pair(first,second)) return 1;
    bool done=false;
    capy::run_async(context.get_executor())(exchange(first,second,done));
    (void)context.run_for(1s);
    first.close(); second.close();
    if (!done || !context.stopped()) return 2;
    std::cout << "independent Capy and Corosio module exchange passed\n";
}
