import std;
import endpoint.process_signals;
import platform.netlink_abi;
import nexus.thirdparty.corosio;
namespace {
    namespace p=endpoint::process;
    namespace a = ::platform::netlink_abi;
    namespace io=nex::corosio;
    auto require(bool value,unsigned line) -> void {if(!value){std::println("signal wake assertion {}",line);throw 1;}}
    auto empty(int fd) -> bool {
        std::array<char,1024> bytes{};auto count=a::recvfrom(fd,bytes.data(),bytes.size(),0,nullptr,nullptr);
        return count<0 && *a::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again);
    }
}
auto main() -> int {
    try {
        p::Signals signals;require(signals.install(),1);
        for(bool uring:{false,true}) {
            if(uring && !io::has_uring)return 77;
            auto context=io::make_io_context(uring);
            std::optional<io::local_stream_socket> reader(std::in_place,context),writer(std::in_place,context);
            auto error=io::connect_pair(*reader,*writer);require(!error,2);
            require((a::fcntl(reader->native_handle(),a::F_GETFL)&a::O_NONBLOCK) && (a::fcntl(writer->native_handle(),a::F_GETFL)&a::O_NONBLOCK),3);
            auto old_reader=reader->native_handle(),old_writer=writer->native_handle();
            std::optional<p::WakeRegistration> registration(std::in_place,old_writer);require(registration->active(),4);
            // Notifications exceed the real socket's capacity. The handler
            // remains nonblocking, saves errno and keeps its persistent latch.
            for(unsigned i=0;i<100000;++i) {
                *a::__errno_location()=12345;
                std::raise(a::SIGTERM);
                require(signals.requested()==a::SIGTERM && *a::__errno_location()==12345,5);
            }
            std::array<char,1> byte{};
            require(a::write(old_writer,byte.data(),byte.size())<0 && *a::__errno_location()==std::to_underlying(std::errc::resource_unavailable_try_again),6);
            std::optional<io::local_stream_socket> new_reader,new_writer;
            p::requested_signal=0;
            {
                p::SignalMask transition;require(transition.active(),7);
                std::raise(a::SIGINT);require(!signals.requested(),8);
                registration.reset();reader.reset();writer.reset();
                new_reader.emplace(context);new_writer.emplace(context);
                auto new_error=io::connect_pair(*new_reader,*new_writer);require(!new_error,9);
                require(new_reader->native_handle()==old_reader && new_writer->native_handle()==old_writer,10);
            }
            require(signals.requested()==a::SIGINT && p::wake_descriptor<0 && empty(new_reader->native_handle()),11);
            new_reader.reset();new_writer.reset();
            auto executor=context.get_executor();executor.on_work_started();context.restart();context.poll();executor.on_work_finished();
        }
    } catch(int code){return code;}
    std::println("signal wake: both actual backends, nonblocking fd, 100000 raises with full buffer, saved errno, masked pending signal across detach/close/fd reuse, no stale write passed");
}
