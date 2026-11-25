module;
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/random.h>
#elif defined(__APPLE__)
#include <cstdlib>
#include <sys/ucred.h>
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

module cli.control;
import std;
import platform.unique_fd;

namespace cli {
    namespace {
        constexpr std::string_view version="NEXUS/1";
        constexpr std::size_t max_request=1024,max_reply=65536;

        using ControlFd = platform::UniqueFd;

        auto socket_address(std::string_view path) -> std::optional<sockaddr_un> {
            sockaddr_un address{};
            if (!path.starts_with('/') || path.size()>=sizeof(address.sun_path) ||
                path.ends_with('/') || path.contains('\0')) return {};
            address.sun_family=AF_UNIX;
            std::ranges::copy(path,address.sun_path);
            return address;
        }

        auto socket_size(sockaddr_un const& address) noexcept -> socklen_t {
            return static_cast<socklen_t>(offsetof(sockaddr_un,sun_path)+
                std::char_traits<char>::length(address.sun_path)+1);
        }

        auto system_error(std::string_view action) -> std::string {
            return std::string(action)+": "+std::error_code(errno,std::generic_category()).message();
        }

        auto peer_uid(int fd) noexcept -> std::optional<uid_t> {
#if defined(__linux__)
            ucred peer{};
            socklen_t size=sizeof(peer);
            if (::getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)!=0 ||
                size!=sizeof(peer) || peer.uid==static_cast<uid_t>(-1)) return {};
            return peer.uid;
#elif defined(__APPLE__)
            uid_t uid{};
            gid_t gid{};
            if (::getpeereid(fd,&uid,&gid)!=0 || uid==static_cast<uid_t>(-1)) return {};
            return uid;
#else
            (void)fd;
            return {};
#endif
        }

        auto fill_control_random(std::span<std::uint8_t> out) noexcept -> bool {
#if defined(__linux__)
            ssize_t size;
            do {
                size=::getrandom(out.data(),out.size(),0);
            } while (size<0 && errno==EINTR);
            return size==static_cast<ssize_t>(out.size());
#elif defined(__APPLE__)
            ::arc4random_buf(out.data(),out.size());
            return true;
#else
            return false;
#endif
        }

        auto dispatch(std::string_view wire,ControlRole role,ControlHandler handler) -> std::expected<std::string,std::string> {
            std::array<std::string_view,8> arguments;
            std::size_t count=0;
            auto split=wire.find(' ');
            if (split==wire.npos || wire.substr(0,split)!=version)
                return std::unexpected("unsupported-version");
            wire.remove_prefix(split+1);
            while (!wire.empty()) {
                auto end=wire.find('\0');
                auto token=wire.substr(0,end);
                if (count==arguments.size() || token.empty()) return std::unexpected("invalid-request");
                arguments[count++]=token;
                if (end==wire.npos) break;
                wire.remove_prefix(end+1);
                if (wire.empty()) return std::unexpected("invalid-request");
            }
            if (!count) return std::unexpected("invalid-request");
            return handler(role,std::span(arguments).first(count));
        }
    }

    struct LocalControl::Impl {
        using Clock=std::chrono::steady_clock;
        struct Peer {
            ControlFd fd;
            Clock::time_point expiry;
            ControlRole role;
#if !defined(__linux__)
            std::string in, out;
            std::size_t out_offset=0;
            bool writing=false;
#endif
        };
        ControlFd listener, directory;
        std::string entry, instance;
        ControlDiagnostics diagnostics;
        dev_t device=0;
        ino_t inode=0;
        std::vector<Peer> peers;
        std::optional<uid_t> reader;

        ~Impl() {
            struct stat current{};
            if (directory && inode && ::fstatat(directory.get(),entry.c_str(),&current,AT_SYMLINK_NOFOLLOW)==0 &&
                S_ISSOCK(current.st_mode) && current.st_dev==device && current.st_ino==inode)
                (void)::unlinkat(directory.get(),entry.c_str(),0);
        }

        auto start(std::string_view path,std::optional<std::uint32_t> read_uid) -> std::expected<void,std::string> {
            if (read_uid) {
                if (*read_uid==::geteuid())
                    return std::unexpected("control read-uid must differ from the process UID");
                // An unmapped peer appears as the kernel overflow UID in this namespace.
                std::ifstream sysctl("/proc/sys/kernel/overflowuid");
                uid_t overflow;
                if (!(sysctl>>overflow) || *read_uid==overflow || ::geteuid()==overflow)
                    return std::unexpected("shared control socket requires unambiguous UIDs");
                reader=*read_uid;
            }
            auto address=socket_address(path);
            if (!address) return std::unexpected("control socket path must be an absolute Unix socket path");
            auto slash=path.rfind('/');
            auto parent=std::string(path.substr(0,slash==0 ? 1 : slash));
            entry=path.substr(slash+1);
            directory=ControlFd(::open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW));
            struct stat base{};
            auto disallowed=reader ? 022 : 077;
            if (!directory || ::fstat(directory.get(),&base)<0 || base.st_uid!=::geteuid() ||
                (base.st_mode&disallowed)!=0)
                return std::unexpected(reader ? "control socket directory must be owned by the process user and writable only by its owner" :
                    "control socket directory must be owned by the process user and private");
#if defined(__linux__)
            auto anchored=std::format("/proc/self/fd/{}/{}",directory.get(),entry);
            auto bound=socket_address(anchored);
#else
            auto bound=address;
#endif
            if (!bound) return std::unexpected("control socket filename is too long");
            std::array<std::uint8_t,16> random{};
            if (!fill_control_random(random))
                return std::unexpected("cannot create control instance ID");
            instance.reserve(32);
            for (auto byte:random) std::format_to(std::back_inserter(instance),"{:02x}",byte);
            peers.reserve(32);
#if defined(__linux__)
            listener=ControlFd(::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0));
#else
            listener=ControlFd(::socket(AF_UNIX,SOCK_STREAM,0));
            if (listener) {
                int fl=::fcntl(listener.get(),F_GETFL,0);
                if (fl>=0) (void)::fcntl(listener.get(),F_SETFL,fl|O_NONBLOCK);
                (void)::fcntl(listener.get(),F_SETFD,FD_CLOEXEC);
            }
#endif
            if (!listener) return std::unexpected(system_error("control socket"));
            if (::bind(listener.get(),reinterpret_cast<sockaddr const*>(&*bound),socket_size(*bound))<0)
                return std::unexpected(system_error("bind control socket"));
            struct stat info{};
            if (::fstatat(directory.get(),entry.c_str(),&info,AT_SYMLINK_NOFOLLOW)<0 || !S_ISSOCK(info.st_mode))
                return std::unexpected(system_error("inspect control socket"));
            device=info.st_dev;
            inode=info.st_ino;
            if (::fchmodat(directory.get(),entry.c_str(),reader ? 0666 : 0600,0)<0 ||
                ::listen(listener.get(),32)<0) return std::unexpected(system_error("publish control socket"));
            return {};
        }

        auto poll(ControlHandler handler) -> void {
            auto now=Clock::now();
            for (unsigned attempt=0;attempt<32 && peers.size()<32;++attempt) {
#if defined(__linux__)
                ControlFd socket(::accept4(listener.get(),nullptr,nullptr,SOCK_NONBLOCK|SOCK_CLOEXEC));
#else
                ControlFd socket(::accept(listener.get(),nullptr,nullptr));
                if (socket) {
                    int fl=::fcntl(socket.get(),F_GETFL,0);
                    if (fl>=0) (void)::fcntl(socket.get(),F_SETFL,fl|O_NONBLOCK);
                    (void)::fcntl(socket.get(),F_SETFD,FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
                    int one=1;
                    (void)::setsockopt(socket.get(),SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
                }
#endif
                if (!socket) break;
                auto uid=peer_uid(socket.get());
                if (!uid || (*uid!=::geteuid() && uid!=reader)) {
                    ++diagnostics.unauthorized;
                    continue;
                }
                ++diagnostics.authorized;
                auto role=*uid==::geteuid() ? ControlRole::administrator : ControlRole::reader;
                peers.push_back(Peer{std::move(socket),now+std::chrono::seconds(2),role});
            }
            std::array<char,max_request> buffer;
            std::erase_if(peers,[&](Peer& peer) {
                if (now>=peer.expiry) {
                    ++diagnostics.expired;
                    return true;
                }
                auto build_response=[&](std::string_view req,bool oversized) -> std::string {
                    try {
                        auto parsed=oversized ?
                            std::expected<std::string,std::string>(std::unexpected("request-too-large")) :
                            dispatch(req,peer.role,handler);
                        auto response=parsed ? std::format("{} OK\n{}",version,*parsed) :
                            std::format("{} ERROR\n{}\n",version,parsed.error());
                        return response.size()>max_reply ? std::string("NEXUS/1 ERROR\nreply-too-large\n") : response;
                    } catch (std::bad_alloc const&) {
                        return "NEXUS/1 ERROR\nresource-exhausted\n";
                    } catch (std::system_error const&) {
                        return "NEXUS/1 ERROR\noperation-failed\n";
                    }
                };
#if defined(__linux__)
                auto size=::recv(peer.fd.get(),buffer.data(),buffer.size(),MSG_TRUNC);
                if (size<0 && (errno==EAGAIN || errno==EINTR)) return false;
                if (size<=0) return true;
                auto response=build_response(
                    std::string_view(buffer.data(),std::min(static_cast<std::size_t>(size),buffer.size())),
                    static_cast<std::size_t>(size)>buffer.size());
                if (::send(peer.fd.get(),response.data(),response.size(),MSG_NOSIGNAL)!=
                    static_cast<ssize_t>(response.size())) ++diagnostics.reply_failed;
                return true;
#else
                if (!peer.writing) {
                    for (;;) {
                        auto n=::recv(peer.fd.get(),buffer.data(),buffer.size(),0);
                        if (n<0) {
                            if (errno==EINTR) continue;
                            if (errno==EAGAIN || errno==EWOULDBLOCK) return false;
                            return true;
                        }
                        if (n==0) {
                            if (peer.in.empty()) return true;
                            peer.out=build_response(peer.in,peer.in.size()>max_request);
                            peer.writing=true;
                            break;
                        }
                        auto take=std::min<std::size_t>(static_cast<std::size_t>(n),(max_request+1)-peer.in.size());
                        peer.in.append(buffer.data(),take);
                        if (peer.in.size()>max_request) {
                            peer.out=build_response({},true);
                            peer.writing=true;
                            break;
                        }
                    }
                }
#ifdef MSG_NOSIGNAL
                constexpr int kFlags=MSG_NOSIGNAL;
#else
                constexpr int kFlags=0;
#endif
                while (peer.out_offset<peer.out.size()) {
                    auto w=::send(peer.fd.get(),peer.out.data()+peer.out_offset,peer.out.size()-peer.out_offset,kFlags);
                    if (w>0) { peer.out_offset+=static_cast<std::size_t>(w); continue; }
                    if (w<0 && errno==EINTR) continue;
                    if (w<0 && (errno==EAGAIN || errno==EWOULDBLOCK)) return false;
                    ++diagnostics.reply_failed;
                    return true;
                }
                return true;
#endif
            });
        }
    };

    LocalControl::LocalControl() noexcept = default;
    LocalControl::~LocalControl() = default;
    auto LocalControl::start(std::string_view path,std::optional<std::uint32_t> reader) -> std::expected<void,std::string> {
        if (impl_) return std::unexpected("control socket already started");
        auto candidate=std::make_unique<Impl>();
        auto started=candidate->start(path,reader);
        if (!started) return started;
        impl_=std::move(candidate);
        return {};
    }
    auto LocalControl::poll(ControlHandler handler) -> void { if (impl_) impl_->poll(handler); }
    auto LocalControl::stop() noexcept -> void { impl_.reset(); }
    auto LocalControl::active() const noexcept -> bool { return bool(impl_); }
    auto LocalControl::listen_native_fd() const noexcept -> int {
        return impl_ && impl_->listener ? impl_->listener.get() : -1;
    }
    auto LocalControl::next_poll_delay() const noexcept -> std::optional<std::chrono::milliseconds> {
        return (impl_ && !impl_->peers.empty()) ? std::optional(std::chrono::milliseconds(5)) : std::nullopt;
    }
    auto LocalControl::instance() const noexcept -> std::string_view {
        return impl_ ? std::string_view(impl_->instance) : std::string_view{};
    }
    auto LocalControl::diagnostics() const noexcept -> ControlDiagnostics {
        return impl_ ? impl_->diagnostics : ControlDiagnostics{};
    }

    namespace {
        auto send_control_once(sockaddr_un const& address,uid_t owner,std::span<std::string const> tokens)
            -> std::expected<std::string,std::pair<int,std::string>> {
            std::string request(version);
            for (std::size_t i=0;i<tokens.size();++i) {
                auto const& argument=tokens[i];
                if (argument.empty() || request.size()+argument.size()+1>max_request)
                    return std::unexpected(std::pair{2,std::string("invalid control argument")});
                request+=i==0 ? ' ' : '\0';
                request+=argument;
            }
#if defined(__linux__)
            ControlFd socket(::socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0));
            constexpr int kSendFlags=MSG_NOSIGNAL;
#else
            ControlFd socket(::socket(AF_UNIX,SOCK_STREAM,0));
            if (socket) {
                (void)::fcntl(socket.get(),F_SETFD,FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
                int one=1;
                (void)::setsockopt(socket.get(),SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
#endif
            }
            constexpr int kSendFlags=0;
#endif
            timeval timeout{3,0};
            if (!socket || ::setsockopt(socket.get(),SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0 ||
                ::setsockopt(socket.get(),SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout))<0 ||
                ::connect(socket.get(),reinterpret_cast<sockaddr const*>(&address),socket_size(address))<0)
                return std::unexpected(std::pair{1,system_error("connect control socket")});
            if (peer_uid(socket.get())!=owner)
                return std::unexpected(std::pair{1,std::string("unexpected control server UID")});
#if defined(__linux__)
            if (::send(socket.get(),request.data(),request.size(),kSendFlags)!=static_cast<ssize_t>(request.size()))
                return std::unexpected(std::pair{1,system_error("send control request")});
            std::array<char,max_reply> bytes;
            auto received=::recv(socket.get(),bytes.data(),bytes.size(),MSG_TRUNC);
            if (received<=0 || static_cast<std::size_t>(received)>bytes.size())
                return std::unexpected(std::pair{1,std::string("missing or oversized control reply")});
            std::string_view wire(bytes.data(),static_cast<std::size_t>(received));
#else
            std::size_t sent_total=0;
            while (sent_total<request.size()) {
                auto w=::send(socket.get(),request.data()+sent_total,request.size()-sent_total,kSendFlags);
                if (w<0) {
                    if (errno==EINTR) continue;
                    return std::unexpected(std::pair{1,system_error("send control request")});
                }
                if (w==0) return std::unexpected(std::pair{1,std::string("send control request: short write")});
                sent_total+=static_cast<std::size_t>(w);
            }
            (void)::shutdown(socket.get(),SHUT_WR);
            std::string reply;
            std::array<char,4096> chunk;
            for (;;) {
                auto r=::recv(socket.get(),chunk.data(),chunk.size(),0);
                if (r<0) {
                    if (errno==EINTR) continue;
                    return std::unexpected(std::pair{1,std::string("missing or oversized control reply")});
                }
                if (r==0) break;
                if (static_cast<std::size_t>(r)>max_reply-reply.size())
                    return std::unexpected(std::pair{1,std::string("missing or oversized control reply")});
                reply.append(chunk.data(),static_cast<std::size_t>(r));
            }
            if (reply.empty())
                return std::unexpected(std::pair{1,std::string("missing or oversized control reply")});
            std::string_view wire(reply);
#endif
            if (wire.starts_with("NEXUS/1 OK\n")) return std::string(wire.substr(11));
            if (wire.starts_with("NEXUS/1 ERROR\n")) return std::unexpected(std::pair{1,std::string(wire.substr(14))});
            return std::unexpected(std::pair{1,std::string("unsupported control reply")});
        }
    }

    auto run_control(int argc,char** argv) -> int {
        if (argc<3 || (argc==2 && std::string_view(argv[1])=="--help")) {
            std::cerr << "usage: nexus control <socket> [--server-uid UID] status|mode|connections|connection show <id>|close|close-any|close-all|select|probe|group-health|user-usage|reload|clear-cache|network-change|operation|events|diagnostics|log-level|logs [arguments]\n";
            return argc==2 && std::string_view(argv[1])=="--help" ? 0 : 2;
        }
        auto address=socket_address(argv[1]);
        if (!address) {std::cerr << "invalid control socket path\n";return 2;}
        auto owner=::geteuid();
        int first=2;
        if (std::string_view(argv[2])=="--server-uid") {
            if (argc<5) {std::cerr << "expected --server-uid UID followed by a command\n";return 2;}
            auto uid=std::string_view(argv[3]);
            auto [end,error]=std::from_chars(uid.data(),uid.data()+uid.size(),owner);
            if (error!=std::errc{} || end!=uid.data()+uid.size() || owner==static_cast<uid_t>(-1)) {
                std::cerr << "invalid control server UID\n";return 2;
            }
            first=4;
        }
        auto cmd=std::string_view(argv[first]);
        if (cmd=="connection" && first+2<argc && std::string_view(argv[first+1])=="show" && first+3==argc) {
            std::array<std::string,2> tokens{"connection",argv[first+2]};
            auto res=send_control_once(*address,owner,tokens);
            if (!res) { std::cerr << res.error().second << (res.error().second.ends_with('\n') ? "" : "\n"); return res.error().first; }
            std::cout << *res;
            return 0;
        }
        if (cmd=="logs") {
            bool follow=false;
            std::string since="0";
            std::vector<std::string> filters;
            for (int i=first+1;i<argc;++i) {
                auto arg=std::string_view(argv[i]);
                if (arg=="-f" || arg=="--follow") { follow=true; continue; }
                auto next_val=[&](std::string_view flag) -> std::optional<std::string_view> {
                    if (arg==flag && i+1<argc) return std::string_view(argv[++i]);
                    if (arg.starts_with(std::string(flag)+"=")) return arg.substr(flag.size()+1);
                    return std::nullopt;
                };
                if (auto v=next_val("--level")) filters.push_back("level="+std::string(*v));
                else if (auto v=next_val("--domain")) filters.push_back("domain="+std::string(*v));
                else if (auto v=next_val("--search")) filters.push_back("search="+std::string(*v));
                else if (auto v=next_val("--limit")) filters.push_back("limit="+std::string(*v));
                else if (auto v=next_val("--since")) since=std::string(*v);
                else filters.push_back(std::string(arg));
            }
            for (;;) {
                std::vector<std::string> tokens{"logs","since="+since};
                tokens.insert(tokens.end(),filters.begin(),filters.end());
                auto res=send_control_once(*address,owner,tokens);
                if (!res) { std::cerr << res.error().second << (res.error().second.ends_with('\n') ? "" : "\n"); return res.error().first; }
                auto nl=res->find('\n');
                auto head=nl==std::string::npos ? std::string_view(*res) : std::string_view(*res).substr(0,nl);
                auto body=nl==std::string::npos ? std::string_view{} : std::string_view(*res).substr(nl+1);
                if (head.starts_with("latest=")) {
                    auto sp=head.find(' ');
                    since=std::string(head.substr(7,sp==std::string_view::npos ? std::string_view::npos : sp-7));
                }
                if (!follow) { std::cout << *res; return 0; }
                if (!body.empty()) { std::cout << body << std::flush; }
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
            }
        }
        std::vector<std::string> tokens;
        for (int i=first;i<argc;++i) tokens.emplace_back(argv[i]);
        auto res=send_control_once(*address,owner,tokens);
        if (!res) { std::cerr << res.error().second << (res.error().second.ends_with('\n') ? "" : "\n"); return res.error().first; }
        std::cout << *res;
        return 0;
    }
}
