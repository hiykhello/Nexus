namespace {
    namespace fs = std::filesystem;

    auto slurp(fs::path const& path) -> std::string {
        std::ifstream file(path, std::ios::binary);
        check(static_cast<bool>(file), "read test file");
        return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
    }

    class Temporary {
        fs::path root_;
    public:
        Temporary() {
            char path[] = "/tmp/nexus-logging-unit.XXXXXX";
            auto directory = ::mkdtemp(path);
            check(directory != nullptr, "create temporary directory");
            root_ = directory;
        }
        ~Temporary() {
            std::error_code ignored;
            fs::remove_all(root_, ignored);
        }
        auto operator/(this Temporary const& self, std::string_view name) -> fs::path {
            return self.root_ / name;
        }
    };

    auto pipe_bytes(int fd, std::size_t size) -> std::string {
        std::string bytes(size, '\0');
        std::size_t offset = 0;
        while (offset < bytes.size()) {
            auto count = ::read(fd, bytes.data() + offset, bytes.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            check(count > 0, "read pipe payload");
            offset += static_cast<std::size_t>(count);
        }
        return bytes;
    }

    std::atomic<bool> signal_received{false};
    static_assert(std::atomic<bool>::is_always_lock_free);

    auto receive_signal(int) -> void {
        signal_received.store(true, std::memory_order_relaxed);
    }

    auto stderr_io(Temporary const& temporary) -> void {
        int pipe[2];
        check(::pipe2(pipe, O_CLOEXEC) == 0, "create pipe");
        auto capacity = ::fcntl(pipe[1], F_SETPIPE_SZ, 4096);
        check(capacity >= 4096, "set pipe capacity");
        check(::fcntl(pipe[1], F_SETFL, O_NONBLOCK) == 0, "set nonblocking pipe");
        auto sink = logging::stderr_sink(pipe[1]);
        check(sink.has_value(), "duplicate inherited pipe fd");
        check((::fcntl(pipe[1], F_GETFL) & O_NONBLOCK) != 0, "retain inherited flags");
        ::close(pipe[1]);

        std::string first(static_cast<std::size_t>(capacity) + 251, 'a');
        std::string second(static_cast<std::size_t>(capacity), 'b');
        std::array<std::string_view, 3> lines{first, "", second};
        struct sigaction interrupt{}, original{};
        interrupt.sa_handler = receive_signal;
        ::sigemptyset(&interrupt.sa_mask);
        check(::sigaction(SIGUSR1, &interrupt, &original) == 0, "install interrupt handler");
        std::promise<logging::SinkResult> result;
        auto written = result.get_future();
        std::jthread writer([&] { result.set_value(logging::write_batch(*sink, lines)); });
        pollfd reader{pipe[0], POLLIN, 0};
        check(::poll(&reader, 1, 2000) == 1, "observe first partial write");
        check(written.wait_for(0ms) == std::future_status::timeout, "pipe capacity forced short write");
        auto deadline = Clock::now() + 2s;
        while (!signal_received.load(std::memory_order_relaxed) && Clock::now() < deadline) {
            check(::pthread_kill(writer.native_handle(), SIGUSR1) == 0, "interrupt blocked writer");
            std::this_thread::sleep_for(1ms);
        }
        check(signal_received.load(std::memory_order_relaxed), "writer handled an interrupt");
        auto bytes = pipe_bytes(pipe[0], first.size() + second.size());
        writer.join();
        check(::sigaction(SIGUSR1, &original, nullptr) == 0, "restore interrupt handler");
        check(written.get().has_value() && bytes == first + second, "writev continuation keeps vector order");
        ::close(pipe[0]);

        struct sigaction before{}, after{};
        sigset_t mask_before{}, mask_after{};
        check(::sigaction(SIGPIPE, nullptr, &before) == 0, "read SIGPIPE disposition");
        check(::pthread_sigmask(SIG_SETMASK, nullptr, &mask_before) == 0, "read thread mask");
        auto broken = logging::write_batch(*sink, lines);
        check(!broken && broken.error() == std::errc::broken_pipe, "report EPIPE");
        check(::sigaction(SIGPIPE, nullptr, &after) == 0 && before.sa_handler == after.sa_handler &&
              before.sa_flags == after.sa_flags &&
              ::pthread_sigmask(SIG_SETMASK, nullptr, &mask_after) == 0 &&
              ::sigismember(&mask_before, SIGPIPE) == ::sigismember(&mask_after, SIGPIPE),
              "preserve process disposition and caller mask");

        sigset_t blocked{};
        ::sigemptyset(&blocked);
        ::sigaddset(&blocked, SIGPIPE);
        check(::pthread_sigmask(SIG_BLOCK, &blocked, nullptr) == 0, "block SIGPIPE in test thread");
        if (before.sa_handler != SIG_IGN) {
            check(::raise(SIGPIPE) == 0, "queue a caller SIGPIPE");
            broken = logging::write_batch(*sink, lines);
            sigset_t pending{};
            check(!broken && ::sigpending(&pending) == 0 && ::sigismember(&pending, SIGPIPE) == 1,
                  "retain caller's pending SIGPIPE");
            timespec now{};
            check(::sigtimedwait(&blocked, nullptr, &now) == SIGPIPE, "discard test signal");
        }
        check(::pthread_sigmask(SIG_SETMASK, &mask_before, nullptr) == 0, "restore test mask");

        auto logger = start(std::move(*sink), 1);
        auto producer = *logger->producer(0);
        check(producer.log(Domain::core, Level::error, 1, {}, "broken pipe") == Submit::accepted,
              "submit when stderr is broken");
        auto drained = logger->drain(Clock::now() + 2s);
        check(drained.completed && drained.diagnostics.undrained == 0 && drained.diagnostics.sink_errors == 1 &&
              !drained.diagnostics.last_success_ns, "background sink failure is observable");

        auto regular = temporary / "stderr-redirected";
        int fd = ::open(regular.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
        check(fd >= 0, "open redirected stderr");
        auto redirected = logging::stderr_sink(fd);
        ::close(fd);
        check(redirected && logging::write_batch(*redirected, lines) && slurp(regular) == first + second,
              "stderr redirected to a regular file");

        int terminal = ::posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
        check(terminal >= 0 && ::grantpt(terminal) == 0 && ::unlockpt(terminal) == 0, "create pseudo-terminal");
        auto slave_path = ::ptsname(terminal);
        check(slave_path != nullptr, "resolve pseudo-terminal slave");
        int slave = ::open(slave_path, O_WRONLY | O_NOCTTY | O_CLOEXEC);
        check(slave >= 0 && ::isatty(slave), "open pseudo-terminal slave");
        auto tty = logging::stderr_sink(slave);
        ::close(slave);
        constexpr std::array<std::string_view, 1> greeting{"message to tty"};
        check(tty && logging::write_batch(*tty, greeting) && pipe_bytes(terminal, greeting.front().size()) ==
              greeting.front(), "inherited terminal receives logs");
        ::close(terminal);
    }

    auto file_safety_and_rotation(Temporary const& temporary) -> void {
        auto path = temporary / "rotate.log";
        auto previous = ::umask(0777);
        auto sink = logging::file_sink({path, 8, 3});
        ::umask(previous);
        check(sink.has_value(), "open private file sink");
        struct stat attributes{};
        check(::stat(path.c_str(), &attributes) == 0 && (attributes.st_mode & 0777) == 0600,
              "secret log file mode is 0600 even with restrictive umask");

        std::array<std::string_view, 5> lines{"aaa\n", "bbb\n", "ccc\n", "dddddddd\n", "eee\n"};
        check(logging::write_batch(*sink, lines).has_value(), "rotate complete lines");
        check(slurp(path) == "eee\n" && slurp(temporary / "rotate.log.1") == "dddddddd\n" &&
              slurp(temporary / "rotate.log.2") == "ccc\n" && !fs::exists(temporary / "rotate.log.3"),
              "size boundary, oversized line, and retention limit");
        auto keep_one = logging::file_sink({temporary / "single", 4, 1});
        check(keep_one && logging::write_batch(*keep_one, std::span(lines).first(2)) &&
              slurp(temporary / "single") == "bbb\n" && !fs::exists(temporary / "single.1"),
              "one-file retention replaces active file");
        auto link = temporary / "symlink";
        fs::create_symlink(path, link);
        check(!logging::file_sink({link}), "refuse file symlink");
        auto indirect = temporary / "indirect";
        fs::create_directory(temporary / "subdirectory");
        fs::create_directory_symlink(path.parent_path(), indirect);
        check(!logging::file_sink({indirect / "subdirectory" / "log"}),
              "refuse intermediate directory symlink");
        auto fifo = temporary / "pipe";
        check(::mkfifo(fifo.c_str(), 0600) == 0 && !logging::file_sink({fifo}), "refuse FIFO without blocking");
        check(!logging::file_sink({path.parent_path()}), "refuse directory");
        check(::chmod(path.c_str(), 0640) == 0 && !logging::file_sink({path}), "refuse group-readable file");
        check(::chmod(path.c_str(), 0600) == 0, "restore file permissions");
        auto hardlink = temporary / "hardlink";
        fs::create_hard_link(path, hardlink);
        check(!logging::file_sink({hardlink}), "refuse a multiply linked file");
    }

    auto file_reopen(Temporary const& temporary) -> void {
        auto path = temporary / "reopen.log";
        auto original = temporary / "old-reopen.log";
        auto sink = logging::file_sink({path, 1, 2});
        check(sink.has_value(), "open file for reopen");
        auto logger = start(std::move(*sink), 1);
        auto producer = *logger->producer(0);
        check(producer.log(Domain::core, Level::info, 0, {}, "existing") == Submit::accepted &&
              logger->reopen(), "flush an already full file");
        fs::rename(path, original);
        fs::create_symlink(original, path);
        check(producer.log(Domain::core, Level::info, 1, {}, "before") == Submit::accepted,
              "submit before failed reopen");
        auto failed = logger->reopen();
        check(!failed && failed.error() == std::errc::too_many_symbolic_link_levels &&
              slurp(original).contains("before"), "reopen drains old fd and rejects symlink");
        check(producer.log(Domain::core, Level::warn, 2, {}, "still on old fd") == Submit::accepted,
              "submit after failed reopen");
        fs::remove(path);
        check(logger->reopen() && slurp(original).contains("still on old fd"), "reopen switched after draining prior fd");
        check(producer.log(Domain::core, Level::info, 3, {}, "on new fd") == Submit::accepted,
              "submit after successful reopen");
        auto drained = logger->drain(Clock::now() + 2s);
        check(drained.completed && drained.diagnostics.undrained == 0 && drained.diagnostics.sink_errors == 1 &&
              slurp(path).contains("on new fd") && !slurp(original).contains("on new fd"),
              "new file receives only post-reopen events");
    }
}
