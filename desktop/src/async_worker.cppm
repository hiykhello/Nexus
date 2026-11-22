export module desktop.async_worker;

import std;

export namespace desktop {
    // Serialized background worker offloading blocking IPC and child-process
    // operations away from the Slint UI event loop thread.
    class AsyncWorker {
        std::mutex mutex_;
        std::condition_variable_any cv_;
        std::deque<std::move_only_function<void()>> queue_;
        bool stopping_ = false;
        std::jthread thread_;

        auto run(this AsyncWorker& self, std::stop_token st) -> void;
    public:
        AsyncWorker();
        ~AsyncWorker();
        AsyncWorker(AsyncWorker const&) = delete;
        auto operator=(AsyncWorker const&) -> AsyncWorker& = delete;

        auto post(this AsyncWorker& self, std::move_only_function<void()> task) -> bool;
        auto stop(this AsyncWorker& self) -> void;
    };
}
