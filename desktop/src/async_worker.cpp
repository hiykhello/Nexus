module desktop.async_worker;

import std;

namespace desktop {
    AsyncWorker::AsyncWorker()
        : thread_([this](std::stop_token st) { run(st); }) {}

    AsyncWorker::~AsyncWorker() { stop(); }

    auto AsyncWorker::post(this AsyncWorker& self, std::move_only_function<void()> task) -> bool {
        if (!task) return false;
        {
            std::scoped_lock lock(self.mutex_);
            if (self.stopping_) return false;
            self.queue_.push_back(std::move(task));
        }
        self.cv_.notify_one();
        return true;
    }

    auto AsyncWorker::stop(this AsyncWorker& self) -> void {
        {
            std::scoped_lock lock(self.mutex_);
            if (self.stopping_) return;
            self.stopping_ = true;
        }
        self.cv_.notify_all();
        if (self.thread_.joinable()) {
            self.thread_.join();
        }
    }

    auto AsyncWorker::run(this AsyncWorker& self, std::stop_token st) -> void {
        for (;;) {
            std::move_only_function<void()> task;
            {
                std::unique_lock lock(self.mutex_);
                self.cv_.wait(lock, st, [&self] { return self.stopping_ || !self.queue_.empty(); });
                if (self.queue_.empty()) {
                    if (self.stopping_ || st.stop_requested()) return;
                    continue;
                }
                task = std::move(self.queue_.front());
                self.queue_.pop_front();
            }
            task();
        }
    }
}
