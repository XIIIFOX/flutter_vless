#pragma once
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>

// Owned worker: plugin destruction joins its active operation before releasing
// callbacks or status state. No detached task can retain a dangling `this`.
class NativeTaskQueue {
 public:
  NativeTaskQueue() : worker_([this] {
    for (;;) {
      std::function<void()> operation;
      {
        std::unique_lock<std::mutex> lock(mutex_);
        changed_.wait(lock, [this] { return stopping_ || !pending_.empty(); });
        if (stopping_) return;
        operation = std::move(pending_.front()); pending_.pop_front();
      }
      operation();
    }
  }) {}
  ~NativeTaskQueue() { Stop(); }
  void Submit(std::function<void()> operation) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!stopping_) { pending_.push_back(std::move(operation)); changed_.notify_one(); }
  }
  void Stop() {
    { std::lock_guard<std::mutex> lock(mutex_); stopping_ = true; pending_.clear(); }
    changed_.notify_all();
    if (worker_.joinable()) worker_.join();
  }
 private:
  std::mutex mutex_;
  std::condition_variable changed_;
  std::deque<std::function<void()>> pending_;
  bool stopping_ = false;
  std::thread worker_;
};
