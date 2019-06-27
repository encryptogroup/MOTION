#pragma once

#include <condition_variable>
#include <functional>

namespace ENCRYPTO {

class Condition {
 public:
  Condition(std::function<bool()> f) : condition_function_(f) {}

  ~Condition() = default;
  Condition() = delete;
  Condition(Condition &) = delete;

  bool operator()() { return condition_function_(); }

  bool Wait();

  template <typename Tick, typename Period>
  bool WaitFor(std::chrono::duration<Tick, Period> duration) {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_variable_.wait_for(lock, duration, [this] { return condition_function_(); });
    return condition_function_();
  }

  void NotifyOne() noexcept { condition_variable_.notify_one(); }

  void NotifyAll() noexcept { condition_variable_.notify_all(); }

  // the variables that the condition function depends on shall only be modified under the locked
  // mutex
  std::mutex &GetMutex() noexcept { return mutex_; }

 private:
  std::condition_variable condition_variable_;
  std::mutex mutex_;
  std::function<bool()> condition_function_;
};

}