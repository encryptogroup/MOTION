// MIT License
//
// Copyright (c) 2019 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#ifndef LOCKED_QUEUE_HPP
#define LOCKED_QUEUE_HPP

#include <condition_variable>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>

namespace encrypto::motion {

/**
 * Locked queue for elements of type T
 */
template <typename T>
class LockedQueue {
 public:
  /**
   * Checks if queue is empty.
   */
  bool empty() const {
    std::lock_guard<std::timed_mutex> lock(mutex_);
    return queue_.empty();
  }

  /**
   * Adds a new element to the queue.
   */
  void enqueue(const T& item) {
    {
      std::scoped_lock<std::timed_mutex> lock(mutex_);
      queue_.push(item);
    }
    condition_variable_.notify_one();
  }

  void enqueue(T&& item) {
    {
      std::scoped_lock<std::timed_mutex> lock(mutex_);
      queue_.push(item);
    }
    condition_variable_.notify_one();
  }

  /**
   * Receives an element from the queue.
   */
  T dequeue() {
    std::unique_lock<std::timed_mutex> lock(mutex_);
    if (queue_.empty()) {
      condition_variable_.wait(lock, [this] { return !this->queue_.empty(); });
    }
    auto item = queue_.front();
    queue_.pop();
    lock.unlock();
    return item;
  }

  /**
   * Receives an element from the queue with timeout.
   */
  template <typename Tick, typename Period>
  std::optional<T> dequeue(const std::chrono::duration<Tick, Period>& duration) {
    std::unique_lock<std::timed_mutex> lock(mutex_, duration);
    if (!lock) {
      return std::optional<T>(std::nullopt);
    }
    // lock is aquired
    if (!queue_.empty()) {
      auto item = queue_.front();
      queue_.pop();
      lock.unlock();
      return std::optional(item);
    }
    // queue is currently empty
    if (!condition_variable_.wait_for(lock, duration, [this] { return !this->queue_.empty(); })) {
      lock.unlock();
      return std::optional<T>(std::nullopt);
    }
    // queue contains an item
    auto item = queue_.front();
    queue_.pop();
    lock.unlock();
    return std::optional(item);
  }

  /**
   * Extract all elements of the queue.
   */
  template <typename Tick, typename Period>
  std::queue<T> BatchDeque(const std::chrono::duration<Tick, Period>& duration) {
    std::queue<T> output;
    std::unique_lock<std::timed_mutex> lock(mutex_, duration);

    // we got the lock in time
    if (lock) {
      // let's wait for new entries
      if (queue_.empty()) {
        // there are some entries now
        if (condition_variable_.wait_for(lock, duration,
                                         [this] { return !this->queue_.empty(); })) {
          std::swap(queue_, output);
        }
      }
      // queue is not empty
      else {
        std::swap(queue_, output);
      }
      lock.unlock();
    }
    return output;
  }

 private:
  std::queue<T> queue_;
  mutable std::timed_mutex mutex_;
  std::condition_variable_any condition_variable_;
};

}  // namespace encrypto::motion

#endif  // LOCKED_QUEUE_HPP
