// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#ifndef LOCKED_FIBER_QUEUE_HPP
#define LOCKED_FIBER_QUEUE_HPP

#include <boost/fiber/condition_variable.hpp>
#include <boost/fiber/mutex.hpp>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>

namespace encrypto::motion {

/**
 * Closable queue for elements of type T synchronized with fiber primitives.
 */
template <typename T>
class LockedFiberQueue {
 public:
  /**
   * Checks if queue is empty.
   */
  bool empty() const noexcept {
    std::lock_guard lock(mutex_);
    return queue_.empty();
  }

  /**
   * Checks if queue is closed.
   */
  bool IsClosed() const noexcept {
    std::lock_guard lock(mutex_);
    return closed_;
  }

  /**
   * Close the queue.
   */
  void close() noexcept {
    {
      std::scoped_lock lock(mutex_);
      closed_ = true;
    }
    condition_variable_.notify_all();
  }

  /**
   * Adds a new element to the queue.
   */
  void enqueue(const T& item) {
    if (closed_) {
      throw std::logic_error("Tried to enqueue in closed LockedFiberQueue");
    }
    {
      std::scoped_lock lock(mutex_);
      queue_.push(item);
    }
    condition_variable_.notify_one();
  }

  void enqueue(T&& item) {
    if (closed_) {
      throw std::logic_error("Tried to enqueue in closed LockedFiberQueue");
    }
    {
      std::scoped_lock lock(mutex_);
      queue_.push(std::move(item));
    }
    condition_variable_.notify_one();
  }

  /**
   * Receives an element from the queue.
   */
  std::optional<T> dequeue() noexcept {
    std::unique_lock lock(mutex_);
    if (queue_.empty() && closed_) {
      return std::nullopt;
    }
    if (queue_.empty() && !closed_) {
      condition_variable_.wait(lock, [this] { return !this->queue_.empty() || this->closed_; });
    }
    if (queue_.empty()) {
      return std::nullopt;
    }
    auto item = std::move(queue_.front());
    queue_.pop();
    lock.unlock();
    return std::optional<T>(std::move(item));
  }

 private:
  bool closed_ = false;
  std::queue<T> queue_;
  mutable boost::fibers::mutex mutex_;
  boost::fibers::condition_variable_any condition_variable_;
};

}  // namespace encrypto::motion

#endif  // LOCKED_QUEUE_HPP
