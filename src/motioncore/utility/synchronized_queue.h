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

#pragma once

#include <boost/fiber/condition_variable.hpp>
#include <boost/fiber/mutex.hpp>

// Undefine Windows macros that collide with function names in MOTION.
#ifdef SendMessage
#undef SendMessage
#endif

#ifdef GetMessage
#undef GetMessage
#endif

#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>

namespace encrypto::motion {

/**
 * Synchronized, closable queue for elements of type T.
 *
 * The template is based on std::queue and provides synchronized operations
 * such that items can be enqueued/dequeued by different threads.  The queue
 * can be customized with different synchronization primitives, e.g.,
 * std::mutex and fibers::mutex, via template parameters.  Elements can be
 * dequeued one-by-one (dequeue) or all at once (batch_dequeue).  The queue can
 * be closed which signals consumers that no further elements will be inserted.
 * Dequeue operations return std::nullopt if the queue is closed and empty.
 */
template <typename T, typename MutexType, typename ConditionVariableType>
class BasicSynchronizedQueue {
 public:
  BasicSynchronizedQueue() = default;
  BasicSynchronizedQueue(BasicSynchronizedQueue&& other) = default;

  /**
   * Check if queue is empty.
   */
  bool empty() const noexcept {
    std::scoped_lock lock(mutex_);
    return queue_.empty();
  }

  /**
   * Check if queue is closed.
   */
  bool IsClosed() const noexcept {
    std::scoped_lock lock(mutex_);
    return closed_;
  }

  /**
   * Check if queue is closed and empty.
   */
  bool IsClosedAndEmpty() const noexcept {
    std::scoped_lock lock(mutex_);
    return closed_ && queue_.empty();
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
   * Add a new element to the queue.
   */
  void enqueue(const T& item) {
    if (closed_) {
      throw std::logic_error("Tried to enqueue in closed BasicSynchronizedQueue");
    }
    {
      std::scoped_lock lock(mutex_);
      queue_.push(item);
    }
    condition_variable_.notify_one();
  }

  void enqueue(T&& item) {
    if (closed_) {
      throw std::logic_error("Tried to enqueue in closed BasicSynchronizedQueue");
    }
    {
      std::scoped_lock lock(mutex_);
      queue_.push(std::move(item));
    }
    condition_variable_.notify_one();
  }

  /**
   * Extract an element from the queue.
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
      assert(closed_);
      return std::nullopt;
    }
    auto item = std::move(queue_.front());
    queue_.pop();
    lock.unlock();
    return std::optional<T>(std::move(item));
  }

  /**
   * Extract all elements of the queue.
   */
  std::optional<std::queue<T>> BatchDequeue() noexcept {
    std::queue<T> output;
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
    std::swap(queue_, output);
    lock.unlock();
    return std::optional<std::queue<T>>(std::move(output));
  }

 private:
  bool closed_ = false;
  std::queue<T> queue_;
  mutable MutexType mutex_;
  ConditionVariableType condition_variable_;
};

template <typename T>
using SynchronizedQueue = BasicSynchronizedQueue<T, std::mutex, std::condition_variable>;

template <typename T>
using SynchronizedFiberQueue =
    BasicSynchronizedQueue<T, boost::fibers::mutex, boost::fibers::condition_variable>;

}  // namespace encrypto::motion
