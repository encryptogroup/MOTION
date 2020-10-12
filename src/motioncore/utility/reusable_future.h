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

// This file contains promise/future-like data structures with the difference
// that they can be reused:  After the value stored in the future was
// retrieved, a new value can be set using the same promise.
//
// We cannot throw away our future(s) all the time, we need to recycle them.

#pragma once

#include <boost/fiber/future.hpp>
#include <condition_variable>
#include <future>
#include <mutex>
#include <type_traits>

namespace encrypto::motion {

namespace detail {

// shared state to be used by ReusableFuture and ReusablePromise
template <typename R, typename MutexType, typename ConditionVariableType>
class ReusableSharedState {
 public:
  ReusableSharedState() : contains_value_(false) {}
  ~ReusableSharedState() {
    if (contains_value_) {
      // delete the object
      delete_helper();
    }
  }

  // set value
  template <typename Argument>
  void set(Argument&& argument) {
    {
      std::scoped_lock lock(mutex_);
      if (contains_value_) {
        throw std::future_error(std::future_errc::promise_already_satisfied);
      }
      // construct R from argument in the pre-allocated value_storage
      new (&value_storage_) R(std::forward<Argument>(argument));
      contains_value_ = true;
    }
    condition_variable_.notify_all();
  }

  // remove value if present
  void reset() noexcept {
    std::unique_lock lock(mutex_);
    if (contains_value_) {
      // destroy object
      delete_helper();
      contains_value_ = false;
    }
  }

  // wait until there is a value
  void wait() const noexcept {
    std::unique_lock lock(mutex_);
    wait_helper(lock);
  }

  // move value out of the shared state
  R move() noexcept {
    std::unique_lock lock(mutex_);
    wait_helper(lock);
    contains_value_ = false;
    return std::move(*reinterpret_cast<R*>(&value_storage_));
  }

  // check if there is some value stored
  bool contains_value() const noexcept {
    std::scoped_lock lock(mutex_);
    return contains_value_;
  }

 private:
  // storage for the value
  std::aligned_storage_t<sizeof(R), std::alignment_of_v<R>> value_storage_;

  // status: true -> there is a value in the shared state
  bool contains_value_;

  // synchronization stuff
  mutable MutexType mutex_;
  mutable ConditionVariableType condition_variable_;

  // helper functions
  void wait_helper(std::unique_lock<decltype(mutex_)>& lock) const noexcept {
    if (!contains_value_) {
      condition_variable_.wait(lock, [this] { return contains_value_; });
    }
  }

  // delete the stored object
  void delete_helper() noexcept { reinterpret_cast<R*>(&value_storage_)->~R(); }
};

}  // namespace detail

template <typename R, typename MutexType, typename ConditionVariableType>
class ReusablePromise;

// std::future-like future whose value can be set and read repeatedly,
// basically the consumer end of a channel with a capacity of one
template <typename R, typename MutexType = std::mutex,
          typename ConditionVariableType = std::condition_variable>
class ReusableFuture {
 public:
  // create future without associated state
  ReusableFuture() noexcept : shared_state_(nullptr) {}

  // cannot copy construct future
  ReusableFuture(const ReusableFuture&) = delete;

  // move constructor
  ReusableFuture(ReusableFuture&& other) noexcept : shared_state_(std::move(other.shared_state_)) {
    other.shared_state_ = nullptr;
  }

  ~ReusableFuture() = default;

  // cannot copy-assign
  ReusableFuture& operator=(const ReusableFuture&) = delete;

  // move-assign
  ReusableFuture& operator=(ReusableFuture&& other) noexcept {
    shared_state_ = std::move(other.shared_state_);
    other.shared_state_ = nullptr;
    return *this;
  }

  // retrieve the stored value
  R get() {
    if (!shared_state_) {
      throw std::future_error(std::future_errc::no_state);
    }
    return shared_state_->move();
  }

  // swap two futures
  void swap(ReusableFuture& other) noexcept { std::swap(shared_state_, other.shared_state_); };

  // check if the future has an associated state
  bool valid() const noexcept { return shared_state_ != nullptr; }

  // wait until the future gets ready
  void wait() const { shared_state_->wait(); }

  // TODO: wait_for, wait_until

 private:
  // allow ReusablePromise to use the following constructor
  friend ReusablePromise<R, MutexType, ConditionVariableType>;

  // create future with associated state
  ReusableFuture(std::shared_ptr<detail::ReusableSharedState<R, MutexType, ConditionVariableType>>
                     shared_state) noexcept
      : shared_state_(std::move(shared_state)) {}

  // pointer to the shared state
  std::shared_ptr<detail::ReusableSharedState<R, MutexType, ConditionVariableType>> shared_state_;
};

template <typename R>
using ReusableFiberFuture =
    ReusableFuture<R, boost::fibers::mutex, boost::fibers::condition_variable>;

// std::promise-like promise which can be used repeatedly to set thevalue in the corresponding
// shared state, basically the produceer end of a channel with a capacity of one
template <typename R, typename MutexType = std::mutex,
          typename ConditionVariableType = std::condition_variable>
class ReusablePromise {
 public:
  ReusablePromise() noexcept
      : shared_state_(
            std::make_shared<detail::ReusableSharedState<R, MutexType, ConditionVariableType>>()),
        future_retrieved_(false) {}

  // no copy constructor
  ReusablePromise(const ReusablePromise&) = delete;

  // move constructor
  ReusablePromise(ReusablePromise&& other) noexcept
      : shared_state_(other.shared_state_), future_retrieved_(other.future_retrieved_) {
    other.shared_state_ = nullptr;
    other.future_retrieved_ = false;
  }

  ~ReusablePromise() = default;

  // no copy assign
  ReusablePromise& operator=(const ReusablePromise&) = delete;

  // move assign
  ReusablePromise& operator=(ReusablePromise&& other) noexcept {
    shared_state_ = other.shared_state_;
    future_retrieved_ = other.future_retrieved_;
    other.shared_state_ = nullptr;
    other.future_retrieved_ = false;
    return *this;
  }

  // set value of the shared state
  void set_value(const R& value) {
    if (!shared_state_) {
      throw std::future_error(std::future_errc::no_state);
    }
    shared_state_->set(value);
  }

  // set value of the shared state
  void set_value(R&& value) {
    if (!shared_state_) {
      throw std::future_error(std::future_errc::no_state);
    }
    shared_state_->set(std::move(value));
  }

  // returns future associated with the shared state of the promise
  ReusableFuture<R, MutexType, ConditionVariableType> get_future() {
    if (!shared_state_) {
      throw std::future_error(std::future_errc::no_state);
    }
    if (future_retrieved_) {
      throw std::future_error(std::future_errc::future_already_retrieved);
    }
    future_retrieved_ = true;
    return ReusableFuture(shared_state_);
  }

  // swaps this future with another
  void swap(ReusablePromise& other) noexcept {
    std::swap(shared_state_, other.shared_state_);
    std::swap(future_retrieved_, other.future_retrieved_);
  }

 private:
  std::shared_ptr<detail::ReusableSharedState<R, MutexType, ConditionVariableType>> shared_state_;
  bool future_retrieved_ = false;
};

template <typename R>
using ReusableFiberPromise =
    ReusablePromise<R, boost::fibers::mutex, boost::fibers::condition_variable>;

// make ReusablePromise swappable
template <typename R, typename MutexType, typename ConditionVariableType>
void swap(ReusablePromise<R, MutexType, ConditionVariableType>& lhs,
          ReusablePromise<R, MutexType, ConditionVariableType>& rhs) noexcept {
  lhs.swap(rhs);
}

}  // namespace encrypto::motion
