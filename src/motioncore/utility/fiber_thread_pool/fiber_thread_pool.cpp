// Copyright 2019 Lennart Braun
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include <algorithm>
#include <fmt/format.h>
#include <boost/fiber/buffered_channel.hpp>
#include <boost/fiber/channel_op_status.hpp>
#include <boost/fiber/operations.hpp>
#include <cassert>
#include <iostream>
#include <thread>
#include "fiber_thread_pool.hpp"
#include "pooled_work_stealing.hpp"
#include "utility/constants.h"
#include "utility/thread.h"

namespace ENCRYPTO {

FiberThreadPool::FiberThreadPool(std::size_t num_workers, std::size_t num_tasks, bool suspend_scheduler)
    : num_workers_(num_workers),
      running_(false),
      suspend_scheduler_(suspend_scheduler),
      task_queue_(std::make_unique<boost::fibers::buffered_channel<task_t>>(64)) {
  if (num_workers_ == 1) {
    throw std::invalid_argument("FiberThreadPool needs at least two worker threads");
  }
  if (num_workers_ == 0) {
    num_workers_ = std::thread::hardware_concurrency();
  }

  // reserve storage to store the fiber objects
  fibers_ = std::vector<std::vector<boost::fibers::fiber>>(num_workers_);
  if (num_tasks > 0) {
    for (auto& v : fibers_) {
      v.reserve(num_tasks / num_workers_ + std::min(num_tasks, std::size_t(1000)));
    }
  }

  // create the worker threads
  create_threads();
}

FiberThreadPool::~FiberThreadPool() {
  if (running_) {
    join();
  }
}

// This function is executed in the worker thread
static void worker_fctn(std::shared_ptr<pool_ctx> pool_ctx,
                        boost::fibers::buffered_channel<FiberThreadPool::task_t>& task_queue,
                        std::vector<boost::fibers::fiber>& fibers) {
  // register this thread with the pool
  boost::fibers::use_scheduling_algorithm<pooled_work_stealing>(pool_ctx);

  FiberThreadPool::task_t task;

  // try to get new tasks from the queue until the channel is closed and empty,
  // which is the signal to therminate the pool
  while (task_queue.pop(task) != boost::fibers::channel_op_status::closed) {
    // create a fiber from the task we retrieved and store its handle
    fibers.emplace_back(task);

    // give another fiber the chance to run
    boost::this_fiber::yield();
  }
}

void FiberThreadPool::create_threads() {
  assert(worker_threads_.empty());

  // create a pool context which is used to coordinate the worker threads'
  // schedulers
  pool_ctx_ = pooled_work_stealing::create_pool_ctx(num_workers_, suspend_scheduler_);

  // create the worker threads
  worker_threads_.reserve(num_workers_);
  for (std::size_t i = 0; i < num_workers_; ++i) {
    auto& t = worker_threads_.emplace_back(worker_fctn, pool_ctx_, std::ref(*task_queue_),
                                           std::ref(fibers_.at(i)));

    if constexpr (MOTION::MOTION_DEBUG) {
      thread_set_name(t, fmt::format("pool-worker-{}", i));
    }
  }
  running_ = true;
}

void FiberThreadPool::join() {
  join_fibers();
  task_queue_->close();
  std::for_each(worker_threads_.begin(), worker_threads_.end(), [](auto& t) { t.join(); });
  running_ = false;
}

void FiberThreadPool::join_fibers() {
  for (auto& v : fibers_) {
    for (auto& fiber : v) {
      fiber.join();
    }
    v.clear();
  }
}

void FiberThreadPool::post(std::function<void()> fctn) {
  assert(running_);
  task_queue_->push(fctn);
}

}  // namespace ENCRYPTO
