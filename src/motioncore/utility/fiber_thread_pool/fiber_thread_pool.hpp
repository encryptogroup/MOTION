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

#ifndef FIBER_THREAD_POOL_HPP
#define FIBER_THREAD_POOL_HPP

#include <functional>
#include <memory>
#include <thread>
#include <vector>

namespace boost::fibers {

class barrier;
template <typename T>
class buffered_channel;

}  // namespace boost::fibers

struct pool_ctx;

namespace encrypto::motion {

class FiberThreadPool {
public:
    using task_t = std::function<void()>;

    // Create a thread pool with given number of workers
    // - number_of_workers
    //   if 0 then the value of std::thread::hardware_concurrency() is used
    //   else it must be at least 2
    // - number_of_tasks
    //   number of tasks that are to be expected
    // - suspend_scheduler
    //   suspend if there is no work to be done
    FiberThreadPool(std::size_t number_of_workers, std::size_t number_of_tasks = 0,
                    bool suspend_scheduler = true);

    // Destructor, calls join() if necessary
    ~FiberThreadPool();

    // Post a new task to the pool's queue.
    // This may block if the task queue is currently full
    void post(task_t task);

    // Close the pool.  No new tasks can be posted to the pool.
    // Note: Be sure that all previously posted tasks has been completed before
    // you call this method.
    void join();

    // Join all the fibers that were created.
    // No new fibers must be created during this call.
    void join_fibers();

private:
    void create_threads();

    std::size_t number_of_workers_;
    bool running_;
    bool suspend_scheduler_;
    std::unique_ptr<boost::fibers::buffered_channel<task_t>> task_queue_;
    std::unique_ptr<boost::fibers::barrier> worker_barrier_;
    std::vector<std::thread> worker_threads_;
    std::shared_ptr<pool_ctx> pool_ctx_;
};

}  // namespace encrypto::motion

#endif  // FIBER_THREAD_POOL_HPP
