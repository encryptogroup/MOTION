// This file is adapted from fiber/algo/work_stealing.hpp of Boost 1.71.0.
//
//          Copyright Oliver Kowalke 2015 / Lennart Braun 2019.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file BOOST_SOFTWARE_LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)
//


#ifndef POOLED_WORK_STEALING_H
#define POOLED_WORK_STEALING_H

#include <atomic>
#include <condition_variable>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include <boost/config.hpp>
#include <boost/intrusive_ptr.hpp>

#include <boost/fiber/algo/algorithm.hpp>
#include <boost/fiber/context.hpp>
#include <boost/fiber/detail/config.hpp>
#include <boost/fiber/detail/context_spinlock_queue.hpp>
#include <boost/fiber/detail/context_spmc_queue.hpp>
#include <boost/fiber/scheduler.hpp>
#include <boost/thread/barrier.hpp>

struct pool_ctx;

class pooled_work_stealing : public boost::fibers::algo::algorithm {
  public:

private:
    std::shared_ptr<pool_ctx> pool_ctx_;

    std::uint32_t                                           id_;
    std::uint32_t                                           thread_count_;
#ifdef BOOST_FIBERS_USE_SPMC_QUEUE
    boost::fibers::detail::context_spmc_queue               rqueue_{};
#else
    boost::fibers::detail::context_spinlock_queue           rqueue_{};
#endif
    std::mutex                                              mtx_{};
    std::condition_variable                                 cnd_{};
    bool                                                    flag_{ false };
    bool                                                    suspend_;

    static void init_( std::uint32_t, std::vector< boost::intrusive_ptr< pooled_work_stealing > > &);

public:
    static std::shared_ptr<pool_ctx> create_pool_ctx(std::uint32_t, bool = false);
    pooled_work_stealing( std::shared_ptr<pool_ctx>);
    ~pooled_work_stealing();

    pooled_work_stealing( pooled_work_stealing const&) = delete;
    pooled_work_stealing( pooled_work_stealing &&) = delete;

    pooled_work_stealing & operator=( pooled_work_stealing const&) = delete;
    pooled_work_stealing & operator=( pooled_work_stealing &&) = delete;

    virtual void awakened( boost::fibers::context *) noexcept;

    virtual boost::fibers::context * pick_next() noexcept;

    virtual boost::fibers::context * steal() noexcept {
        return rqueue_.steal();
    }

    virtual bool has_ready_fibers() const noexcept {
        return ! rqueue_.empty();
    }

    virtual void suspend_until( std::chrono::steady_clock::time_point const&) noexcept;

    virtual void notify() noexcept;
};


#endif // POOLED_WORK_STEALING_H
