// This file is adapted from fiber/algo/work_stealing.hpp of Boost 1.71.0.
//
//          Copyright Oliver Kowalke 2015 / Lennart Braun 2019.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file BOOST_SOFTWARE_LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)
//

#include "pooled_work_stealing.hpp"

#include <random>

#include <boost/assert.hpp>
#include <boost/context/detail/prefetch.hpp>

#include <boost/fiber/detail/thread_barrier.hpp>
#include <boost/fiber/type.hpp>

// clang-format off

struct pool_ctx {
    pool_ctx(std::uint32_t thread_count, bool suspend)
        : thread_count_(thread_count),
          suspend_(suspend),
          counter_(0),
          schedulers_(thread_count, nullptr),
          barrier_(thread_count) {
        BOOST_ASSERT(thread_count > 1);
    }
    const std::uint32_t thread_count_;
    const bool suspend_;
    std::atomic<std::uint32_t> counter_;
    std::vector<pooled_work_stealing*> schedulers_;
    boost::barrier barrier_;
};

std::shared_ptr<pool_ctx> pooled_work_stealing::create_pool_ctx(std::uint32_t thread_count,
        bool suspend) {
    auto ctx = std::make_shared<pool_ctx>(thread_count, suspend);
    return ctx;
}

pooled_work_stealing::pooled_work_stealing(std::shared_ptr<pool_ctx> pool_ctx)
    : pool_ctx_{pool_ctx},
      id_{pool_ctx_->counter_++},
      thread_count_{pool_ctx_->thread_count_},
      suspend_{pool_ctx_->suspend_} {
    pool_ctx_->schedulers_[id_] = this;
    pool_ctx_->barrier_.wait();
}

pooled_work_stealing::~pooled_work_stealing() {
    // wait for all thread of the pool such that pointers in pool_ctx_ stay
    // valid while still in use
    pool_ctx_->barrier_.wait();
}

void pooled_work_stealing::awakened(boost::fibers::context* ctx) noexcept {
    if (!ctx->is_context(boost::fibers::type::pinned_context)) {
        ctx->detach();
    }
    rqueue_.push(ctx);
}

boost::fibers::context* pooled_work_stealing::pick_next() noexcept {
    boost::fibers::context* victim = rqueue_.pop();
    if (nullptr != victim) {
        boost::context::detail::prefetch_range(victim, sizeof(boost::fibers::context));
        if (!victim->is_context(boost::fibers::type::pinned_context)) {
            boost::fibers::context::active()->attach(victim);
        }
    }
    else {
        std::uint32_t id = 0;
        std::size_t count = 0, size = pool_ctx_->schedulers_.size();
        static thread_local std::minstd_rand generator{std::random_device{}()};
        std::uniform_int_distribution<std::uint32_t> distribution{
            0, static_cast<std::uint32_t>(thread_count_ - 1)};
        do {
            do {
                ++count;
                // random selection of one logical cpu
                // that belongs to the local NUMA node
                id = distribution(generator);
                // prevent stealing from own scheduler
            }
            while (id == id_);
            // steal context from other scheduler
            victim = pool_ctx_->schedulers_[id]->steal();
        }
        while (nullptr == victim && count < size);
        if (nullptr != victim) {
            boost::context::detail::prefetch_range(victim, sizeof(boost::fibers::context));
            BOOST_ASSERT(!victim->is_context(boost::fibers::type::pinned_context));
            boost::fibers::context::active()->attach(victim);
        }
    }
    return victim;
}

void pooled_work_stealing::suspend_until(
    std::chrono::steady_clock::time_point const& time_point) noexcept {
    if (suspend_) {
        if ((std::chrono::steady_clock::time_point::max)() == time_point) {
            std::unique_lock<std::mutex> lk{mtx_};
            cnd_.wait(lk, [this]() {
                return flag_;
            });
            flag_ = false;
        }
        else {
            std::unique_lock<std::mutex> lk{mtx_};
            cnd_.wait_until(lk, time_point, [this]() {
                return flag_;
            });
            flag_ = false;
        }
    }
}

void pooled_work_stealing::notify() noexcept {
    if (suspend_) {
        std::unique_lock<std::mutex> lk{mtx_};
        flag_ = true;
        lk.unlock();
        cnd_.notify_all();
    }
}

// clang-format on
