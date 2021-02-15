// This file is adapted from context/pooled_fixedsize_stack.hpp of Boost 1.72.0.

//          Copyright Oliver Kowalke 2014 / Lennart Braun 2020
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#ifndef SINGLETON_POOLED_FIXEDSIZE_STACK_H
#define SINGLETON_POOLED_FIXEDSIZE_STACK_H

#include <atomic>
#include <boost/pool/poolfwd.hpp>
#include <cstddef>
#include <cstdlib>
#include <new>

#include <boost/assert.hpp>
#include <boost/config.hpp>
#include <boost/intrusive_ptr.hpp>
#include <boost/pool/singleton_pool.hpp>

#include <boost/context/detail/config.hpp>
#include <boost/context/stack_context.hpp>
#include <boost/context/stack_traits.hpp>

// clang-format off

template <std::size_t stack_size, typename traitsT>
class basic_singleton_pooled_fixedsize_stack {
private:
    class storage {
    private:
        std::atomic<std::size_t> use_count_;
        struct pool_tag {};
        typedef boost::singleton_pool<pool_tag, stack_size, boost::default_user_allocator_malloc_free>
        storage_pool;

    public:
        storage() : use_count_(0) {
            BOOST_ASSERT(traits_type::is_unbounded() || (traits_type::maximum_size() >= stack_size));
        }

        boost::context::stack_context allocate() {
            void* vp = storage_pool::malloc();
            if (!vp) {
                throw std::bad_alloc();
            }
            boost::context::stack_context sctx;
            sctx.size = stack_size;
            sctx.sp = static_cast<char*>(vp) + sctx.size;
#if defined(BOOST_USE_VALGRIND)
            sctx.valgrind_stack_id = VALGRIND_STACK_REGISTER(sctx.sp, vp);
#endif
            return sctx;
        }

        void deallocate(boost::context::stack_context& sctx) BOOST_NOEXCEPT_OR_NOTHROW {
            BOOST_ASSERT(sctx.sp);
            BOOST_ASSERT(traits_type::is_unbounded() || (traits_type::maximum_size() >= sctx.size));

#if defined(BOOST_USE_VALGRIND)
            VALGRIND_STACK_DEREGISTER(sctx.valgrind_stack_id);
#endif
            void* vp = static_cast<char*>(sctx.sp) - sctx.size;
            storage_pool::free(vp);
        }

        friend void intrusive_ptr_add_ref(storage* s) noexcept {
            ++s->use_count_;
        }

        friend void intrusive_ptr_release(storage* s) noexcept {
            if (0 == --s->use_count_) {
                delete s;
            }
        }
    };

    boost::intrusive_ptr<storage> storage_;

public:
    typedef traitsT traits_type;

    // parameters are kept for compatibility of interface
    basic_singleton_pooled_fixedsize_stack(std::size_t = 0, std::size_t = 0,
                                           std::size_t = 0) BOOST_NOEXCEPT_OR_NOTHROW
:
    storage_(new storage()) {}

    boost::context::stack_context allocate() {
        return storage_->allocate();
    }

    void deallocate(boost::context::stack_context& sctx) BOOST_NOEXCEPT_OR_NOTHROW {
        storage_->deallocate(sctx);
    }
};

template <std::size_t stack_size>
using singleton_pooled_fixedsize_stack =
    basic_singleton_pooled_fixedsize_stack<stack_size, boost::context::stack_traits>;

// clang-format on

#endif  // SINGLETON_POOLED_FIXEDSIZE_STACK_H
