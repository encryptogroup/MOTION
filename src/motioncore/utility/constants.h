// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
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

#include <iostream>
#include <limits>
#include <string>

#include "config.h"
#include "typedefs.h"

namespace MOTION {

// just in case if we all of a sudden will decide to change the name
constexpr std::string_view FRAMEWORK_NAME{"MOTION"};

constexpr auto MB{1024 * 1024};

constexpr bool MOTION_VERBOSE_DEBUG_WISH{false};

// Don't compile unnecessary code if verbose debugging is not needed
constexpr bool MOTION_VERBOSE_DEBUG{MOTION_DEBUG && MOTION_VERBOSE_DEBUG_WISH};

constexpr std::size_t AES_KEY_SIZE{16};

constexpr std::size_t AES_BLOCK_SIZE_{16};

constexpr std::size_t AES_IV_SIZE{AES_BLOCK_SIZE_ / 2};

constexpr std::size_t MESSAGE_SIZE_BYTELEN{sizeof(std::uint32_t)};

// 2^32 - 2, approx. 4.3 GB
constexpr std::uint32_t MAX_MESSAGE_SIZE{std::numeric_limits<std::uint32_t>::max() - 1};

// symmetric security parameter
constexpr std::size_t kappa{128};

// stack size for fibers
constexpr std::size_t MOTION_FIBER_STACK_SIZE{14 * 1024};

enum class FiberStackAllocator {
  // standard allocator
  fixedsize,
  // allocate the stacks from a memory pool
  pooled_fixedsize,
  // use an allocator for fiber stacks that inserts a guard page at the end of
  // the stack space resulting in a SIGSEGV if a stack overflow happens
  protected_fixedsize,
};

// standard allocator for fiber stacks
constexpr FiberStackAllocator MOTION_FIBER_STACK_ALLOCATOR{FiberStackAllocator::fixedsize};

}  // namespace MOTION
