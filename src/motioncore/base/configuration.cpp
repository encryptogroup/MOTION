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

#include "configuration.h"

#include <functional>
#include <thread>

#include <fmt/format.h>

#include "communication/context.h"

#include "utility/constants.h"

namespace MOTION {

Configuration::Configuration(const std::vector<Communication::ContextPtr> &contexts, std::size_t id)
    : my_id_(id),
      fixed_key_aes_key_my_part_(ENCRYPTO::AlignedBitVector::Random(kappa)),
      BMR_random_offset_(ENCRYPTO::AlignedBitVector::Random(kappa)),
      num_threads_(std::max(std::thread::hardware_concurrency(), 8u)) {
  communication_contexts_.resize(contexts.size() + 1, nullptr);
  if constexpr (MOTION_VERBOSE_DEBUG) {
    severity_level_ = boost::log::trivial::trace;
  } else if constexpr (MOTION_DEBUG) {
    severity_level_ = boost::log::trivial::debug;
  }

  for (auto &p : contexts) {
    assert(p);
    if (p->GetId() < 0) {
      throw(std::runtime_error(
          fmt::format("IDs should be positive integers, found: {}", p->GetId())));
    } else if (static_cast<std::size_t>(p->GetId()) >= contexts.size() + 1) {
      throw(
          std::runtime_error("IDs should be in the range {0..N-1}, where N is "
                             "the number of parties"));
    } else if (communication_contexts_.at(p->GetId())) {
      throw(std::runtime_error("You cannot have multiple parties with the same id"));
    }
    communication_contexts_.at(p->GetId()) = p;
  }

  if (communication_contexts_.at(my_id_) != nullptr) {
    throw(std::runtime_error("Someone else has my id"));
  }
}

void Configuration::SetOnlineAfterSetup(bool value) { online_after_setup_ = value; }
}