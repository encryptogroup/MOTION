// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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

#include "base_ot_data.h"

#include "utility/fiber_condition.h"

namespace encrypto::motion {

BaseOtReceiverData::BaseOtReceiverData() {
  is_ready_condition = std::make_unique<FiberCondition>([this]() { return is_ready.load(); });
}

void BaseOtReceiverData::Add(std::size_t number_of_ots) {
  messages_c.resize(messages_c.size() + number_of_ots);
}

BaseOtSenderData::BaseOtSenderData() {
  is_ready_condition = std::make_unique<FiberCondition>([this]() { return is_ready.load(); });
}

void BaseOtSenderData::Add(std::size_t number_of_ots) {
  messages_0.resize(messages_0.size() + number_of_ots);
  messages_1.resize(messages_1.size() + number_of_ots);
}

}  // namespace encrypto::motion
