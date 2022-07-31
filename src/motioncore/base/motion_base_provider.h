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

#include <atomic>
#include <memory>
#include <vector>

#include "utility/fiber_waitable.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion::primitives {

class SharingRandomnessGenerator;

}  // namespace encrypto::motion::primitives

namespace encrypto::motion {

class FiberCondition;
class Logger;

class BaseProvider : public FiberSetupWaitable {
 public:
  BaseProvider(communication::CommunicationLayer&);
  ~BaseProvider();

  void Setup();

  const std::vector<std::uint8_t>& GetAesFixedKey() const { return aes_fixed_key_; }
  primitives::SharingRandomnessGenerator& GetMyRandomnessGenerator(std::size_t party_id) {
    return *my_randomness_generators_[party_id];
  }
  primitives::SharingRandomnessGenerator& GetTheirRandomnessGenerator(std::size_t party_id) {
    return *their_randomness_generators_[party_id];
  }
  primitives::SharingRandomnessGenerator& GetGlobalRandomnessGenerator() {
    return *global_randomness_generator_;
  }

 private:
  communication::CommunicationLayer& communication_layer_;
  std::shared_ptr<Logger> logger_;
  std::size_t number_of_parties_;
  std::size_t my_id_;
  std::vector<std::uint8_t> aes_fixed_key_;
  std::vector<std::unique_ptr<primitives::SharingRandomnessGenerator>> my_randomness_generators_;
  std::vector<std::unique_ptr<primitives::SharingRandomnessGenerator>> their_randomness_generators_;
  std::unique_ptr<primitives::SharingRandomnessGenerator> global_randomness_generator_;

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> hello_message_futures_;
};

}  // namespace encrypto::motion
