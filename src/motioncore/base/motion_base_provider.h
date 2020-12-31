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
struct HelloMessageHandler;
class OutputMessageHandler;

class BaseProvider {
 public:
  BaseProvider(communication::CommunicationLayer&, std::shared_ptr<Logger> logger);
  ~BaseProvider();

  void Setup();
  void WaitForSetup() const;

  const std::vector<std::uint8_t>& GetAesFixedKey() const { return aes_fixed_key_; }
  primitives::SharingRandomnessGenerator& GetMyRandomnessGenerator(std::size_t party_id) {
    return *my_randomness_generators_.at(party_id);
  }
  primitives::SharingRandomnessGenerator& GetTheirRandomnessGenerator(std::size_t party_id) {
    return *their_randomness_generators_.at(party_id);
  }

  std::vector<ReusableFiberFuture<std::vector<std::uint8_t>>> RegisterForOutputMessages(
      std::size_t gate_id);

 private:
  communication::CommunicationLayer& communication_layer_;
  std::shared_ptr<Logger> logger_;
  std::size_t number_of_parties_;
  std::size_t my_id_;
  std::vector<std::uint8_t> aes_fixed_key_;
  std::vector<std::unique_ptr<primitives::SharingRandomnessGenerator>> my_randomness_generators_;
  std::vector<std::unique_ptr<primitives::SharingRandomnessGenerator>> their_randomness_generators_;
  std::shared_ptr<HelloMessageHandler> hello_message_handler_;
  std::vector<std::shared_ptr<OutputMessageHandler>> output_message_handlers_;

  std::atomic_flag execute_setup_flag_ = ATOMIC_FLAG_INIT;
  bool setup_ready_;
  std::unique_ptr<FiberCondition> setup_ready_cond_;
};

}  // namespace encrypto::motion
