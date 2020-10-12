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

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

#include "message_handler.h"

namespace encrypto::motion {

class Logger;

}  // namespace encrypto::motion

namespace encrypto::motion::communication {

class SynchronizationHandler : public MessageHandler {
 public:
  SynchronizationHandler(std::size_t my_id, std::size_t number_of_parties,
                         std::shared_ptr<Logger> logger)
      : my_id_(my_id),
        number_of_parties_(number_of_parties),
        synchronization_states_(number_of_parties_, 0),
        logger_(std::move(logger)) {}
  std::uint64_t IncrementMySynchronizationState() { return ++synchronization_states_.at(my_id_); }
  void ReceivedMessage(std::size_t party_id, std::vector<std::uint8_t>&& message) override;
  void Wait();
  std::mutex& GetMutex() { return this_party_mutex_; }

 private:
  std::size_t my_id_;
  std::size_t number_of_parties_;
  std::mutex this_party_mutex_;
  std::mutex received_synchronization_states_mutex_;
  std::condition_variable synchronization_states_condition_variable_;
  std::vector<std::uint64_t> synchronization_states_;
  std::shared_ptr<Logger> logger_;
};

}  // namespace encrypto::motion::communication
