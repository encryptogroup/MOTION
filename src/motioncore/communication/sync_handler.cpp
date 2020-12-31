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

#include "sync_handler.h"

#include <fmt/format.h>

#include "fbs_headers/message_generated.h"
#include "utility/logger.h"

namespace encrypto::motion::communication {

void SynchronizationHandler::ReceivedMessage(std::size_t party_id,
                                             std::vector<std::uint8_t>&& raw_message) {
  assert(!raw_message.empty());
  const auto message =
      communication::GetMessage(reinterpret_cast<std::uint8_t*>(raw_message.data()));
  const auto message_size = message->payload()->size();
  if (message_size != sizeof(std::uint64_t)) {
    if (logger_) {
      logger_->LogError(
          fmt::format("received SynchronizationMessage from party {} with invalid size {} /= {}",
                      party_id, message_size, sizeof(std::uint64_t)));
    }
    return;
  }
  // the data may not be aligned to the same as a 64-bit value
  // thus we need to copy it
  const auto message_data = message->payload()->data();
  std::uint64_t received_synchronization_state;
  // std::copy requires its dereferenced iterators to be assignable,
  // so we do the extra cast here
  char* received_synchronization_state_ptr =
      reinterpret_cast<char*>(&received_synchronization_state);
  std::copy_n(message_data, sizeof(std::uint64_t), received_synchronization_state_ptr);
  {
    std::scoped_lock lock(received_synchronization_states_mutex_);
    synchronization_states_.at(party_id) =
        std::max(received_synchronization_state, synchronization_states_.at(party_id));
  }
  synchronization_states_condition_variable_.notify_all();
}

void SynchronizationHandler::Wait() {
  auto my_synchronization_state = synchronization_states_.at(my_id_);
  std::unique_lock lock(received_synchronization_states_mutex_);
  synchronization_states_condition_variable_.wait(lock, [this, my_synchronization_state] {
    return std::all_of(
        std::begin(synchronization_states_), std::end(synchronization_states_),
        [my_synchronization_state](auto s) { return s >= my_synchronization_state; });
  });
}

}  // namespace encrypto::motion::communication
