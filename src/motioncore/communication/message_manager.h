// MIT License
//
// Copyright (c) 2022 Oleksandr Tkachenko
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

#include <memory>
#include <unordered_map>

#include "utility/reusable_future.h"
#include "utility/synchronized_queue.h"

namespace encrypto::motion::communication {

enum class MessageType : uint8_t;

/// \brief Manages future/promise based communication channels in the following way:
/// In a pre-setup phase, a callee calls some Register* function eg RegisterReceive for
/// some \p sender_id, \p message_type and a \p message_id. The result of the function is a future.
/// The respective promise is stored in a nested hash map based structure that allows to efficiently
/// find the promise, when a matching message arrives.
/// After the pre-setup phase, another party transmits the message corresponding to the registered
/// parameters. The message gets moved to the promise as a whole ie all further actions such as
/// parsing the message depend on the code calling the get() function. Consequently, a message
/// obtained from the future should be obtained via
/// communication::GetMessage(raw_message_pointer)->payload() interface from flatbuffers.
class MessageManager {
 public:
  // byte type
  using value_type = std::uint8_t;
  // byte container for the message data
  using container_type = std::vector<value_type>;
  // promise for a message
  using promise_type = ReusableFiberPromise<container_type>;
  // future belonging to a promise
  using future_type = ReusableFiberFuture<container_type>;
  // submap[message_id] -> message_promise
  using submap_type = std::unordered_map<std::size_t, std::unique_ptr<promise_type>>;
  // map[message_type] -> submap
  using map_type = std::unordered_map<MessageType, submap_type>;

  MessageManager() = delete;
  MessageManager(const MessageManager&) = delete;

  MessageManager(std::size_t number_of_parties, std::size_t my_id);

  // This method is called to forward a received message to the corresponding future.
  void ReceivedMessage(std::size_t sender_id, std::vector<std::uint8_t>&& message);

  [[nodiscard]] future_type RegisterReceive(std::size_t sender_id, MessageType message_type,
                                            std::size_t message_id);

  [[nodiscard]] std::vector<future_type> RegisterReceiveAll(MessageType message_type,
                                                            std::size_t message_id);

  auto& GetMessagePromises(std::size_t party_id) {
    return incoming_message_promises_[ComputeId(party_id)];
  }

  auto& GetMessagePromises() { return incoming_message_promises_; }

  auto& GetSyncStates(std::size_t party_id) { return incoming_sync_states_[ComputeId(party_id)]; }

  auto& GetSyncStates() { return incoming_sync_states_; }

 private:
  std::size_t ComputeId(std::size_t id) { return id < my_id_ ? id : id - 1; }

  // incoming_message_promises_[sender_id][message_type][message_id]
  std::vector<map_type> incoming_message_promises_;
  // sync states need to be handled differently because it may happen that 2 sync states arrive
  // sequentially, which would break the promise-future logic.
  std::vector<SynchronizedFiberQueue<container_type>> incoming_sync_states_;
  std::size_t my_id_;
};

}  // namespace encrypto::motion::communication
