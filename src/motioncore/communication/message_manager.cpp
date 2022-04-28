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

#include "message_manager.h"

#include "fbs_headers/message_generated.h"

namespace encrypto::motion::communication {

MessageManager::MessageManager(std::size_t number_of_parties, std::size_t my_id) : my_id_(my_id) {
  incoming_message_promises_.resize(number_of_parties - 1);
  incoming_sync_states_ =
      std::vector<SynchronizedFiberQueue<container_type>>(number_of_parties - 1);
}

void MessageManager::ReceivedMessage(std::size_t sender_id,
                                     std::vector<std::uint8_t>&& message) {
  auto fb_message{GetMessage(message.data())};
  MessageType message_type{fb_message->message_type()};
  std::size_t message_id{fb_message->message_id()};
  incoming_message_promises_[ComputeId(sender_id)][message_type][message_id]->set_value(
      std::move(message));
}

MessageManager::future_type MessageManager::RegisterReceive(std::size_t sender_id,
                                                            MessageType message_type,
                                                            std::size_t message_id) {
  auto p{std::make_unique<promise_type>()};
  auto f{p->get_future()};
  incoming_message_promises_[ComputeId(sender_id)][message_type][message_id] = std::move(p);
  return f;
}

std::vector<MessageManager::future_type> MessageManager::RegisterReceiveAll(
    MessageType message_type, std::size_t message_id) {
  std::vector<MessageManager::future_type> futures;
  futures.reserve(incoming_message_promises_.size());
  for (auto& m : incoming_message_promises_) {
    auto p{std::make_unique<promise_type>()};
    auto f{p->get_future()};
    m[message_type][message_id] = std::move(p);
    futures.emplace_back(std::move(f));
  }
  return futures;
}

}  // namespace encrypto::motion::communication