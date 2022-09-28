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

#include "message.h"

#include "fbs_headers/message_generated.h"
#include "utility/typedefs.h"

namespace encrypto::motion::communication {

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type) {
  auto allocation_size = 32;
  flatbuffers::FlatBufferBuilder fbb(allocation_size);
  MessageBuilder message_builder(fbb);
  message_builder.add_message_type(message_type);
  auto root = message_builder.Finish();
  FinishMessageBuffer(fbb, root);
  return fbb;
}

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type, std::size_t message_id,
                                            std::span<const uint8_t> payload) {
  auto allocation_size = payload.size() + 20;
  flatbuffers::FlatBufferBuilder fbb(allocation_size);
  auto payload_vector = fbb.CreateVector<uint8_t>(payload.data(), payload.size());
  MessageBuilder message_builder(fbb);
  message_builder.add_message_id(message_id);
  message_builder.add_payload(payload_vector);
  message_builder.add_message_type(message_type);
  auto root = message_builder.Finish();
  FinishMessageBuffer(fbb, root);
  return fbb;
}

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                            std::span<const uint8_t> payload) {
  auto allocation_size = payload.size() + 20;
  flatbuffers::FlatBufferBuilder fbb(allocation_size);
  auto payload_vector = fbb.CreateVector<uint8_t>(payload.data(), payload.size());
  MessageBuilder message_builder(fbb);
  message_builder.add_payload(payload_vector);
  message_builder.add_message_type(message_type);
  auto root = message_builder.Finish();
  FinishMessageBuffer(fbb, root);
  return fbb;
}

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                            const std::vector<uint8_t>* payload) {
  assert(payload);
  return BuildMessage(message_type, std::span(*payload));
}

using namespace std::string_literals;

std::string to_string(MessageType message_type) {
  switch (message_type) {
    case MessageType::kHelloMessage:
      return "MessageType::HelloMessage"s;
    case MessageType::kOutputMessage:
      return "MessageType::OutputMessage"s;
    case MessageType::kTerminationMessage:
      return "MessageType::TerminationMessage"s;
    case MessageType::kSynchronizationMessage:
      return "MessageType::SynchronizationMessage"s;
    case MessageType::kBaseROtMessageSender:
      return "MessageType::BaseROtMessageSender"s;
    case MessageType::kBaseROtMessageReceiver:
      return "MessageType::BaseROtMessageReceiver"s;
    case MessageType::kOtExtensionReceiverMasks:
      return "MessageType::OtExtensionReceiverMasks"s;
    case MessageType::kOtExtensionReceiverCorrections:
      return "MessageType::OtExtensionReceiverCorrections"s;
    case MessageType::kOtExtensionSender:
      return "MessageType::OtExtensionSender"s;
    case MessageType::kBmrInputGate0:
      return "MessageType::BmrInputGate0"s;
    case MessageType::kBmrInputGate1:
      return "MessageType::BmrInputGate1"s;
    case MessageType::kBmrAndGate:
      return "MessageType::BmrAndGate"s;
    case MessageType::kSharedBitsMask:
      return "MessageType::SharedBitsMask"s;
    case MessageType::kSharedBitsReconstruct:
      return "MessageType::SharedBitsReconstruct"s;
    default:
      return "Unknown MessageType => update to_string function"s;
  }
}

}  // namespace encrypto::motion::communication
