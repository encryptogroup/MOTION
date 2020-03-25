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

namespace MOTION::Communication {
flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type,
                                                   const std::vector<uint8_t> *payload) {
  auto allocation_size = payload ? payload->size() + 20 : 1024;
  flatbuffers::FlatBufferBuilder builder(allocation_size);
  auto root = CreateMessageDirect(builder, message_type, payload);
  FinishMessageBuffer(builder, root);
  return builder;
}

flatbuffers::FlatBufferBuilder BuildMessage(MessageType message_type, const uint8_t *payload,
                                                   std::size_t size) {
  assert(payload);
  std::vector<std::uint8_t> buffer(payload, payload + size);
  return BuildMessage(message_type, &buffer);
}

using namespace std::string_literals;

std::string to_string(MessageType message_type) {
  switch (message_type) {
    case MessageType::HelloMessage:
      return "MessageType::HelloMessage"s;
    case MessageType::OutputMessage:
      return "MessageType::OutputMessage"s;
    case MessageType::TerminationMessage:
      return "MessageType::TerminationMessage"s;
    case MessageType::SynchronizationMessage:
      return "MessageType::SynchronizationMessage"s;
    case MessageType::BaseROTMessageSender:
      return "MessageType::BaseROTMessageSender"s;
    case MessageType::BaseROTMessageReceiver:
      return "MessageType::BaseROTMessageReceiver"s;
    case MessageType::OTExtensionReceiverMasks:
      return "MessageType::OTExtensionReceiverMasks"s;
    case MessageType::OTExtensionReceiverCorrections:
      return "MessageType::OTExtensionReceiverCorrections"s;
    case MessageType::OTExtensionSender:
      return "MessageType::OTExtensionSender"s;
    case MessageType::BMRInputGate0:
      return "MessageType::BMRInputGate0"s;
    case MessageType::BMRInputGate1:
      return "MessageType::BMRInputGate1"s;
    case MessageType::BMRANDGate:
      return "MessageType::BMRANDGate"s;
    case MessageType::SharedBitsMask:
      return "MessageType::SharedBitsMask"s;
    case MessageType::SharedBitsReconstruct:
      return "MessageType::SharedBitsReconstruct"s;
    default:
      return "Unknown MessageType => update to_string function"s;
  }
}

}  // namespace MOTION::Communication
