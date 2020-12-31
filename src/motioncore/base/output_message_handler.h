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

#include "communication/message_handler.h"
#include "utility/reusable_future.h"

namespace encrypto::motion {

class Logger;

// Handler for messages of type OutputMessage
class OutputMessageHandler : public communication::MessageHandler {
 public:
  // Create a handler object for a given party
  OutputMessageHandler(std::size_t party_id, std::shared_ptr<Logger> logger);

  // Register for an OutputMessage.
  // Returns a future which can be used to wait for and retrieve the message.
  ReusableFiberFuture<std::vector<std::uint8_t>> register_for_output_message(std::size_t gate_id);

  // Method which is called on received messages.
  void ReceivedMessage(std::size_t, std::vector<std::uint8_t>&& message) override;

 private:
  std::size_t party_id_;
  std::shared_ptr<Logger> logger_;

  std::unordered_map<std::size_t, ReusableFiberPromise<std::vector<std::uint8_t>>>
      output_message_promises_;
  // synchronizes access to above map
  std::mutex output_message_promises_mutex_;
};

}  // namespace encrypto::motion
