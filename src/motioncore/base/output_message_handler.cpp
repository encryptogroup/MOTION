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

#include "output_message_handler.h"

#include <fmt/format.h>

#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

OutputMessageHandler::OutputMessageHandler(std::size_t party_id, std::shared_ptr<Logger> logger)
    : party_id_(party_id), logger_(std::move(logger)) {}

ReusableFiberFuture<std::vector<std::uint8_t>> OutputMessageHandler::register_for_output_message(
    std::size_t gate_id) {
  ReusableFiberPromise<std::vector<std::uint8_t>> promise;
  auto future = promise.get_future();
  std::unique_lock<std::mutex> lock(output_message_promises_mutex_);
  auto [_, success] = output_message_promises_.insert({gate_id, std::move(promise)});
  lock.unlock();
  if (!success) {
    if (logger_) {
      logger_->LogError(
          fmt::format("Tried to register twice for OutputMessage with gate#{}", gate_id));
    }
    throw std::logic_error(
        fmt::format("Tried to register twice for OutputMessage with gate#{}", gate_id));
  }
  if constexpr (kVerboseDebug) {
    if (logger_) {
      logger_->LogDebug(fmt::format("Registered for OutputMessage from Party#{} for gate#{}",
                                    gate_id, party_id_));
    }
  }
  return future;
}

void OutputMessageHandler::ReceivedMessage(std::size_t,
                                           std::vector<std::uint8_t>&& output_message) {
  assert(!output_message.empty());
  auto message = communication::GetMessage(reinterpret_cast<std::uint8_t*>(output_message.data()));
  auto output_message_pointer = communication::GetOutputMessage(message->payload()->data());
  auto gate_id = output_message_pointer->gate_id();

  // find promise
  auto iterator = output_message_promises_.find(gate_id);
  if (iterator == output_message_promises_.end()) {
    // no promise found -> drop message
    if (logger_) {
      logger_->LogError(
          fmt::format("Received unexpected OutputMessage from Party#{} for gate#{}, dropping",
                      party_id_, gate_id));
    }
    return;
  }
  auto& promise = iterator->second;
  // put the received message into the promise
  try {
    promise.set_value(std::move(output_message));
  } catch (std::future_error& e) {
    // there might be already a value in the promise
    if (logger_) {
      logger_->LogError(fmt::format(
          "Error while processing OutputMessage from Party#{} for gate#{}, dropping: {}", party_id_,
          gate_id, e.what()));
    }
    return;
  }

  if constexpr (kVerboseDebug) {
    if (logger_) {
      logger_->LogDebug(
          fmt::format("Received an OutputMessage from Party#{} for gate#{}", party_id_, gate_id));
    }
  }
}

}  // namespace encrypto::motion
