// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "ot_extension_data.h"

#include <thread>

#include "utility/block.h"
#include "utility/condition.h"
#include "utility/fiber_condition.h"

namespace encrypto::motion {

OtExtensionReceiverData::OtExtensionReceiverData() {
  setup_finished_condition =
      std::make_unique<FiberCondition>([this]() { return setup_finished.load(); });
}

OtExtensionSenderData::OtExtensionSenderData() {
  setup_finished_condition =
      std::make_unique<FiberCondition>([this]() { return setup_finished.load(); });

  for (std::size_t i = 0; i < u_promises.size(); ++i) u_futures[i] = u_promises[i].get_future();
}

void OtExtensionData::MessageReceived(const std::uint8_t* message,
                                      [[maybe_unused]] std::size_t message_size,
                                      const OtExtensionDataType type, const std::size_t i) {
  switch (type) {
    case OtExtensionDataType::kReceptionMask: {
      {
        while (sender_data.bit_size == 0) std::this_thread::yield();
        std::scoped_lock lock(sender_data.u_mutex);
        sender_data.u[i] = AlignedBitVector(message, sender_data.bit_size);
        sender_data.u_promises[sender_data.number_of_received_us].set_value(i);

        // set to 0 after Clear()
        sender_data.number_of_received_us++;
      }

      break;
    }
    case OtExtensionDataType::kReceptionCorrection: {
      auto condition = sender_data.received_correction_offsets_condition.find(i);
      assert(condition != sender_data.received_correction_offsets_condition.end());
      {
        std::scoped_lock lock(condition->second->GetMutex(), sender_data.corrections_mutex);
        auto number_of_ots = sender_data.number_of_ots_in_batch.find(i);
        assert(number_of_ots != sender_data.number_of_ots_in_batch.end());
        BitVector<> local_corrections(message, number_of_ots->second);
        sender_data.corrections.Copy(i, i + number_of_ots->second, local_corrections);
        sender_data.received_correction_offsets.emplace(i);
      }
      condition->second->NotifyAll();
      break;
    }
    case OtExtensionDataType::kSendMessage: {
      {
        receiver_data.setup_finished_condition->Wait();

        std::unique_lock lock(receiver_data.bitlengths_mutex);
        const auto bitlength = receiver_data.bitlengths.at(i);
        lock.unlock();

        const auto batch_iterator = receiver_data.number_of_ots_in_batch.find(i);
        assert(batch_iterator != receiver_data.number_of_ots_in_batch.end());
        const auto batch_size = batch_iterator->second;

        auto message_type = receiver_data.message_type.find(i);
        if (message_type != receiver_data.message_type.end()) {
          switch (message_type->second) {
            case OtMessageType::kBlock128: {
              auto promise_iterator = receiver_data.message_promises_block128.find(i);
              assert(promise_iterator != receiver_data.message_promises_block128.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * 16 == message_size);
              promise.set_value(Block128Vector(size, message));
              return;
            } break;
            case OtMessageType::kBit: {
              auto promise_iterator = receiver_data.message_promises_bit.find(i);
              assert(promise_iterator != receiver_data.message_promises_bit.end());
              auto& [size, promise] = promise_iterator->second;
              assert((size + 7) / 8 == message_size);
              promise.set_value(BitVector<>(message, size));
              return;
            } break;
            case OtMessageType::kUint8: {
              constexpr auto type_c = boost::hana::type_c<std::uint8_t>;
              auto& promise_map = receiver_data.message_promises_int[type_c];
              auto promise_iterator = promise_map.find(i);
              assert(promise_iterator != promise_map.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * sizeof(decltype(type_c)::type) == message_size);
              auto message_pointer = reinterpret_cast<const decltype(type_c)::type*>(message);
              promise.set_value(std::vector(message_pointer, message_pointer + size));
              return;
            } break;
            case OtMessageType::kUint16: {
              constexpr auto type_c = boost::hana::type_c<std::uint16_t>;
              auto& promise_map = receiver_data.message_promises_int[type_c];
              auto promise_iterator = promise_map.find(i);
              assert(promise_iterator != promise_map.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * sizeof(decltype(type_c)::type) == message_size);
              auto message_pointer = reinterpret_cast<const decltype(type_c)::type*>(message);
              promise.set_value(std::vector(message_pointer, message_pointer + size));
              return;
            } break;
            case OtMessageType::kUint32: {
              constexpr auto type_c = boost::hana::type_c<std::uint32_t>;
              auto& promise_map = receiver_data.message_promises_int[type_c];
              auto promise_iterator = promise_map.find(i);
              assert(promise_iterator != promise_map.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * sizeof(decltype(type_c)::type) == message_size);
              auto message_pointer = reinterpret_cast<const decltype(type_c)::type*>(message);
              promise.set_value(std::vector(message_pointer, message_pointer + size));
              return;
            } break;
            case OtMessageType::kUint64: {
              constexpr auto type_c = boost::hana::type_c<std::uint64_t>;
              auto& promise_map = receiver_data.message_promises_int[type_c];
              auto promise_iterator = promise_map.find(i);
              assert(promise_iterator != promise_map.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * sizeof(decltype(type_c)::type) == message_size);
              auto message_pointer = reinterpret_cast<const decltype(type_c)::type*>(message);
              promise.set_value(std::vector(message_pointer, message_pointer + size));
              return;
            } break;
            case OtMessageType::kUint128: {
              constexpr auto type_c = boost::hana::type_c<__uint128_t>;
              auto& promise_map = receiver_data.message_promises_int[type_c];
              auto promise_iterator = promise_map.find(i);
              assert(promise_iterator != promise_map.end());
              auto& [size, promise] = promise_iterator->second;
              assert(size * sizeof(decltype(type_c)::type) == message_size);
              auto message_pointer = reinterpret_cast<const decltype(type_c)::type*>(message);
              promise.set_value(std::vector(message_pointer, message_pointer + size));
              return;
            } break;
          }
        }

        auto conditions_iterator = receiver_data.output_conditions.find(i);
        assert(conditions_iterator != receiver_data.output_conditions.end());

        bool success{false};
        do {
          {
            std::scoped_lock lock(receiver_data.number_of_messages_to_be_sent_mutex);
            success = receiver_data.number_of_messages_to_be_sent.find(i) !=
                      receiver_data.number_of_messages_to_be_sent.end();
          }
          if (!success) std::this_thread::yield();
        } while (!success);

        const auto n = receiver_data.number_of_messages_to_be_sent.at(i);

        BitVector<> message_bv(message, batch_size * bitlength * n);

        success = false;
        do {
          {
            std::scoped_lock lock(receiver_data.real_choices_mutex);
            success = receiver_data.real_choices_condition.find(i) !=
                      receiver_data.real_choices_condition.end();
          }
          if (!success) std::this_thread::yield();
        } while (!success);
        receiver_data.real_choices_condition.at(i)->Wait();

        for (auto j = 0ull; j < batch_size; ++j) {
          if (n == 2) {
            if (receiver_data.random_choices->Get(i + j)) {
              receiver_data.outputs.at(i + j) ^=
                  message_bv.Subset((2 * j + 1) * bitlength, (2 * j + 2) * bitlength);
            } else {
              receiver_data.outputs.at(i + j) ^=
                  message_bv.Subset(2 * j * bitlength, (2 * j + 1) * bitlength);
            }
          } else if (n == 1) {
            if (receiver_data.real_choices->Get(i + j)) {
              if (receiver_data.xor_correlation.find(i) != receiver_data.xor_correlation.end()) {
                receiver_data.outputs.at(i + j) ^=
                    message_bv.Subset(j * bitlength, (j + 1) * bitlength);
              } else {
                auto message = message_bv.Subset(j * bitlength, (j + 1) * bitlength);
                auto output = receiver_data.outputs.at(i + j).GetMutableData().data();
                switch (bitlength) {
                  case 8u: {
                    *reinterpret_cast<uint8_t*>(output) =
                        *reinterpret_cast<const uint8_t*>(message.GetData().data()) -
                        *reinterpret_cast<const uint8_t*>(output);
                    break;
                  }
                  case 16u: {
                    *reinterpret_cast<uint16_t*>(output) =
                        *reinterpret_cast<const uint16_t*>(message.GetData().data()) -
                        *reinterpret_cast<const uint16_t*>(output);
                    break;
                  }
                  case 32u: {
                    *reinterpret_cast<uint32_t*>(output) =
                        *reinterpret_cast<const uint32_t*>(message.GetData().data()) -
                        *reinterpret_cast<const uint32_t*>(output);
                    break;
                  }
                  case 64u: {
                    *reinterpret_cast<uint64_t*>(output) =
                        *reinterpret_cast<const uint64_t*>(message.GetData().data()) -
                        *reinterpret_cast<const uint64_t*>(output);
                    break;
                  }
                  case 128u: {
                    *reinterpret_cast<__uint128_t*>(output) =
                        *reinterpret_cast<const __uint128_t*>(message.GetData().data()) -
                        *reinterpret_cast<const __uint128_t*>(output);
                    break;
                  }
                  default:
                    throw std::runtime_error(fmt::format(
                        "Unsupported bitlength={} for additive correlation. Allowed are "
                        "bitlengths: 8, 16, 32, 64.",
                        bitlength));
                }
              }
            }
          } else {
            throw std::runtime_error("Not inmplemented yet");
          }
        }

        {
          std::scoped_lock lock(conditions_iterator->second->GetMutex(),
                                receiver_data.received_outputs_mutex);
          receiver_data.received_outputs.emplace(i);
        }
        conditions_iterator->second->NotifyAll();
      }
      break;
    }
    default: {
      throw std::runtime_error(fmt::format(
          "DataStorage::OtExtensionDataType: unknown data type {}; data_type must be <{}", type,
          OtExtensionDataType::kOtExtensionInvalidDataType));
    }
  }
}

ReusableFiberFuture<Block128Vector> OtExtensionReceiverData::RegisterForBlock128SenderMessage(
    std::size_t ot_id, std::size_t size) {
  ReusableFiberPromise<Block128Vector> promise;
  auto future = promise.get_future();
  auto [it, success] =
      message_promises_block128.emplace(ot_id, std::make_pair(size, std::move(promise)));
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for Block128SenderMessage for OT#{}", ot_id));
  }
  return future;
}

ReusableFiberFuture<BitVector<>> OtExtensionReceiverData::RegisterForBitSenderMessage(
    std::size_t ot_id, std::size_t size) {
  ReusableFiberPromise<BitVector<>> promise;
  auto future = promise.get_future();
  auto [it, success] =
      message_promises_bit.emplace(ot_id, std::make_pair(size, std::move(promise)));
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for BitSenderMessage for OT#{}", ot_id));
  }
  return future;
}

template <typename T>
ReusableFiberFuture<std::vector<T>> OtExtensionReceiverData::RegisterForIntSenderMessage(
    std::size_t ot_id, std::size_t size) {
  ReusableFiberPromise<std::vector<T>> promise;
  auto future = promise.get_future();
  auto [it, success] = message_promises_int[boost::hana::type_c<T>].emplace(
      ot_id, std::make_pair(size, std::move(promise)));
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for IntSenderMessage for OT#{}", ot_id));
  }
  return future;
}

template ReusableFiberFuture<std::vector<std::uint8_t>>
OtExtensionReceiverData::RegisterForIntSenderMessage(std::size_t ot_id, std::size_t size);
template ReusableFiberFuture<std::vector<std::uint16_t>>
OtExtensionReceiverData::RegisterForIntSenderMessage(std::size_t ot_id, std::size_t size);
template ReusableFiberFuture<std::vector<std::uint32_t>>
OtExtensionReceiverData::RegisterForIntSenderMessage(std::size_t ot_id, std::size_t size);
template ReusableFiberFuture<std::vector<std::uint64_t>>
OtExtensionReceiverData::RegisterForIntSenderMessage(std::size_t ot_id, std::size_t size);
template ReusableFiberFuture<std::vector<__uint128_t>>
OtExtensionReceiverData::RegisterForIntSenderMessage(std::size_t ot_id, std::size_t size);

}  // namespace encrypto::motion
