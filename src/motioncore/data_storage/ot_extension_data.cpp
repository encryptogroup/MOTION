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
            case OtMessageType::kGenericBoolean: {
              auto promise_iterator = receiver_data.message_promises_generic.find(i);
              assert(promise_iterator != receiver_data.message_promises_generic.end());
              auto& [vector_size, bitlength, promise] = promise_iterator->second;
              assert((vector_size * bitlength + 7) / 8 == message_size);
              BitSpan bit_span(const_cast<std::uint8_t*>(message), vector_size * bitlength);
              std::vector<BitVector<>> result;
              result.reserve(vector_size);
              for (std::size_t i = 0; i < vector_size; ++i) {
                result.emplace_back(bit_span.Subset(i * bitlength, (i + 1) * bitlength));
              }
              promise.set_value(std::move(result));
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

ReusableFiberFuture<std::vector<BitVector<>>>
OtExtensionReceiverData::RegisterForGenericSenderMessage(std::size_t ot_id, std::size_t size,
                                                         std::size_t bitlength) {
  ReusableFiberPromise<std::vector<BitVector<>>> promise;
  auto future = promise.get_future();
  auto [it, success] =
      message_promises_generic.emplace(ot_id, std::make_tuple(size, bitlength, std::move(promise)));
  if (!success) {
    throw std::runtime_error(
        fmt::format("tried to register twice for GenericSenderMessage for OT#{}", ot_id));
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
