// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko
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

#include "garbled_circuit_gate.h"

#include "communication/garbled_circuit_message.h"
#include "communication/message.h"
#include "garbled_circuit_constants.h"
#include "garbled_circuit_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "protocols/constant/constant_share.h"
#include "utility/block.h"

namespace encrypto::motion::proto::garbled_circuit {

InputGate::InputGate(std::size_t input_owner_id, std::size_t number_of_wires,
                     std::size_t number_of_simd, Backend& backend)
    : Base(backend),
      number_of_simd_(number_of_simd),
      number_of_wires_(number_of_wires),
      is_my_input_(backend.GetCommunicationLayer().GetMyId() == input_owner_id) {
  if constexpr (kDebug) {
    if (input_owner_id >= backend.GetCommunicationLayer().GetNumberOfParties()) {
      throw std::out_of_range(
          fmt::format("Input owner id is out of range: {} but expected less than {}",
                      input_owner_id, backend.GetCommunicationLayer().GetNumberOfParties()));
    }
  }

  if (is_my_input_) {
    // If this party's input, create a promise/future pair to pass the inputs later.
    ReusableFiberPromise<ValueType> promise;
    auto future{promise.get_future()};
    input_promise_future_ = std::optional{std::pair(std::move(promise), std::move(future))};
  }
  output_wires_.resize(number_of_wires);
  for (auto& wire : output_wires_) {
    wire = std::make_shared<garbled_circuit::Wire>(backend, number_of_simd);
  }
}

ReusableFiberPromise<InputGate::ValueType>& InputGate::GetInputPromise() {
  if constexpr (kDebug) {
    if (!input_promise_future_.has_value()) {
      throw std::logic_error("Trying to obtain promise for someone else's input");
    }
  }
  return input_promise_future_->first;
}

const SharePointer InputGate::GetOutputAsGarbledCircuitShare() {
  auto result = std::make_shared<garbled_circuit::Share>(output_wires_);
  assert(result);
  return result;
}

InputGateGarbler::InputGateGarbler(std::size_t input_owner_id, std::size_t number_of_wires,
                                   std::size_t number_of_simd, Backend& backend)
    : Base(input_owner_id, number_of_wires, number_of_simd, backend) {
  // If this is not the garbler's input, the evaluator obtains the label via OT, so register the
  // sender OT object.
  if (!is_my_input_) {
    ots_for_evaluators_inputs_ =
        GetOtProvider(input_owner_id).RegisterSendGOt128(number_of_wires * number_of_simd);
  }
}

InputGateGarbler::InputGateGarbler([[maybe_unused]] std::span<const BitVector<>> input,
                                   std::size_t input_owner_id, Backend& backend)
    : InputGateGarbler(input_owner_id, input.size(), input[0].GetSize(), backend) {
  // if this party's input, copy inputs to the input promise
  if (is_my_input_) GetInputPromise().set_value(std::vector(input.begin(), input.end()));
}

InputGateGarbler::InputGateGarbler(std::vector<BitVector<>>&& input, std::size_t input_owner_id,
                                   Backend& backend)
    : InputGateGarbler(input_owner_id, input.size(), input[0].GetSize(), backend) {
  // if this party's input, move inputs to the input promise
  if (is_my_input_) GetInputPromise().set_value(std::move(input));
}

void InputGateGarbler::EvaluateSetup() {
  for (auto& wire : output_wires_) {
    auto gc_wire = std::dynamic_pointer_cast<garbled_circuit::Wire>(wire);
    assert(gc_wire);
    gc_wire->GetMutableKeys() = Block128Vector::MakeRandom(number_of_simd_);
    // set the bits at positions where we will store the r vector to 0
    for (auto& key : gc_wire->GetMutableKeys()) {
      BitSpan key_span(key.data(), kKappa);
      key_span.Set(false, 0);
      key_span.Set(false, kGarbledRowBitSize);
    }

    gc_wire->SetSetupIsReady();
  }
}

void InputGateGarbler::EvaluateOnline() {
  // Wait for the wire labels to get generated.
  WaitSetup();

  auto& provider{dynamic_cast<ThreeHalvesGarblerProvider&>(GetGarbledCircuitProvider())};
  const Block128& offset{provider.GetOffset()};

  if (is_my_input_) {
    if constexpr (kDebug) {
      if (!input_promise_future_.has_value()) {
        throw std::logic_error(
            "Optional input promise/future must be instantiated for evaluator's input gates");
      }
    }
    auto zero = Block128::MakeZero();
    // send the labels corresponding to the inputs to the evaluator
    std::vector<BitVector<>> inputs{input_promise_future_->second.get()};
    std::vector<std::uint8_t> input_labels(Block128::kBlockSize * number_of_wires_ *
                                           number_of_simd_);
    for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
      auto gc_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
      assert(gc_wire);
      for (std::size_t simd_j = 0; simd_j < number_of_simd_; ++simd_j) {
        const Block128& offset_or_zero = inputs[wire_i][simd_j] ? offset : zero;
        const auto lhs_data{std::assume_aligned<Block128::kBlockSize>(
            reinterpret_cast<const std::uint8_t* __restrict__>(offset_or_zero.data()))};
        const auto rhs_data{std::assume_aligned<Block128::kBlockSize>(
            reinterpret_cast<const std::uint8_t* __restrict__>(gc_wire->GetKeys()[simd_j].data()))};
        auto output_data{reinterpret_cast<std::uint8_t* __restrict__>(
            input_labels.data() + Block128::kBlockSize * (number_of_simd_ * wire_i + simd_j))};
        std::transform(lhs_data, lhs_data + Block128::kBlockSize, rhs_data, output_data,
                       [](const std::uint8_t& lhs, const std::uint8_t& rhs) { return lhs ^ rhs; });
      }
    }
    // Send garbler's input labels to the evaluator.
    flatbuffers::FlatBufferBuilder builder{communication::BuildMessage(
        communication::MessageType::kGarbledCircuitInput, gate_id_, input_labels)};

    backend_.GetCommunicationLayer().SendMessage(
        static_cast<std::size_t>(GarbledCircuitRole::kEvaluator), builder.Release());
  } else {  // evaluator's input
    if constexpr (kDebug) {
      if (!ots_for_evaluators_inputs_) {
        throw std::logic_error("OT object must be instantiated for evaluator's input gates");
      }
    }
    auto& provider{dynamic_cast<ThreeHalvesGarblerProvider&>(GetGarbledCircuitProvider())};
    const Block128& offset = provider.GetOffset();
    // a pair of labels for each wire and simd value
    Block128Vector labels(2 * number_of_wires_ * number_of_simd_);
    for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
      auto gc_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
      for (std::size_t simd_j = 0; simd_j < number_of_simd_; ++simd_j) {
        labels[2 * (wire_i * number_of_simd_ + simd_j)] = gc_wire->GetKeys()[simd_j];
        labels[2 * (wire_i * number_of_simd_ + simd_j) + 1] = gc_wire->GetKeys()[simd_j] ^ offset;
      }
    }
    ots_for_evaluators_inputs_->WaitSetup();
    ots_for_evaluators_inputs_->SetInputs(std::move(labels));
    ots_for_evaluators_inputs_->SendMessages();
  }
}

InputGateEvaluator::InputGateEvaluator(std::size_t input_owner_id, std::size_t number_of_wires,
                                       std::size_t number_of_simd, Backend& backend)
    : Base(input_owner_id, number_of_wires, number_of_simd, backend) {
  // If this is not the garbler's input, the evaluator obtains the label via OT, so register the
  // sender OT object
  if (is_my_input_) {
    label_source_ = backend.GetOtProvider(1 - input_owner_id)
                        .RegisterReceiveGOt128(number_of_wires * number_of_simd);
  } else {  // garbler's input
    label_source_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
        static_cast<std::size_t>(GarbledCircuitRole::kGarbler),
        communication::MessageType::kGarbledCircuitInput, gate_id_);
  }
}

InputGateEvaluator::InputGateEvaluator(std::span<const BitVector<>> input,
                                       std::size_t input_owner_id, Backend& backend)
    : InputGateEvaluator(input_owner_id, input.size(), input[0].GetSize(), backend) {
  // if this party's input, copy inputs to the input promise
  if (is_my_input_) InputGate::GetInputPromise().set_value(std::vector(input.begin(), input.end()));
}

InputGateEvaluator::InputGateEvaluator(std::vector<BitVector<>>&& input, std::size_t input_owner_id,
                                       Backend& backend)
    : InputGateEvaluator(input_owner_id, input.size(), input[0].GetSize(), backend) {
  // if this party's input, copy inputs to the input promise
  if (is_my_input_) GetInputPromise().set_value(std::move(input));
}

void InputGateEvaluator::EvaluateSetup() {}

void InputGateEvaluator::EvaluateOnline() {
  if (is_my_input_) {
    auto& ot_receiver{std::get<std::unique_ptr<GOt128Receiver>>(label_source_)};
    ot_receiver->WaitSetup();
    BitVector<> choices;
    choices.Reserve(number_of_wires_ * number_of_simd_);
    assert(input_promise_future_.has_value());
    auto inputs{input_promise_future_->second.get()};
    for (auto& bit_vector : inputs) choices.Append(bit_vector);
    ot_receiver->SetChoices(std::move(choices));
    ot_receiver->SendCorrections();
    ot_receiver->ComputeOutputs();
    const Block128Vector& output_labels{ot_receiver->GetOutputs()};
    for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
      Block128Vector labels(output_labels.begin() + wire_i * number_of_simd_,
                            output_labels.begin() + (wire_i + 1) * number_of_simd_);
      auto gc_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
      gc_wire->GetMutableKeys() = std::move(labels);
    }
  } else {  // garbler's input
    auto& label_future{std::get<ReusableFiberFuture<std::vector<std::uint8_t>>>(label_source_)};
    auto labels_msg{label_future.get()};
    const auto payload = communication::GetMessage(labels_msg.data())->payload();
    assert(payload->size() == (Block128::kBlockSize * number_of_wires_ * number_of_simd_));

    for (std::size_t wire_i = 0; wire_i < number_of_wires_; ++wire_i) {
      const auto wire_block_ptr{reinterpret_cast<const Block128*>(
          payload->data() + wire_i * Block128::kBlockSize * number_of_simd_)};
      auto gc_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
      assert(gc_wire);
      gc_wire->GetMutableKeys().resize(number_of_simd_);
      std::copy_n(wire_block_ptr, number_of_simd_, gc_wire->GetMutableKeys().data());
    }
  }
}

OutputGate::OutputGate(motion::SharePointer parent, std::size_t output_owner)
    : Base(parent->GetBackend()),
      output_owner_(output_owner),
      everyones_output_(output_owner == kAll),
      my_output_(everyones_output_ || (output_owner == GetCommunicationLayer().GetMyId())) {
  parent_ = parent->GetWires();
  output_wires_.resize(parent_.size());
  for (auto& wire : output_wires_) {
    wire = GetRegister().EmplaceWire<ConstantBooleanWire>(backend_,
                                                          parent_[0]->GetNumberOfSimdValues());
  }
  if (my_output_) {
    std::size_t other_party_id{1 - GetCommunicationLayer().GetMyId()};
    output_future_ = std::optional{GetCommunicationLayer().GetMessageManager().RegisterReceive(
        other_party_id, communication::MessageType::kGarbledCircuitOutput,
        static_cast<std::size_t>(gate_id_))};
  }
}

const std::shared_ptr<ConstantBooleanShare> OutputGate::GetOutputAsConstantShare() {
  auto result = std::make_shared<ConstantBooleanShare>(output_wires_);
  assert(result);
  return result;
}

void OutputGate::EvaluateSetup() {}

void OutputGate::EvaluateOnline() {
  for (auto& wire : parent_) wire->GetIsReadyCondition().Wait();

  // if not this party's output or everyone gets the outputs, parse and send the permutation bits to
  // the other party.
  if ((!my_output_) || everyones_output_) {
    BitVector<> permutation_bits;
    permutation_bits.Reserve(parent_.size() * parent_[0]->GetNumberOfSimdValues());
    for (std::size_t wire_i = 0; wire_i < output_wires_.size(); ++wire_i) {
      auto gc_parent_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_[wire_i])};
      assert(gc_parent_wire);
      permutation_bits.Append(gc_parent_wire->CopyPermutationBits());
    }
    auto fbb{communication::BuildMessage(
        communication::MessageType::kGarbledCircuitOutput, gate_id_,
        std::span(reinterpret_cast<const std::uint8_t*>(permutation_bits.GetData().data()),
                  permutation_bits.GetData().size()))};
    auto other_partys_id{static_cast<std::size_t>(1) - GetCommunicationLayer().GetMyId()};
    GetCommunicationLayer().SendMessage(other_partys_id, fbb.Release());
  }
  // if this party gets the output, wait for the other party's permutation bits to get transmitted
  // and xor them with own permutation bits, which yields the plaintext result.
  if (my_output_) {
    assert(output_future_.has_value());
    auto permutation_bits_msg{output_future_->get()};
    auto permutation_bits = communication::GetMessage(permutation_bits_msg.data())->payload();
    std::size_t number_of_simd{parent_[0]->GetNumberOfSimdValues()};
    BitSpan permutation_bits_span(const_cast<std::uint8_t*>(permutation_bits->data()),
                                  number_of_simd * output_wires_.size());
    for (std::size_t wire_i = 0; wire_i < output_wires_.size(); ++wire_i) {
      auto gc_parent_wire{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_[wire_i])};
      assert(gc_parent_wire);
      auto output_wire{std::dynamic_pointer_cast<ConstantBooleanWire>(output_wires_[wire_i])};
      assert(output_wire);
      output_wire->GetMutableValues() = gc_parent_wire->CopyPermutationBits();
      output_wire->GetMutableValues() ^=
          permutation_bits_span.Subset(wire_i * number_of_simd, (wire_i + 1) * number_of_simd);
    }
  }
}

XorGate::XorGate(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : Base(parent_a->GetBackend()) {
  parent_a_ = parent_a->GetWires();
  parent_b_ = parent_b->GetWires();
  assert(parent_a_.size() == parent_b_.size());
  output_wires_.resize(parent_a_.size());
  for (auto& wire : output_wires_) {
    wire = GetRegister().EmplaceWire<garbled_circuit::Wire>(backend_,
                                                            parent_a_[0]->GetNumberOfSimdValues());
  }
}

SharePointer XorGate::GetOutputAsGarbledCircuitShare() const {
  auto result = std::make_shared<garbled_circuit::Share>(output_wires_);
  assert(result);
  return result;
}

encrypto::motion::SharePointer XorGate::GetOutputAsShare() const {
  return GetOutputAsGarbledCircuitShare();
}

XorGateGarbler::XorGateGarbler(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : XorGate(parent_a, parent_b) {}

void XorGateGarbler::EvaluateSetup() {
  for (std::size_t wire_i = 0; wire_i < parent_a_.size(); ++wire_i) {
    auto gc_wire_a{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_a_[wire_i])};
    auto gc_wire_b{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_b_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_a);
    assert(gc_wire_b);
    assert(gc_wire_out);
    gc_wire_a->WaitSetup();
    gc_wire_b->WaitSetup();
    gc_wire_out->GetMutableKeys() = gc_wire_a->GetKeys() ^ gc_wire_b->GetKeys();
    gc_wire_out->SetSetupIsReady();
  }
}

void XorGateGarbler::EvaluateOnline() {}

XorGateEvaluator::XorGateEvaluator(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : XorGate(parent_a, parent_b) {}

void XorGateEvaluator::EvaluateSetup() {}

void XorGateEvaluator::EvaluateOnline() {
  WaitSetup();
  for (std::size_t wire_i = 0; wire_i < parent_a_.size(); ++wire_i) {
    auto gc_wire_a{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_a_[wire_i])};
    auto gc_wire_b{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_b_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_a);
    assert(gc_wire_b);
    assert(gc_wire_out);
    gc_wire_a->GetIsReadyCondition().Wait();
    gc_wire_b->GetIsReadyCondition().Wait();
    gc_wire_out->GetMutableKeys() = gc_wire_a->GetKeys() ^ gc_wire_b->GetKeys();
  }
}

InvGate::InvGate(motion::SharePointer parent) : Base(parent->GetBackend()) {
  parent_ = parent->GetWires();
  output_wires_.resize(parent_.size());
  for (auto& wire : output_wires_) {
    wire = GetRegister().EmplaceWire<garbled_circuit::Wire>(backend_,
                                                            parent_[0]->GetNumberOfSimdValues());
  }
}

SharePointer InvGate::GetOutputAsGarbledCircuitShare() const {
  auto result = std::make_shared<garbled_circuit::Share>(output_wires_);
  assert(result);
  return result;
}

encrypto::motion::SharePointer InvGate::GetOutputAsShare() const {
  return GetOutputAsGarbledCircuitShare();
}

InvGateGarbler::InvGateGarbler(motion::SharePointer parent) : InvGate(parent) {}

void InvGateGarbler::EvaluateSetup() {
  // xor offset to each key
  auto& garbled_circuit_provider{
      dynamic_cast<ThreeHalvesGarblerProvider&>(GetGarbledCircuitProvider())};
  const Block128& offset{garbled_circuit_provider.GetOffset()};

  for (std::size_t wire_i = 0; wire_i < parent_.size(); ++wire_i) {
    auto gc_wire_in{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_in);
    assert(gc_wire_out);
    gc_wire_in->WaitSetup();
    gc_wire_out->GetMutableKeys() = gc_wire_in->GetKeys();
    for (auto& key : gc_wire_out->GetMutableKeys()) key ^= offset;
    gc_wire_out->SetSetupIsReady();
  }
}

void InvGateGarbler::EvaluateOnline() {}

InvGateEvaluator::InvGateEvaluator(motion::SharePointer parent) : InvGate(parent) {}

void InvGateEvaluator::EvaluateSetup() {}

void InvGateEvaluator::EvaluateOnline() {
  WaitSetup();
  // only copy keys
  for (std::size_t wire_i = 0; wire_i < parent_.size(); ++wire_i) {
    auto gc_wire_in{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_in);
    assert(gc_wire_out);
    gc_wire_in->GetIsReadyCondition().Wait();
    gc_wire_out->GetMutableKeys() = gc_wire_in->GetKeys();
  }
}

AndGate::AndGate(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : Base(parent_a->GetBackend()) {
  assert(parent_a->GetNumberOfSimdValues() == parent_b->GetNumberOfSimdValues());
  parent_a_ = parent_a->GetWires();
  parent_b_ = parent_b->GetWires();

  assert(parent_a_.size() == parent_b_.size());
  output_wires_.resize(parent_a_.size());
  for (auto& wire : output_wires_) {
    wire = GetRegister().EmplaceWire<garbled_circuit::Wire>(backend_,
                                                            parent_a_[0]->GetNumberOfSimdValues());
  }
}

SharePointer AndGate::GetOutputAsGarbledCircuitShare() const {
  auto result = std::make_shared<garbled_circuit::Share>(output_wires_);
  assert(result);
  return result;
}

encrypto::motion::SharePointer AndGate::GetOutputAsShare() const {
  return GetOutputAsGarbledCircuitShare();
}

AndGateGarbler::AndGateGarbler(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : Base(parent_a, parent_b) {}

void AndGateGarbler::EvaluateSetup() {
  auto& provider{dynamic_cast<ThreeHalvesGarblerProvider&>(GetGarbledCircuitProvider())};
  provider.WaitSetup();
  std::size_t number_of_simd{parent_a_[0]->GetNumberOfSimdValues()};
  std::size_t total_number_of_wires{parent_a_.size() * number_of_simd};
  std::size_t tables_byte_size{total_number_of_wires * kGarbledTableByteSize};
  // avoid using std::vector to not initialize the memory
  std::size_t payload_size{
      BitsToBytes(total_number_of_wires * (kGarbledTableBitSize + kGarbledControlBitsBitSize))};
  auto garbled_tables_and_control_bits{std::make_unique<std::byte[]>(payload_size)};
  std::byte* control_bits{(garbled_tables_and_control_bits.get()) + tables_byte_size};

  // Remark: it's not necessary to wait for the provider's setup phase, since all the required
  // information (hash and aes key) is generated in the constructor.
  for (std::size_t wire_i = 0; wire_i < output_wires_.size(); ++wire_i) {
    auto gc_wire_a{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_a_[wire_i])};
    auto gc_wire_b{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_b_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_a);
    assert(gc_wire_b);
    gc_wire_a->WaitSetup();
    gc_wire_b->WaitSetup();
    assert(gc_wire_out);
    if constexpr (kVerboseDebug) {
      std::string message{fmt::format("Garble garbled circuit AND gate for wires ({}, {}) -> {}\n",
                                      gc_wire_a->GetWireId(), gc_wire_b->GetWireId(),
                                      gc_wire_out->GetWireId())};
      GetLogger().LogDebug(std::move(message));
    }
    gc_wire_out->GetMutableKeys().resize(number_of_simd);
    provider.Garble(gc_wire_a->GetKeys(), gc_wire_b->GetKeys(), gc_wire_out->GetMutableKeys(),
                    garbled_tables_and_control_bits.get(), control_bits, wire_i * number_of_simd,
                    gate_id_ + wire_i);
    gc_wire_out->SetSetupIsReady();
  }

  auto builder{communication::BuildMessage(
      communication::MessageType::kGarbledCircuitGarbledTables, gate_id_,
      std::span(reinterpret_cast<const std::uint8_t*>(garbled_tables_and_control_bits.get()),
                payload_size))};
  backend_.GetCommunicationLayer().SendMessage(
      static_cast<std::size_t>(GarbledCircuitRole::kEvaluator), builder.Release());
}

void AndGateGarbler::EvaluateOnline() {}

AndGateEvaluator::AndGateEvaluator(motion::SharePointer parent_a, motion::SharePointer parent_b)
    : Base(parent_a, parent_b) {
  garbled_tables_msg_future_ = GetCommunicationLayer().GetMessageManager().RegisterReceive(
      static_cast<std::size_t>(GarbledCircuitRole::kGarbler),
      communication::MessageType::kGarbledCircuitGarbledTables, gate_id_);
}

void AndGateEvaluator::EvaluateSetup() {
  auto& provider{dynamic_cast<ThreeHalvesEvaluatorProvider&>(GetGarbledCircuitProvider())};
  provider.WaitSetup();
  garbled_tables_msg_future_.wait(); }

void AndGateEvaluator::EvaluateOnline() {
  auto& provider{dynamic_cast<ThreeHalvesEvaluatorProvider&>(GetGarbledCircuitProvider())};
  for (auto& wire : parent_a_) wire->GetIsReadyCondition().Wait();
  for (auto& wire : parent_b_) wire->GetIsReadyCondition().Wait();
  std::size_t number_of_simd{parent_a_[0]->GetNumberOfSimdValues()};

  auto garbled_tables_msg{garbled_tables_msg_future_.get()};
  auto garbled_tables{communication::GetMessage(garbled_tables_msg.data())->payload()};
  for (std::size_t wire_i = 0; wire_i < output_wires_.size(); ++wire_i) {
    auto gc_wire_a{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_a_[wire_i])};
    auto gc_wire_b{std::dynamic_pointer_cast<garbled_circuit::Wire>(parent_b_[wire_i])};
    auto gc_wire_out{std::dynamic_pointer_cast<garbled_circuit::Wire>(output_wires_[wire_i])};
    assert(gc_wire_a);
    assert(gc_wire_b);
    assert(gc_wire_out);
    if constexpr (kVerboseDebug) {
      std::string message{fmt::format("Garbled circuit: evaluate AND gate for wires ({}, {}) -> {}",
                                      gc_wire_a->GetWireId(), gc_wire_b->GetWireId(),
                                      gc_wire_out->GetWireId())};
      GetLogger().LogDebug(std::move(message));
    }
    gc_wire_out->GetMutableKeys().resize(number_of_simd);
    std::size_t tables_size{output_wires_.size() * number_of_simd * kGarbledTableByteSize};
    provider.Evaluate(gc_wire_a->GetKeys(), gc_wire_b->GetKeys(), gc_wire_out->GetMutableKeys(),
                      reinterpret_cast<const std::byte*>(garbled_tables->data()),
                      reinterpret_cast<const std::byte*>(garbled_tables->data() + tables_size),
                      wire_i * number_of_simd, gate_id_ + wire_i);
  }
}

}  // namespace encrypto::motion::proto::garbled_circuit