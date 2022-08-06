// MIT License
//
// Copyright (c) 2019-2021 Oleksandr Tkachenko, Lennart Braun, Arianne Roselina Prananto
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

#include "arithmetic_gmw_gate.h"

#include <flatbuffers/flatbuffers.h>
#include <fmt/format.h>
#include <cmath>
#include <span>

#include "base/backend.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/message.h"
#include "communication/message_manager.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"
#include "utility/logger.h"

namespace encrypto::motion::proto::arithmetic_gmw {

template <typename T>
InputGate<T>::InputGate(std::span<const T> input, std::size_t input_owner, Backend& backend)
    : Base(backend), input_(std::vector(input.begin(), input.end())) {
  input_owner_id_ = input_owner;
  InitializationHelper();
}

template <typename T>
InputGate<T>::InputGate(std::vector<T>&& input, std::size_t input_owner, Backend& backend)
    : Base(backend), input_(std::move(input)) {
  input_owner_id_ = input_owner;
  InitializationHelper();
}

template <typename T>
void InputGate<T>::InitializationHelper() {
  static_assert(!std::is_same_v<T, bool>);

  arithmetic_sharing_id_ = GetRegister().NextArithmeticSharingId(input_.size());
  if constexpr (kVerboseDebug) {
    GetLogger().LogTrace(
        fmt::format("Created an arithmetic_gmw::InputGate with global id {}", gate_id_));
  }
  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(input_, backend_)};

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, input_owner_id_);
  GetLogger().LogDebug(fmt::format(
      "Allocate an arithmetic_gmw::InputGate with following properties: {}", gate_info));
}

template <typename T>
void InputGate<T>::EvaluateSetup() {}

template <typename T>
void InputGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  GetBaseProvider().WaitSetup();

  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  std::vector<T> result;

  if (static_cast<std::size_t>(input_owner_id_) == my_id) {
    result.resize(input_.size());
    auto log_string = std::string("");
    for (auto party_id = 0u; party_id < number_of_parties; ++party_id) {
      if (party_id == my_id) {
        continue;
      }
      auto& randomness_generator = GetBaseProvider().GetMyRandomnessGenerator(party_id);
      auto randomness =
          randomness_generator.template GetUnsigned<T>(arithmetic_sharing_id_, input_.size());
      if constexpr (kVerboseDebug) {
        log_string.append(fmt::format("id#{}:{} ", party_id, randomness.at(0)));
      }
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) += randomness.at(j);
      }
    }
    for (auto j = 0u; j < result.size(); ++j) {
      result.at(j) = input_.at(j) - result.at(j);
    }

    if constexpr (kVerboseDebug) {
      auto s = fmt::format(
          "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
          "share: {}, expected shares of other parties: {}",
          input_owner_id_, gate_id_, input_.at(0), result.at(0), log_string);
      GetLogger().LogTrace(s);
    }
  } else {
    auto& randomness_generator = GetBaseProvider().GetTheirRandomnessGenerator(input_owner_id_);
    result = randomness_generator.template GetUnsigned<T>(arithmetic_sharing_id_, input_.size());

    if constexpr (kVerboseDebug) {
      auto s = fmt::format(
          "Arithmetic input sharing (gate#{}) of Party's#{} input, got a share "
          "{} from the seed",
          gate_id_, input_owner_id_, result.at(0));
      GetLogger().LogTrace(s);
    }
  }
  auto my_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(my_wire);
  my_wire->GetMutableValues() = std::move(result);

  GetLogger().LogDebug(fmt::format("Evaluated arithmetic_gmw::InputGate with id#{}", gate_id_));
}

// perhaps, we should return a copy of the pointer and not move it for the
// case we need it multiple times
template <typename T>
arithmetic_gmw::SharePointer<T> InputGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = GetOutputArithmeticWire();
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

// perhaps, we should return a copy of the pointer and not move it for the
// case we need it multiple times
template <typename T>
arithmetic_gmw::WirePointer<T> InputGate<T>::GetOutputArithmeticWire() {
  auto result = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(result);
  return result;
}

template class InputGate<std::uint8_t>;
template class InputGate<std::uint16_t>;
template class InputGate<std::uint32_t>;
template class InputGate<std::uint64_t>;
template class InputGate<__uint128_t>;

template <typename T>
OutputGate<T>::OutputGate(const arithmetic_gmw::WirePointer<T>& parent, std::size_t output_owner)
    : Base(parent->GetBackend()) {
  assert(parent);

  if (parent->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(
        std::runtime_error((fmt::format("Arithmetic output gate expects an arithmetic share, "
                                        "got a share of type {}",
                                        sharing_type))));
  }

  parent_ = {parent};

  // values we need repeatedly
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  if (static_cast<std::size_t>(output_owner) >= number_of_parties &&
      static_cast<std::size_t>(output_owner) != kAll) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, number_of_parties));
  }

  output_owner_ = output_owner;
  is_my_output_ = my_id == static_cast<std::size_t>(output_owner_) ||
                  static_cast<std::size_t>(output_owner_) == kAll;

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, parent->GetNumberOfSimdValues())};

  // Tell the DataStorages that we want to receive OutputMessages from the
  // other parties.
  if (is_my_output_) {
    output_message_futures_ = GetCommunicationLayer().GetMessageManager().RegisterReceiveAll(
        communication::MessageType::kOutputMessage, gate_id_);
  }

  if constexpr (kDebug) {
    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, output_owner_);
    GetLogger().LogDebug(fmt::format(
        "Allocate an arithmetic_gmw::OutputGate with following properties: {}", gate_info));
  }
}

template <typename T>
OutputGate<T>::OutputGate(const arithmetic_gmw::SharePointer<T>& parent, std::size_t output_owner)
    : OutputGate(parent->GetArithmeticWire(), output_owner) {
  assert(parent);
}

template <typename T>
OutputGate<T>::OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
    : OutputGate(std::dynamic_pointer_cast<arithmetic_gmw::Share<T>>(parent), output_owner) {
  assert(parent);
}

template <typename T>
void OutputGate<T>::EvaluateSetup() {}

template <typename T>
void OutputGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check

  // data we need repeatedly
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  // note that arithmetic gates have only a single wire
  auto arithmetic_wire = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));
  assert(arithmetic_wire);
  // wait for parent wire to obtain a value
  arithmetic_wire->GetIsReadyCondition().Wait();
  // initialize output with local share
  auto output = arithmetic_wire->GetValues();

  // we need to send shares to one other party:
  if (!is_my_output_) {
    auto payload = ToByteVector<T>(output);
    auto msg{
        communication::BuildMessage(communication::MessageType::kOutputMessage, gate_id_, payload)};
    communication_layer.SendMessage(output_owner_, msg.Release());
  }
  // we need to send shares to all other parties:
  else if (output_owner_ == kAll) {
    auto payload = ToByteVector<T>(output);
    auto msg{
        communication::BuildMessage(communication::MessageType::kOutputMessage, gate_id_, payload)};
    communication_layer.BroadcastMessage(msg.Release());
  }

  // we receive shares from other parties
  if (is_my_output_) {
    // collect shares from all parties
    std::vector<std::vector<T>> shared_outputs;
    shared_outputs.reserve(number_of_parties);

    for (std::size_t i = 0; i < number_of_parties; ++i) {
      if (i == my_id) {
        shared_outputs.push_back(output);
        continue;
      }
      const auto output_message = output_message_futures_.at(i > my_id ? i - 1 : i).get();
      auto message = communication::GetMessage(output_message.data());

      const auto& fb_vector{*message->payload()};
      shared_outputs.push_back(FromByteVector<T>(std::span(fb_vector.Data(), fb_vector.size())));
      assert(shared_outputs[i].size() == parent_[0]->GetNumberOfSimdValues());
    }

    // reconstruct the shared value
    if constexpr (kVerboseDebug) {
      // we need to copy since we have to keep shared_outputs for the debug output below
      output = AddVectors(shared_outputs);
    } else {
      // we can move
      output = AddVectors(std::move(shared_outputs));
    }

    // set the value of the output wire
    auto arithmetic_output_wire =
        std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_output_wire);
    arithmetic_output_wire->GetMutableValues() = output;

    if constexpr (kVerboseDebug) {
      std::string shares{""};
      for (auto i = 0u; i < number_of_parties; ++i) {
        shares.append(fmt::format("id#{}:{} ", i, to_string(shared_outputs.at(i))));
      }
      auto result = to_string(output);
      GetLogger().LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, result));
    }
  }

  // we are done with this gate
  if constexpr (kDebug) {
    GetLogger().LogDebug(fmt::format("Evaluated arithmetic_gmw::OutputGate with id#{}", gate_id_));
  }
}

template <typename T>
arithmetic_gmw::SharePointer<T> OutputGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class OutputGate<std::uint8_t>;
template class OutputGate<std::uint16_t>;
template class OutputGate<std::uint32_t>;
template class OutputGate<std::uint64_t>;
template class OutputGate<__uint128_t>;

template <typename T>
AdditionGate<T>::AdditionGate(const arithmetic_gmw::WirePointer<T>& a,
                              const arithmetic_gmw::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
  parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

  assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, a->GetNumberOfSimdValues())};

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::AdditionGate with following properties: {}", gate_info));
}

template <typename T>
void AdditionGate<T>::EvaluateSetup() {}

template <typename T>
void AdditionGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto wire_a = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
  auto wire_b = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));

  assert(wire_a);
  assert(wire_b);

  std::vector<T> output;
  output = RestrictAddVectors<T>(wire_a->GetValues(), wire_b->GetValues());

  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  arithmetic_wire->GetMutableValues() = std::move(output);

  GetLogger().LogDebug(fmt::format("Evaluated arithmetic_gmw::AdditionGate with id#{}", gate_id_));
}

template <typename T>
arithmetic_gmw::SharePointer<T> AdditionGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class AdditionGate<std::uint8_t>;
template class AdditionGate<std::uint16_t>;
template class AdditionGate<std::uint32_t>;
template class AdditionGate<std::uint64_t>;
template class AdditionGate<__uint128_t>;

template <typename T>
SubtractionGate<T>::SubtractionGate(const arithmetic_gmw::WirePointer<T>& a,
                                    const arithmetic_gmw::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
  parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

  assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, a->GetNumberOfSimdValues())};

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::SubtractionGate with following properties: {}", gate_info));
}

template <typename T>
void SubtractionGate<T>::EvaluateSetup() {}

template <typename T>
void SubtractionGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto wire_a = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
  auto wire_b = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));

  assert(wire_a);
  assert(wire_b);

  std::vector<T> output = SubVectors<T>(wire_a->GetValues(), wire_b->GetValues());

  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  arithmetic_wire->GetMutableValues() = std::move(output);

  GetLogger().LogDebug(
      fmt::format("Evaluated arithmetic_gmw::SubtractionGate with id#{}", gate_id_));
}

template <typename T>
arithmetic_gmw::SharePointer<T> SubtractionGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class SubtractionGate<std::uint8_t>;
template class SubtractionGate<std::uint16_t>;
template class SubtractionGate<std::uint32_t>;
template class SubtractionGate<std::uint64_t>;
template class SubtractionGate<__uint128_t>;

template <typename T>
MultiplicationGate<T>::MultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
                                          const arithmetic_gmw::WirePointer<T>& b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
  parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

  assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

  d_ = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(backend_,
                                                                   a->GetNumberOfSimdValues());
  e_ = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(backend_,
                                                                   a->GetNumberOfSimdValues());

  d_output_ = GetRegister().template EmplaceGate<OutputGate<T>>(d_);
  e_output_ = GetRegister().template EmplaceGate<OutputGate<T>>(e_);

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, a->GetNumberOfSimdValues())};

  number_of_mts_ = parent_a_.at(0)->GetNumberOfSimdValues();
  mt_offset_ = GetMtProvider().template RequestArithmeticMts<T>(number_of_mts_);

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::MultiplicationGate with following properties: {}", gate_info));
}

template <typename T>
void MultiplicationGate<T>::EvaluateSetup() {}

template <typename T>
void MultiplicationGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto& mt_provider = GetMtProvider();
  mt_provider.WaitFinished();
  const auto& mts = mt_provider.template GetIntegerAll<T>();
  {
    const auto x = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
    assert(x);
    d_->GetMutableValues() = std::vector<T>(
        mts.a.begin() + mt_offset_, mts.a.begin() + mt_offset_ + x->GetNumberOfSimdValues());
    T* __restrict__ d_v = d_->GetMutableValues().data();
    const T* __restrict__ x_v = x->GetValues().data();
    const auto number_of_simd_values{x->GetNumberOfSimdValues()};

    std::transform(x_v, x_v + number_of_simd_values, d_v, d_v,
                   [](const T& a, const T& b) { return a + b; });
    d_->SetOnlineFinished();

    const auto y = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));
    assert(y);
    e_->GetMutableValues() = std::vector<T>(
        mts.b.begin() + mt_offset_, mts.b.begin() + mt_offset_ + x->GetNumberOfSimdValues());
    T* __restrict__ e_v = e_->GetMutableValues().data();
    const T* __restrict__ y_v = y->GetValues().data();
    std::transform(y_v, y_v + number_of_simd_values, e_v, e_v,
                   [](const T& a, const T& b) { return a + b; });
    e_->SetOnlineFinished();
  }

  d_output_->WaitOnline();
  e_output_->WaitOnline();

  const auto& d_clear = d_output_->GetOutputWires().at(0);
  const auto& e_clear = e_output_->GetOutputWires().at(0);

  d_clear->GetIsReadyCondition().Wait();
  e_clear->GetIsReadyCondition().Wait();

  const auto d_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(d_clear);
  const auto x_i_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
  const auto e_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(e_clear);
  const auto y_i_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));

  assert(d_w);
  assert(x_i_w);
  assert(e_w);
  assert(y_i_w);

  auto output = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(output);
  output->GetMutableValues() =
      std::vector<T>(mts.c.begin() + mt_offset_,
                     mts.c.begin() + mt_offset_ + parent_a_.at(0)->GetNumberOfSimdValues());

  const T* __restrict__ d{d_w->GetValues().data()};
  const T* __restrict__ s_x{x_i_w->GetValues().data()};
  const T* __restrict__ e{e_w->GetValues().data()};
  const T* __restrict__ s_y{y_i_w->GetValues().data()};
  T* __restrict__ output_pointer{output->GetMutableValues().data()};

  if (GetCommunicationLayer().GetMyId() ==
      (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
    for (auto i = 0ull; i < output->GetNumberOfSimdValues(); ++i) {
      output_pointer[i] += (d[i] * s_y[i]) + (e[i] * s_x[i]) - (e[i] * d[i]);
    }
  } else {
    for (auto i = 0ull; i < output->GetNumberOfSimdValues(); ++i) {
      output_pointer[i] += (d[i] * s_y[i]) + (e[i] * s_x[i]);
    }
  }

  GetLogger().LogDebug(
      fmt::format("Evaluated arithmetic_gmw::MultiplicationGate with id#{}", gate_id_));
}

template <typename T>
arithmetic_gmw::SharePointer<T> MultiplicationGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class MultiplicationGate<std::uint8_t>;
template class MultiplicationGate<std::uint16_t>;
template class MultiplicationGate<std::uint32_t>;
template class MultiplicationGate<std::uint64_t>;
// template class MultiplicationGate<__uint128_t>; not yet supported

template <typename T>
HybridMultiplicationGate<T>::HybridMultiplicationGate(const boolean_gmw::WirePointer& bit,
                                                      const arithmetic_gmw::WirePointer<T>& integer)
    : TwoGate(bit->GetBackend()) {
  // this gate works only for two parties
  assert(GetCommunicationLayer().GetNumberOfParties() == 2);
  parent_a_ = {std::static_pointer_cast<motion::Wire>(bit)};
  parent_b_ = {std::static_pointer_cast<motion::Wire>(integer)};

  assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());
  assert(parent_a_.at(0)->GetBitLength() == 1);

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, parent_a_[0]->GetNumberOfSimdValues())};

  const std::size_t number_of_parties{GetCommunicationLayer().GetNumberOfParties()};
  const std::size_t my_id = GetCommunicationLayer().GetMyId();

  for (std::size_t i = 0; i < number_of_parties; ++i) {
    if (i == my_id) continue;
    ot_sender_ =
        GetOtProvider(i).RegisterSendAcOt(parent_a_[0]->GetNumberOfSimdValues(), sizeof(T) * 8);
    ot_receiver_ =
        GetOtProvider(i).RegisterReceiveAcOt(parent_a_[0]->GetNumberOfSimdValues(), sizeof(T) * 8);
  }

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::HybridMultiplicationGate with following properties: {}",
      gate_info));
}

template <typename T>
void HybridMultiplicationGate<T>::EvaluateSetup() {}

template <typename T>
void HybridMultiplicationGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  const auto bw = std::dynamic_pointer_cast<boolean_gmw::Wire>(parent_a_.at(0));
  assert(bw);
  const auto aw = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(parent_b_.at(0));
  assert(aw);

  auto a_out = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(a_out);
  a_out->GetMutableValues().reserve(aw->GetNumberOfSimdValues());

  auto& bv = bw->GetValues();
  auto& av = aw->GetValues();

  std::vector<T> ot_data;
  ot_data.reserve(bv.GetSize());
  for (std::size_t i = 0; i != bv.GetSize(); ++i) {
    // (-1)^<b>_i^B * <v>_i^A + r as AC-OT msgs for party i-1
    ot_data.emplace_back(bv[i] ? -av[i] : av[i]);
    // Locally calculate <b>_i^B * <v>_i^A
    a_out->GetMutableValues().emplace_back(bv[i] ? av[i] : static_cast<T>(0));
  }

  // AcOt Send and Recieve

  auto casted_ot_sender{dynamic_cast<AcOtSender<T>*>(ot_sender_.get())};
  auto casted_ot_receiver{dynamic_cast<AcOtReceiver<T>*>(ot_receiver_.get())};
  assert(casted_ot_sender);
  assert(casted_ot_receiver);

  casted_ot_sender->WaitSetup();
  casted_ot_sender->SetCorrelations(ot_data);
  casted_ot_sender->SendMessages();

  casted_ot_receiver->WaitSetup();
  casted_ot_receiver->SetChoices(bv);
  casted_ot_receiver->SendCorrections();

  casted_ot_sender->ComputeOutputs();
  casted_ot_receiver->ComputeOutputs();

  // parse OT outputs
  std::vector<T> ot_sender_output{casted_ot_sender->GetOutputs()};
  std::vector<T> ot_receiver_output{casted_ot_receiver->GetOutputs()};

  // Compute the result
  for (std::size_t simd_i = 0; simd_i < parent_a_[0]->GetNumberOfSimdValues(); ++simd_i) {
    a_out->GetMutableValues()[simd_i] += ot_receiver_output[simd_i] - ot_sender_output[simd_i];
  }

  GetLogger().LogDebug(
      fmt::format("Evaluated arithmetic_gmw::HybridMultiplicationGate with id#{}", gate_id_));
}

template <typename T>
arithmetic_gmw::SharePointer<T> HybridMultiplicationGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class HybridMultiplicationGate<std::uint8_t>;
template class HybridMultiplicationGate<std::uint16_t>;
template class HybridMultiplicationGate<std::uint32_t>;
template class HybridMultiplicationGate<std::uint64_t>;
// template class HybridMultiplicationGate<__uint128_t>; not yet supported

template <typename T>
SquareGate<T>::SquareGate(const arithmetic_gmw::WirePointer<T>& a) : OneGate(a->GetBackend()) {
  parent_ = {std::static_pointer_cast<motion::Wire>(a)};

  d_ = GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(backend_,
                                                                   a->GetNumberOfSimdValues());
  d_output_ = GetRegister().template EmplaceGate<OutputGate<T>>(d_);

  output_wires_ = {GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(
      backend_, a->GetNumberOfSimdValues())};

  number_of_sps_ = parent_.at(0)->GetNumberOfSimdValues();
  sp_offset_ = GetSpProvider().template RequestSps<T>(number_of_sps_);

  auto gate_info = fmt::format("uint{}_t type, gate id {}, parent: {}", sizeof(T) * 8, gate_id_,
                               parent_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::SquareGate with following properties: {}", gate_info));
}

template <typename T>
void SquareGate<T>::EvaluateSetup() {}

template <typename T>
void SquareGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check
  parent_.at(0)->GetIsReadyCondition().Wait();

  auto& sp_provider = GetSpProvider();
  sp_provider.WaitFinished();
  const auto& sps = sp_provider.template GetSpsAll<T>();
  {
    const auto x = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));
    assert(x);
    d_->GetMutableValues() = std::vector<T>(
        sps.a.begin() + sp_offset_, sps.a.begin() + sp_offset_ + x->GetNumberOfSimdValues());
    T* __restrict__ d_v{d_->GetMutableValues().data()};
    const T* __restrict__ x_v{x->GetValues().data()};
    const auto number_of_simd_values{x->GetNumberOfSimdValues()};
    std::transform(x_v, x_v + number_of_simd_values, d_v, d_v,
                   [](const T& a, const T& b) { return a + b; });
    d_->SetOnlineFinished();
  }

  d_output_->WaitOnline();

  const auto& d_clear = d_output_->GetOutputWires().at(0);

  d_clear->GetIsReadyCondition().Wait();

  const auto d_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(d_clear);
  const auto x_i_w = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));

  assert(d_w);
  assert(x_i_w);

  auto output = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(output);
  output->GetMutableValues() =
      std::vector<T>(sps.c.begin() + sp_offset_,
                     sps.c.begin() + sp_offset_ + parent_.at(0)->GetNumberOfSimdValues());

  const T* __restrict__ d{d_w->GetValues().data()};
  const T* __restrict__ s_x{x_i_w->GetValues().data()};
  T* __restrict__ output_pointer{output->GetMutableValues().data()};
  if (GetCommunicationLayer().GetMyId() ==
      (gate_id_ % GetCommunicationLayer().GetNumberOfParties())) {
    for (auto i = 0ull; i < output->GetNumberOfSimdValues(); ++i) {
      output_pointer[i] += 2 * (d[i] * s_x[i]) - (d[i] * d[i]);
    }
  } else {
    for (auto i = 0ull; i < output->GetNumberOfSimdValues(); ++i) {
      output_pointer[i] += 2 * (d[i] * s_x[i]);
    }
  }

  GetLogger().LogDebug(fmt::format("Evaluated arithmetic_gmw::SquareGate with id#{}", gate_id_));
}

template <typename T>
arithmetic_gmw::SharePointer<T> SquareGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
  assert(arithmetic_wire);
  auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
  return result;
}

template class SquareGate<std::uint8_t>;
template class SquareGate<std::uint16_t>;
template class SquareGate<std::uint32_t>;
template class SquareGate<std::uint64_t>;
template class SquareGate<__uint128_t>;

template <typename T>
GreaterThanGate<T>::GreaterThanGate(arithmetic_gmw::WirePointer<T>& a,
                                    arithmetic_gmw::WirePointer<T>& b, std::size_t l_s)
    : TwoGate(a->GetBackend()), chunk_bit_length_(l_s) {
  parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
  parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

  assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

  // the plaintext numbers have to be smaller than 2^{bit_length - 1}
  assert(parent_a_.at(0)->GetBitLength() == parent_b_.at(0)->GetBitLength());
  auto bit_length = parent_a_.at(0)->GetBitLength();

  const auto& communication_layer = GetCommunicationLayer();
  number_of_parties_ = communication_layer.GetNumberOfParties();
  number_of_simd_ = parent_a_.at(0)->GetNumberOfSimdValues();
  my_id_ = communication_layer.GetMyId();

  output_wires_ = {
      GetRegister().template EmplaceWire<boolean_gmw::Wire>(backend_, number_of_simd_)};

  auto number_of_intermediate_iterations = 0u;  // how many times while-loop will run
  auto ot_bit_length = chunk_bit_length_ - 1;
  if (my_id_ == 0) {
    // register party 0 as receiver for 1ooN-OT
    if (bit_length > chunk_bit_length_) {
      number_of_intermediate_iterations = std::ceil(
          static_cast<float>(bit_length - 1 - chunk_bit_length_) / (chunk_bit_length_ - 1));
      ot_1oon_receiver_.push_back(
          GetKk13OtProvider(1).RegisterReceiveGOtBit(number_of_simd_, pow(2, chunk_bit_length_)));
    }

    for (auto i = 0u; i < number_of_intermediate_iterations; i++) {
      // number of messages of the last iterations
      if (i == number_of_intermediate_iterations - 1) {
        ot_bit_length =
            bit_length - 2 - number_of_intermediate_iterations * (chunk_bit_length_ - 1);
      }
      ot_1oon_receiver_.push_back(
          GetKk13OtProvider(1).RegisterReceiveGOtBit(number_of_simd_, 2 * pow(2, ot_bit_length)));
    }
  } else {
    // register party 1 as sender for 1ooN-OT
    if (bit_length > chunk_bit_length_) {
      number_of_intermediate_iterations = std::ceil(
          static_cast<float>(bit_length - 1 - chunk_bit_length_) / (chunk_bit_length_ - 1));
      ot_1oon_sender_.push_back(
          GetKk13OtProvider(0).RegisterSendGOtBit(number_of_simd_, pow(2, chunk_bit_length_)));
    }

    for (auto i = 0u; i < number_of_intermediate_iterations; i++) {
      // number of messages of the last iterations
      if (i == number_of_intermediate_iterations - 1) {
        ot_bit_length =
            bit_length - 2 - number_of_intermediate_iterations * (chunk_bit_length_ - 1);
      }
      ot_1oon_sender_.push_back(
          GetKk13OtProvider(0).RegisterSendGOtBit(number_of_simd_, 2 * pow(2, ot_bit_length)));
    }
  }

  auto gate_info =
      fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                  parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  GetLogger().LogDebug(fmt::format(
      "Created an arithmetic_gmw::GreaterThanGate with following properties: {}", gate_info));
}

template <typename T>
void GreaterThanGate<T>::RunSender1ooNOt(encrypto::motion::BitVector<> messages,
                                         std::size_t ot_index) {
  ot_1oon_sender_[ot_index]->WaitSetup();

  ot_1oon_sender_[ot_index]->SetInputs(messages);
  ot_1oon_sender_[ot_index]->SendMessages();
}

template <typename T>
BitVector<> GreaterThanGate<T>::RunReceiver1ooNOt(std::vector<std::uint8_t> selection_index,
                                               std::size_t ot_index) {
  ot_1oon_receiver_[ot_index]->WaitSetup();

  ot_1oon_receiver_[ot_index]->SetChoices(selection_index);
  ot_1oon_receiver_[ot_index]->SendCorrections();

  ot_1oon_receiver_[ot_index]->ComputeOutputs();
  return ot_1oon_receiver_[ot_index]->GetOutputs();
}

template <typename T>
void GreaterThanGate<T>::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  parent_a_.at(0)->GetIsReadyCondition().Wait();
  parent_b_.at(0)->GetIsReadyCondition().Wait();

  auto bit_length = parent_a_.at(0)->GetBitLength();

  const auto a = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
  const auto b = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));
  assert(a);
  assert(b);

  auto a_values = a->GetValues();
  auto b_values = b->GetValues();

  // some variables for the protocol
  std::size_t number_of_messages, ot_index = 0;
  BitVector<> r, c(number_of_simd_), messages;
  std::vector<std::uint8_t> selection_index(number_of_simd_);

  // step 3
  std::vector<T> delta(number_of_simd_);
  std::vector<BitSpan> delta_bs(number_of_simd_);
  for (auto i = 0u; i < number_of_simd_; i++) {
    delta.at(i) = b_values.at(i) - a_values.at(i);
    delta_bs.at(i) = BitSpan(reinterpret_cast<std::byte*>(&delta.at(i)), sizeof(delta.at(i)) * 8);
  }

  // step 4
  std::size_t bit_length_last = 0;

  // step 5
  if (bit_length > chunk_bit_length_) {
    number_of_messages = pow(2, chunk_bit_length_);

    // step 8
    if (my_id_ == 1) {
      r = BitVector<>::SecureRandom(number_of_simd_);
    }

    for (auto i = 0u; i < number_of_simd_; i++) {
      auto delta_subset = delta_bs.at(i).Subset(0, chunk_bit_length_);
      auto delta_subset_value = static_cast<std::uint8_t>(delta_subset.GetMutableData()[0]);

      if (my_id_ == 0) {
        // step 6
        selection_index.at(i) = delta_subset_value;
      } else {
        // step 7 : check whether (j + delta_subset_value) > number_of_messages for j from 1 to
        // number_of_messages
        auto number_of_zeros = number_of_messages - delta_subset_value;
        auto number_of_ones = delta_subset_value;

        BitVector<> this_ot_messages = BitVector<>(number_of_zeros, false);
        this_ot_messages.Append(BitVector<>(number_of_ones, true));

        this_ot_messages ^= BitVector<>(number_of_messages, r.Get(i));
        messages.Append(this_ot_messages);
      }
    }

    // step 9
    if (my_id_ == 0) {
      c = RunReceiver1ooNOt(selection_index, ot_index);
    } else {
      RunSender1ooNOt(messages, ot_index);
    }

    // step 10
    bit_length_last = chunk_bit_length_;
  }

  // step 11
  while (bit_length_last < bit_length - 1) {
    ot_index++;
    messages.Clear();

    // step 12
    auto bit_length_difference = std::min(chunk_bit_length_ - 1, bit_length - bit_length_last - 1);
    number_of_messages = pow(2, bit_length_difference);

    // step 13
    auto bit_length_next = bit_length_last + bit_length_difference;

    // step 20 : save randomized r in another variable, because r is still needed in step 19
    BitVector<> r_for_xor;
    if (my_id_ == 1) {
      r_for_xor = BitVector<>::SecureRandom(number_of_simd_);
    }

    for (auto i = 0u; i < number_of_simd_; i++) {
      auto delta_subset = delta_bs.at(i).Subset(bit_length_last, bit_length_next);
      auto delta_subset_value = static_cast<std::uint8_t>(delta_subset.GetMutableData()[0]);

      if (my_id_ == 0) {
        // step 14
        selection_index.at(i) = delta_subset_value;

        // step 15
        selection_index.at(i) += (c.Get(i) ? number_of_messages : 0);
      } else {
        // step 16-19 : check whether (j + delta_subset_value) > number_of_messages and/or (j +
        // delta_subset_value + 1) > number_of_messages for j from 1 to number_of_messages and
        // append to messages according to r
        auto number_of_zeros = number_of_messages - delta_subset_value;
        auto number_of_ones = delta_subset_value;

        BitVector<> this_ot_messages;
        if (!r.Get(i)) {
          this_ot_messages = BitVector<>(number_of_zeros, false);
          this_ot_messages.Append(BitVector<>(number_of_ones, true));
          this_ot_messages.Append(BitVector<>(number_of_zeros - 1, false));
          this_ot_messages.Append(BitVector<>(number_of_ones + 1, true));
        } else {
          this_ot_messages = BitVector<>(number_of_zeros - 1, false);
          this_ot_messages.Append(BitVector<>(number_of_ones + 1, true));
          this_ot_messages.Append(BitVector<>(number_of_zeros, false));
          this_ot_messages.Append(BitVector<>(number_of_ones, true));
        }

        this_ot_messages ^= BitVector<>(2 * number_of_messages, r_for_xor.Get(i));
        messages.Append(this_ot_messages);
      }
    }

    // step 21
    if (my_id_ == 0) {
      c = RunReceiver1ooNOt(selection_index, ot_index);
    } else {
      RunSender1ooNOt(messages, ot_index);
    }

    // step 22
    bit_length_last = bit_length_next;

    r = r_for_xor;
  }

  // step 23
  BitVector<> output_vector(number_of_simd_);
  for (auto i = 0u; i < number_of_simd_; i++) {
    auto output = ((my_id_ == 0) ? c.Get(i) : r.Get(i)) != delta_bs.at(i).Get(bit_length - 1);
    output_vector.Set(output, i);
  }

  // place the output in output_wires_
  auto output_wire = std::dynamic_pointer_cast<boolean_gmw::Wire>(output_wires_.at(0));
  assert(output_wire);
  output_wire->GetMutableValues() = output_vector;

  GetLogger().LogDebug(
      fmt::format("Evaluated arithmetic_gmw::GreaterThanGate with id#{}", gate_id_));
}

template <typename T>
const boolean_gmw::SharePointer GreaterThanGate<T>::GetOutputAsGmwShare() {
  auto result = std::make_shared<boolean_gmw::Share>(output_wires_);
  assert(result);
  return result;
}

template class GreaterThanGate<std::uint8_t>;
template class GreaterThanGate<std::uint16_t>;
template class GreaterThanGate<std::uint32_t>;
template class GreaterThanGate<std::uint64_t>;
template class GreaterThanGate<__uint128_t>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
