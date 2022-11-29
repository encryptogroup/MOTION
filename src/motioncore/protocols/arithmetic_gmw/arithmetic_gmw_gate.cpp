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
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
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

// added by Liang Zhao
template class MultiplicationGate<__uint128_t>;

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

// added by Liang Zhao
template class HybridMultiplicationGate<__uint128_t>;

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

template <typename T>
ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::
    ReconstructArithmeticGmwShareAndBitDecomposeGate(const arithmetic_gmw::WirePointer<T>& parent,
                                                     std::size_t output_owner)
    : OneGate(parent->GetBackend()) {
  // std::cout << "ReconstructArithmeticGmwShareAndBitDecomposeGate" << std::endl;
  assert(parent);
  // assert(parent_R);

  if (parent->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    auto sharing_type = to_string(parent->GetProtocol());
    throw(std::runtime_error(
        (fmt::format("ReconstructArithmeticGmwShareAndBitDecomposeGate expects an "
                     "arithmetic share, "
                     "got a share of type {}",
                     sharing_type))));
  }

  parent_ = {parent};

  // TODO should support SIMD now
  num_of_simd_ = parent_[0]->GetNumberOfSimdValues();

  // values we need repeatedly
  auto& communication_layer = GetCommunicationLayer();
  auto my_id = communication_layer.GetMyId();
  auto number_of_parties = communication_layer.GetNumberOfParties();

  // create boolean output wires
  // constexpr auto number_of_wires{sizeof(T) * 8};
  bit_size_ = sizeof(T) * 8;
  // std::cout << "number_of_wires: " << bit_size_ << std::endl;

  // requires_online_interaction_ = true;
  // gate_type_ = GateType::kInteractive;

  // create the arithmetic output wires
  arithmetic_output_wires_.emplace_back(
      GetRegister().template EmplaceWire<motion::proto::arithmetic_gmw::Wire<T>>(backend_,
                                                                                 num_of_simd_));
  arithmetic_output_wires_.at(0)->SetAsPubliclyKnownWire();

  // GetRegister().RegisterNextWire(arithmetic_output_wires_.at(0));

  // create the boolean output wires
  boolean_output_wires_.reserve(bit_size_);
  for (size_t i = 0; i < bit_size_; i++) {
    // auto& w = boolean_output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
    // std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));

    boolean_output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
        GetRegister().template EmplaceWire<boolean_gmw::Wire>(backend_, num_of_simd_)));

    boolean_output_wires_.at(i)->SetAsPubliclyKnownWire();
    // GetRegister().RegisterNextWire(w);
  }

  // create the output gate to reconstruct the arithmetic input
  auto arithmetic_input_wire =
      std::dynamic_pointer_cast<motion::proto::arithmetic_gmw::Wire<T>>(parent_.at(0));
  arithmetic_reconstruct_gate_ =
      GetRegister().template EmplaceGate<motion::proto::arithmetic_gmw::OutputGate<T>>(
          arithmetic_input_wire);
  // GetRegister().RegisterNextGate(arithmetic_reconstruct_gate_);

  // // register this gate
  // gate_id_ = GetRegister().NextGateId();

  // // register this gate with the parent_ wires
  // for (auto& wire : parent_) {
  //   RegisterWaitingFor(wire->GetWireId());
  //   wire->RegisterWaitingGate(gate_id_);
  // }

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}", gate_id_);
    GetLogger().LogDebug(
        fmt::format("Allocate an ReconstructArithmeticGmwShareAndBitDecomposeGate with following "
                    "properties: {}",
                    gate_info));
  }
}

template <typename T>
ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::
    ReconstructArithmeticGmwShareAndBitDecomposeGate(const arithmetic_gmw::SharePointer<T>& parent,
                                                     std::size_t output_owner)
    : ReconstructArithmeticGmwShareAndBitDecomposeGate(parent->GetArithmeticWire(), output_owner) {
  assert(parent);
}

template <typename T>
void ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::EvaluateSetup() {}

template <typename T>
void ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::EvaluateOnline() {
  // nothing to setup, no need to wait/check

  // // data we need repeatedly
  // auto& communication_layer = GetCommunicationLayer();
  // auto my_id = communication_layer.GetMyId();
  // auto number_of_parties = communication_layer.GetNumberOfParties();

  // // note that arithmetic gates have only a single wire
  // auto arithmetic_wire = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));
  // assert(arithmetic_wire);
  // // wait for parent wire to obtain a value
  // arithmetic_wire->GetIsReadyCondition().Wait();

  // wait for output gate to reconstruct
  arithmetic_reconstruct_gate_->WaitOnline();
  const auto arithmetic_reconstruct_share =
      arithmetic_reconstruct_gate_->GetOutputAsArithmeticShare();
  const auto& reconstruct_wire = arithmetic_reconstruct_share->GetWires().at(0);
  const auto arithmetic_reconstruct_wire =
      std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(reconstruct_wire);

  // assign reconstructed value to arithmetic_output_wire
  auto arithmetic_output_wire =
      std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_output_wires_.at(0));
  assert(arithmetic_output_wire);
  arithmetic_output_wire->GetMutableValues() = arithmetic_reconstruct_wire->GetValues();

  // arithmetic_output_wire->SetAsPubliclyKnownWire();
  arithmetic_output_wire->SetOnlineFinished();

  // bit-decompose the reconstructed arithmetic value into Boolean bits
  std::vector<BitVector<>> boolean_output;
  boolean_output = ToInput<T>(arithmetic_output_wire->GetValues());

  // std::cout << "reconstructed_arithmetic_output_wire: "
  //           << arithmetic_output_wire->GetValues().at(0) << std::endl;
  // std::cout << "reconstructed_boolean_output.at(i).Get(0): " << std::endl;
  for (auto i = 0ull; i < bit_size_; i++) {
    // for (std::size_t j = 0ull; j < num_of_simd_; j++) {
    // boolean_output.emplace_back(1, ((arithmetic_output_wire->GetValues().at(j) >> i) & 1) ==
    // 1); std::cout << boolean_output.at(i).Get(0);
    auto boolean_output_wire =
        std::dynamic_pointer_cast<boolean_gmw::Wire>(boolean_output_wires_.at(i));
    // }
    boolean_output_wire->GetMutableValues() = boolean_output.at(i);

    // boolean_output_wire->SetAsPubliclyKnownWire();
    boolean_output_wire->SetOnlineFinished();
  }
  // std::cout << std::endl;

  // std::cout << "reconstructed_boolean_output_ reverse order: " << std::endl;
  // for (auto i = 0ull; i < bit_size_; i++) {
  // std::cout << boolean_output.at(bit_size_ - 1 - i).Get(0);
  // }

  // std::cout << "SetOnlineIsReady: " << std::endl;
  //    SetOnlineIsReady();
  // {
  //   std::scoped_lock lock(online_is_ready_condition_.GetMutex());
  //   online_is_ready_ = true;
  // }
  // online_is_ready_condition_.NotifyAll();
  // GetRegister().IncrementEvaluatedGatesOnlineCounter();
  // std::cout << "Evaluate online finish: " << std::endl;
}

template <typename T>
const motion::proto::boolean_gmw::SharePointer
ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::GetOutputAsBooleanGmwValue() {
  auto boolean_output_share =
      std::make_shared<motion::proto::boolean_gmw::Share>(boolean_output_wires_);
  assert(boolean_output_share);
  // auto output_share = std::static_pointer_cast<motion::Share>(boolean_output_share);
  // assert(output_share);
  boolean_output_share->SetAsPubliclyKnownShare();
  return boolean_output_share;
}

template <typename T>
const arithmetic_gmw::SharePointer<T>
ReconstructArithmeticGmwShareAndBitDecomposeGate<T>::GetOutputAsArithmeticGmwValue() {
  auto arithmetic_output_wire =
      std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_output_wires_.at(0));
  assert(arithmetic_output_wire);
  auto arithmetic_output_share = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
  arithmetic_output_share->SetAsPubliclyKnownShare();
  return arithmetic_output_share;
}

template class ReconstructArithmeticGmwShareAndBitDecomposeGate<std::uint8_t>;
template class ReconstructArithmeticGmwShareAndBitDecomposeGate<std::uint16_t>;
template class ReconstructArithmeticGmwShareAndBitDecomposeGate<std::uint32_t>;
template class ReconstructArithmeticGmwShareAndBitDecomposeGate<std::uint64_t>;
template class ReconstructArithmeticGmwShareAndBitDecomposeGate<__uint128_t>;

// added by Liang Zhao
template <typename T>
edaBitGate<T>::edaBitGate(Backend& backend, std::size_t bit_size, std::size_t num_of_simd)
    : Gate(backend) {
  num_of_simd_ = num_of_simd;

  // only generate edaBits of size bit_size,
  // the rest bits (size: total_bit_size_-bit_size) are set to constant value of zero
  bit_size_ = bit_size;

  total_bit_size_ = sizeof(T) * 8;

  // requires_online_interaction_ = false;
  // gate_type_ = GateType::kNonInteractive;

  // create, initialize, and register the output wires in following part:
  arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_.reserve(1);

  std::vector<arithmetic_gmw::WirePointer<T>> constant_arithmetic_gmw_output_wires_of_value_zero;
  constant_arithmetic_gmw_output_wires_of_value_zero.reserve(total_bit_size_);

  // arithmetic_gmw_output_wire_r_vector_.emplace_back(
  //     std::make_shared<arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));
  // GetRegister().RegisterNextWire(arithmetic_gmw_output_wire_r_vector_.at(0));
  arithmetic_gmw_output_wire_r_vector_.emplace_back(
      GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));

  boolean_gmw_output_wire_r_vector_.reserve(total_bit_size_);
  for (std::size_t i = 0; i < total_bit_size_; i++) {
    // boolean_gmw_output_wire_r_vector_.emplace_back(std::static_pointer_cast<motion::Wire>(
    //     std::make_shared<motion::proto::boolean_gmw::Wire>(backend_, num_of_simd_)));
    boolean_gmw_output_wire_r_vector_.emplace_back(
        GetRegister().template EmplaceWire<motion::proto::boolean_gmw::Wire>(backend_,
                                                                             num_of_simd_));

    auto boolean_gmw_output_wire_r =
        std::dynamic_pointer_cast<boolean_gmw::Wire>(boolean_gmw_output_wire_r_vector_.at(i));
    boolean_gmw_output_wire_r->GetMutableValues() = BitVector<>(num_of_simd_, false);

    auto& arithmetic_gmw_output_wire_of_each_bit =
        constant_arithmetic_gmw_output_wires_of_value_zero.emplace_back(
            GetRegister().template EmplaceWire<arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));

    // // only register the gates that have non-zero values
    // GetRegister().RegisterNextWire(boolean_gmw_output_wire_r);
    // GetRegister().RegisterNextWire(arithmetic_gmw_output_wire_of_each_bit);

    arithmetic_gmw_output_wire_of_each_bit->GetMutableValues() = std::vector<T>(num_of_simd_, T(0));
  }

  arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_.push_back(
      constant_arithmetic_gmw_output_wires_of_value_zero);

  // register the required number of shared bits
  num_of_sbs_ = num_of_simd_ * bit_size_;
  sb_offset_ = GetSbProvider().template RequestSbs<T>(num_of_sbs_);

  // // register this gate
  // gate_id_ = GetRegister().NextGateId();

  if constexpr (kDebug) {
    auto gate_info = fmt::format("gate id {}, total_bit_size {}, bit_size {}", gate_id_,
                                 total_bit_size_, bit_size_);

    gate_info.append(fmt::format("arithmetic gmw output wire: {} ",
                                 arithmetic_gmw_output_wire_r_vector_.at(0)->GetWireId()));

    for (const auto& boolean_wire : boolean_gmw_output_wire_r_vector_) {
      gate_info.append(fmt::format("boolean gmw output wire: {} ", boolean_wire->GetWireId()));
    }

    GetLogger().LogDebug(
        fmt::format("Created a edaBitGate with following properties: {}", gate_info));
  }
}

template <typename T>
void edaBitGate<T>::EvaluateSetup() {
  // SetSetupIsReady();
  // GetRegister().IncrementEvaluatedGatesSetupCounter();
}

template <typename T>
void edaBitGate<T>::EvaluateOnline() {
  // std::cout << "edaBitGate<T>::EvaluateOnline" << std::endl;
  // WaitSetup();
  // assert(setup_is_ready_);

  // wait for the SbProvider to finish
  auto& sb_provider = GetSbProvider();
  sb_provider.WaitFinished();

  // extrate shared bits and assign it to <r>^B = (<r_0>^B, ..., <r_l>^B) to
  // boolean_gmw_output_wire_r_vector_
  const auto& sbs = sb_provider.template GetSbsAll<T>();
  for (auto wire_i = 0ull; wire_i < total_bit_size_; wire_i++) {
    auto boolean_gmw_output_wire_r =
        std::dynamic_pointer_cast<boolean_gmw::Wire>(boolean_gmw_output_wire_r_vector_.at(wire_i));
    for (std::size_t j = 0; j < num_of_simd_; ++j) {
      bool sb = false;
      if (wire_i < bit_size_) {
        sb = sbs.at(sb_offset_ + wire_i * num_of_simd_ + j) & 1;  // the Boolean(ly) shared bit}
      }
      boolean_gmw_output_wire_r->GetMutableValues().Set(sb, j);
    }
    boolean_gmw_output_wire_r->SetOnlineFinished();
  }

  // std::cout << "000" << std::endl;
  // std::cout << "<r>^B (reverse order): " << std::endl;

  // for (auto wire_i = 0ull; wire_i < bit_size_; wire_i++) {
  //   bool sb = sbs.at(sb_offset_ + (bit_size_ - 1 - wire_i) * num_of_simd_) &
  // 1;  // the Boolean(ly) shared bit
  // std::cout << sb;
  // }
  // std::cout << std::endl;

  // calculate <r>^A = B2A(<r>^B) and assign it to arithmetic_gmw_output_wire_r_vector_
  auto arithmetic_gmw_output_wire_r = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
      arithmetic_gmw_output_wire_r_vector_.at(0));
  arithmetic_gmw_output_wire_r->GetMutableValues().resize(num_of_simd_);

  for (std::size_t j = 0; j < num_of_simd_; ++j) {
    T arithmetic_value_r = 0;
    for (std::size_t wire_i = 0ull; wire_i < total_bit_size_; wire_i++) {
      T r = 0;
      if (wire_i < bit_size_) {
        r = (sbs.at(sb_offset_ + wire_i * num_of_simd_ + j));
      }
      arithmetic_value_r += T(r) << wire_i;
      auto arithmetic_gmw_output_wire_of_each_bit =
          std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
              arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_.at(0).at(wire_i));
      arithmetic_gmw_output_wire_of_each_bit->GetMutableValues().at(j) = T(r);
    }
    // std::cout << "111" << std::endl;
    arithmetic_gmw_output_wire_r->GetMutableValues().at(j) = arithmetic_value_r;
  }
  // std::cout << "222" << std::endl;
  arithmetic_gmw_output_wire_r->SetOnlineFinished();
  // std::cout << "333" << std::endl;

  for (std::size_t wire_i = 0ull; wire_i < total_bit_size_; wire_i++) {
    auto arithmetic_gmw_output_wire_of_each_bit =
        std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
            arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_.at(0).at(wire_i));
    arithmetic_gmw_output_wire_of_each_bit->SetOnlineFinished();
  }

  GetLogger().LogDebug(fmt::format("Evaluated edaBitGate with id#{}", gate_id_));
  // SetOnlineIsReady();
  // set online condition ready
  // {
  //   // std::cout << "444" << std::endl;
  //   std::scoped_lock lock(online_is_ready_condition_.GetMutex());
  //   online_is_ready_ = true;
  //   // std::cout << "555" << std::endl;
  // }
  // // std::cout << "666" << std::endl;
  // online_is_ready_condition_.NotifyAll();
  // // std::cout << "777" << std::endl;

  // GetRegister().IncrementEvaluatedGatesOnlineCounter();
}

template <typename T>
arithmetic_gmw::SharePointer<T> edaBitGate<T>::GetOutputAsArithmeticShare() {
  auto arithmetic_gmw_output_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
      arithmetic_gmw_output_wire_r_vector_.at(0));
  auto arithmetic_gmw_output_share =
      std::make_shared<proto::arithmetic_gmw::Share<T>>(arithmetic_gmw_output_wire);
  assert(arithmetic_gmw_output_share);
  return arithmetic_gmw_output_share;
}

template <typename T>
motion::proto::boolean_gmw::SharePointer edaBitGate<T>::GetOutputAsBooleanShare() {
  auto boolean_gmw_output_share =
      std::make_shared<motion::proto::boolean_gmw::Share>(boolean_gmw_output_wire_r_vector_);
  assert(boolean_gmw_output_share);
  return boolean_gmw_output_share;
}

// added by Liang Zhao
template <typename T>
std::vector<motion::SharePointer> edaBitGate<T>::GetOutputAsArithmeticShareOfEachBit() {
  std::vector<motion::SharePointer> arithmetic_gmw_output_share_vector;
  arithmetic_gmw_output_share_vector.reserve(total_bit_size_);
  for (auto wire_i = 0ull; wire_i < total_bit_size_; wire_i++) {
    auto arithmetic_gmw_output_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
        arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_.at(0).at(wire_i));
    auto arithmetic_gmw_output_share =
        std::make_shared<proto::arithmetic_gmw::Share<T>>(arithmetic_gmw_output_wire);
    assert(arithmetic_gmw_output_share);

    arithmetic_gmw_output_share_vector.emplace_back(
        std::dynamic_pointer_cast<motion::Share>(arithmetic_gmw_output_share));
  }
  return arithmetic_gmw_output_share_vector;
}

template class edaBitGate<std::uint8_t>;
template class edaBitGate<std::uint16_t>;
template class edaBitGate<std::uint32_t>;
template class edaBitGate<std::uint64_t>;

// should support now
template class edaBitGate<__uint128_t>;

// // added by Liang Zhao
// template <typename T, typename U>
// OutputInLargerFieldGate<T, U>::OutputInLargerFieldGate(const arithmetic_gmw::WirePointer<T>&
// parent,
//                                                        std::size_t output_owner)
//     : Base(parent->GetBackend()) {
//   assert(parent);

//   if (parent->GetProtocol() != MpcProtocol::kArithmeticGmw) {
//     auto sharing_type = to_string(parent->GetProtocol());
//     throw(std::runtime_error(
//         (fmt::format("Arithmetic output gate in large field gate expects an arithmetic share, "
//                      "got a share of type {}",
//                      sharing_type))));
//   }

//   parent_ = {parent};

//   // values we need repeatedly
//   auto& communication_layer = GetCommunicationLayer();
//   auto my_id = communication_layer.GetMyId();
//   auto number_of_parties = communication_layer.GetNumberOfParties();

//   if (static_cast<std::size_t>(output_owner) >= number_of_parties &&
//       static_cast<std::size_t>(output_owner) != kAll) {
//     throw std::runtime_error(
//         fmt::format("Invalid output owner: {} of {}", output_owner, number_of_parties));
//   }

//   output_owner_ = output_owner;
//   requires_online_interaction_ = true;
//   gate_type_ = GateType::kInteractive;
//   gate_id_ = GetRegister().NextGateId();
//   is_my_output_ = my_id == static_cast<std::size_t>(output_owner_) ||
//                   static_cast<std::size_t>(output_owner_) == kAll;

//   RegisterWaitingFor(parent_.at(0)->GetWireId());
//   parent_.at(0)->RegisterWaitingGate(gate_id_);

//   {
//     auto w = std::static_pointer_cast<motion::Wire>(
//         std::make_shared<arithmetic_gmw::Wire<U>>(backend_, parent->GetNumberOfSimdValues()));
//     GetRegister().RegisterNextWire(w);
//     w->SetAsPubliclyKnownWire();
//     output_wires_ = {std::move(w)};
//   }

//   // Tell the DataStorages that we want to receive OutputMessages from the
//   // other parties.
//   if (is_my_output_) {
//     auto& base_provider = GetBaseProvider();
//     output_message_futures_ = base_provider.RegisterForOutputMessages(gate_id_);
//   }

//   if constexpr (kDebug) {
//     auto gate_info =
//         fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
//         output_owner_);
//     GetLogger().LogDebug(fmt::format(
//         "Allocate an arithmetic_gmw::OutputInLargerFieldGate with following properties: {}",
//         gate_info));
//   }
// }

// template <typename T, typename U>
// OutputInLargerFieldGate<T, U>::OutputInLargerFieldGate(
//     const arithmetic_gmw::SharePointer<T>& parent, std::size_t output_owner)
//     : OutputInLargerFieldGate(parent->GetArithmeticWire(), output_owner) {
//   assert(parent);
// }

// template <typename T, typename U>
// OutputInLargerFieldGate<T, U>::OutputInLargerFieldGate(const motion::SharePointer& parent,
//                                                        std::size_t output_owner)
//     : OutputInLargerFieldGate(std::dynamic_pointer_cast<arithmetic_gmw::Share<T>>(parent),
//                               output_owner) {
//   assert(parent);
// }

// template <typename T, typename U>
// void OutputInLargerFieldGate<T, U>::EvaluateSetup() {
//   SetSetupIsReady();
//   GetRegister().IncrementEvaluatedGatesSetupCounter();
// }

// template <typename T, typename U>
// void OutputInLargerFieldGate<T, U>::EvaluateOnline() {
//   // setup needs to be done first
//   WaitSetup();
//   assert(setup_is_ready_);

//   // data we need repeatedly
//   auto& communication_layer = GetCommunicationLayer();
//   auto my_id = communication_layer.GetMyId();
//   auto number_of_parties = communication_layer.GetNumberOfParties();

//   // note that arithmetic gates have only a single wire
//   auto arithmetic_wire = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));
//   assert(arithmetic_wire);
//   // wait for parent wire to obtain a value
//   arithmetic_wire->GetIsReadyCondition().Wait();
//   // initialize output with local share
//   auto output_of_type_T = arithmetic_wire->GetValues();

//   // create output of type U (large field)
//   std::vector<U> output_of_type_U(output_of_type_T.cbegin(), output_of_type_T.cend());

//   // we need to send shares to one other party:
//   if (!is_my_output_) {
//     auto payload = ToByteVector(output_of_type_T);
//     auto output_message = motion::communication::BuildOutputMessage(gate_id_, payload);
//     communication_layer.SendMessage(output_owner_, std::move(output_message));
//   }
//   // we need to send shares to all other parties:
//   else if (output_owner_ == kAll) {
//     auto payload = ToByteVector(output_of_type_T);
//     auto output_message = motion::communication::BuildOutputMessage(gate_id_, payload);
//     communication_layer.BroadcastMessage(std::move(output_message));
//   }

//   // we receive shares from other parties
//   if (is_my_output_) {
//     // collect shares from all parties
//     std::vector<std::vector<T>> shared_outputs_of_type_T;
//     shared_outputs_of_type_T.reserve(number_of_parties);

//     // convert the data type of shared_outputs from T to U
//     std::vector<std::vector<U>> shared_outputs_of_type_U;
//     shared_outputs_of_type_U.reserve(number_of_parties);

//     for (std::size_t i = 0; i < number_of_parties; ++i) {
//       if (i == my_id) {
//         shared_outputs_of_type_T.push_back(output_of_type_T);
//         shared_outputs_of_type_U.push_back(output_of_type_U);
//         continue;
//       }
//       const auto output_message = output_message_futures_.at(i).get();
//       auto message = communication::GetMessage(output_message.data());
//       auto output_message_pointer = communication::GetOutputMessage(message->payload()->data());
//       assert(output_message_pointer);
//       assert(output_message_pointer->wires()->size() == 1);

//       std::vector<T> data_vector_of_type_T =
//           FromByteVector<T>(*output_message_pointer->wires()->Get(0)->payload());
//       shared_outputs_of_type_T.push_back(data_vector_of_type_T);
//       std::vector<U> data_vector_of_type_U(data_vector_of_type_T.cbegin(),
//                                            data_vector_of_type_T.cend());
//       shared_outputs_of_type_U.push_back(data_vector_of_type_U);

//       assert(shared_outputs_of_type_T[i].size() == parent_[0]->GetNumberOfSimdValues());
//       assert(shared_outputs_of_type_U[i].size() == parent_[0]->GetNumberOfSimdValues());
//     }

//     // reconstruct the shared value in larger field U
//     if constexpr (kVerboseDebug) {
//       // we need to copy since we have to keep shared_outputs for the debug output below
//       output_of_type_U = AddVectors(shared_outputs_of_type_U);
//     } else {
//       // we can move
//       output_of_type_U = AddVectors(std::move(shared_outputs_of_type_U));
//     }

//     // set the value of the output wire
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     arithmetic_output_wire->GetMutableValues() = output_of_type_U;

//     // std::cout << "shared_outputs_of_type_T: " << unsigned(shared_outputs_of_type_T[0][0]) <<
//     // std::endl;

//     if constexpr (kVerboseDebug) {
//       std::string shares{""};
//       for (auto i = 0u; i < number_of_parties; ++i) {
//         shares.append(fmt::format("id#{}:{} ", i, to_string(shared_outputs_of_type_U.at(i))));
//       }
//       auto result = to_string(output_of_type_U);
//       GetLogger().LogTrace(
//           fmt::format("Received output shares: {} from other parties, "
//                       "reconstructed result is {}",
//                       shares, result));
//     }
//   }

//   // we are done with this gate
//   if constexpr (kDebug) {
//     GetLogger().LogDebug(
//         fmt::format("Evaluated arithmetic_gmw::OutputInLargerFieldGate with id#{}", gate_id_));
//   }
//   SetOnlineIsReady();
//   GetRegister().IncrementEvaluatedGatesOnlineCounter();
// }

// template <typename T, typename U>
// arithmetic_gmw::SharePointer<U> OutputInLargerFieldGate<T, U>::GetOutputAsArithmeticShare() {
//   auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<U>>(output_wires_.at(0));
//   assert(arithmetic_wire);
//   auto result = std::make_shared<arithmetic_gmw::Share<U>>(arithmetic_wire);
//   return result;
// }

// template class OutputInLargerFieldGate<std::uint8_t, std::uint16_t>;
// template class OutputInLargerFieldGate<std::uint16_t, std::uint32_t>;
// template class OutputInLargerFieldGate<std::uint32_t, std::uint64_t>;
// template class OutputInLargerFieldGate<std::uint64_t, __uint128_t>;

}  // namespace encrypto::motion::proto::arithmetic_gmw
