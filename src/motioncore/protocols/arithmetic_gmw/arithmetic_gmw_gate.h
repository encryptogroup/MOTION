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

#pragma once

#include <fmt/format.h>

#include "arithmetic_gmw_share.h"
#include "base/motion_base_provider.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"
#include "communication/output_message.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "primitives/sharing_randomness_generator.h"
#include "protocols/gate.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "utility/reusable_future.h"

namespace encrypto::motion::proto::arithmetic_gmw {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new arithmetic_gmw::Share) output
//

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::span<const T> input, std::size_t input_owner, Backend& backend)
      : Base(backend), input_(std::vector(input.begin(), input.end())) {
    input_owner_id_ = input_owner;
    InitializationHelper();
  }

  InputGate(std::vector<T>&& input, std::size_t input_owner, Backend& backend)
      : Base(backend), input_(std::move(input)) {
    input_owner_id_ = input_owner;
    InitializationHelper();
  }

  void InitializationHelper() {
    static_assert(!std::is_same_v<T, bool>);

    gate_id_ = GetRegister().NextGateId();
    arithmetic_sharing_id_ = GetRegister().NextArithmeticSharingId(input_.size());
    if constexpr (kVerboseDebug) {
      GetLogger().LogTrace(
          fmt::format("Created an arithmetic_gmw::InputGate with global id {}", gate_id_));
    }
    output_wires_ = {std::static_pointer_cast<motion::Wire>(
        std::make_shared<arithmetic_gmw::Wire<T>>(input_, backend_))};
    for (auto& w : output_wires_) {
      GetRegister().RegisterNextWire(w);
    }

    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                 input_owner_id_);
    GetLogger().LogDebug(fmt::format(
        "Allocate an arithmetic_gmw::InputGate with following properties: {}", gate_info));
  }

  ~InputGate() final = default;

  void EvaluateSetup() final override {
    GetBaseProvider().WaitForSetup();
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);

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
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = GetOutputArithmeticWire();
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::WirePointer<T> GetOutputArithmeticWire() {
    auto result = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(result);
    return result;
  }

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  OutputGate(const arithmetic_gmw::WirePointer<T>& parent, std::size_t output_owner = kAll)
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
    requires_online_interaction_ = true;
    gate_type_ = GateType::kInteractive;
    gate_id_ = GetRegister().NextGateId();
    is_my_output_ = my_id == static_cast<std::size_t>(output_owner_) ||
                    static_cast<std::size_t>(output_owner_) == kAll;

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, parent->GetNumberOfSimdValues()));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    // Tell the DataStorages that we want to receive OutputMessages from the
    // other parties.
    if (is_my_output_) {
      auto& base_provider = GetBaseProvider();
      output_message_futures_ = base_provider.RegisterForOutputMessages(gate_id_);
    }

    if constexpr (kDebug) {
      auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                   output_owner_);
      GetLogger().LogDebug(fmt::format(
          "Allocate an arithmetic_gmw::OutputGate with following properties: {}", gate_info));
    }
  }

  OutputGate(const arithmetic_gmw::SharePointer<T>& parent, std::size_t output_owner)
      : OutputGate(parent->GetArithmeticWire(), output_owner) {
    assert(parent);
  }

  OutputGate(const motion::SharePointer& parent, std::size_t output_owner)
      : OutputGate(std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent),
                   output_owner) {
    assert(parent);
  }

  ~OutputGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    // setup needs to be done first
    WaitSetup();
    assert(setup_is_ready_);

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
      auto payload = ToByteVector(output);
      auto output_message = motion::communication::BuildOutputMessage(gate_id_, payload);
      communication_layer.SendMessage(output_owner_, std::move(output_message));
    }
    // we need to send shares to all other parties:
    else if (output_owner_ == kAll) {
      auto payload = ToByteVector(output);
      auto output_message = motion::communication::BuildOutputMessage(gate_id_, payload);
      communication_layer.BroadcastMessage(std::move(output_message));
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
        const auto output_message = output_message_futures_.at(i).get();
        auto message = communication::GetMessage(output_message.data());
        auto output_message_pointer = communication::GetOutputMessage(message->payload()->data());
        assert(output_message_pointer);
        assert(output_message_pointer->wires()->size() == 1);

        shared_outputs.push_back(
            FromByteVector<T>(*output_message_pointer->wires()->Get(0)->payload()));
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
      GetLogger().LogDebug(
          fmt::format("Evaluated arithmetic_gmw::OutputGate with id#{}", gate_id_));
    }
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class AdditionGate final : public motion::TwoGate {
 public:
  AdditionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::kNonInteractive;

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues()));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an arithmetic_gmw::AdditionGate with following properties: {}", gate_info));
  }

  ~AdditionGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto wire_a = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    std::vector<T> output;
    output = RestrictAddVectors(wire_a->GetValues(), wire_b->GetValues());

    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(
        fmt::format("Evaluated arithmetic_gmw::AdditionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  AdditionGate() = delete;

  AdditionGate(Gate&) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class SubtractionGate final : public motion::TwoGate {
 public:
  SubtractionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::kNonInteractive;

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues()));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an arithmetic_gmw::SubtractionGate with following properties: {}", gate_info));
  }

  ~SubtractionGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition().Wait();
    parent_b_.at(0)->GetIsReadyCondition().Wait();

    auto wire_a = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    std::vector<T> output = SubVectors(wire_a->GetValues(), wire_b->GetValues());

    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger().LogDebug(
        fmt::format("Evaluated arithmetic_gmw::SubtractionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  SubtractionGate() = delete;

  SubtractionGate(Gate&) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class MultiplicationGate final : public motion::TwoGate {
 public:
  MultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
                     const arithmetic_gmw::WirePointer<T>& b)
      : TwoGate(a->GetBackend()) {
    parent_a_ = {std::static_pointer_cast<motion::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<motion::Wire>(b)};

    assert(parent_a_.at(0)->GetNumberOfSimdValues() == parent_b_.at(0)->GetNumberOfSimdValues());

    requires_online_interaction_ = true;
    gate_type_ = GateType::kInteractive;

    d_ = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
    GetRegister().RegisterNextWire(d_);
    e_ = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
    GetRegister().RegisterNextWire(e_);

    d_output_ = std::make_shared<OutputGate<T>>(d_);
    e_output_ = std::make_shared<OutputGate<T>>(e_);

    GetRegister().RegisterNextGate(d_output_);
    GetRegister().RegisterNextGate(e_output_);

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues()));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    number_of_mts_ = parent_a_.at(0)->GetNumberOfSimdValues();
    mt_offset_ = GetMtProvider().template RequestArithmeticMts<T>(number_of_mts_);

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an arithmetic_gmw::MultiplicationGate with following properties: {}", gate_info));
  }

  ~MultiplicationGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);
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
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  MultiplicationGate() = delete;

  MultiplicationGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_, e_;
  std::shared_ptr<OutputGate<T>> d_output_, e_output_;

  std::size_t number_of_mts_, mt_offset_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class SquareGate final : public motion::OneGate {
 public:
  SquareGate(const arithmetic_gmw::WirePointer<T>& a) : OneGate(a->GetBackend()) {
    parent_ = {std::static_pointer_cast<motion::Wire>(a)};

    requires_online_interaction_ = true;
    gate_type_ = GateType::kInteractive;

    d_ = std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues());
    GetRegister().RegisterNextWire(d_);

    d_output_ = std::make_shared<OutputGate<T>>(d_);

    GetRegister().RegisterNextGate(d_output_);

    gate_id_ = GetRegister().NextGateId();

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    {
      auto w = std::static_pointer_cast<motion::Wire>(
          std::make_shared<arithmetic_gmw::Wire<T>>(backend_, a->GetNumberOfSimdValues()));
      GetRegister().RegisterNextWire(w);
      output_wires_ = {std::move(w)};
    }

    number_of_sps_ = parent_.at(0)->GetNumberOfSimdValues();
    sp_offset_ = GetSpProvider().template RequestSps<T>(number_of_sps_);

    auto gate_info = fmt::format("uint{}_t type, gate id {}, parent: {}", sizeof(T) * 8, gate_id_,
                                 parent_.at(0)->GetWireId());
    GetLogger().LogDebug(fmt::format(
        "Created an arithmetic_gmw::SquareGate with following properties: {}", gate_info));
  }

  ~SquareGate() final = default;

  void EvaluateSetup() final override {
    SetSetupIsReady();
    GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final override {
    WaitSetup();
    assert(setup_is_ready_);
    parent_.at(0)->GetIsReadyCondition().Wait();

    auto& sp_provider = GetSpProvider();
    sp_provider.WaitFinished();
    const auto& sps = sp_provider.template GetSpsAll<T>();
    {
      const auto x = std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(parent_.at(0));
      assert(x);
      d_->GetMutableValues() = std::vector<T>(
          sps.a.begin() + sp_offset_, sps.a.begin() + sp_offset_ + x->GetNumberOfSimdValues());
      const auto number_of_simd_values{d_->GetNumberOfSimdValues()};
      T* __restrict__ d_v{d_->GetMutableValues().data()};
      const T* __restrict__ x_v{x->GetValues().data()};
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
    SetOnlineIsReady();
    GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  SquareGate() = delete;

  SquareGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_;
  std::shared_ptr<OutputGate<T>> d_output_;

  std::size_t number_of_sps_, sp_offset_;
};

}  // namespace encrypto::motion::proto::arithmetic_gmw
