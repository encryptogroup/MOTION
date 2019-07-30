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

#pragma once

#include "gate.h"

#include "fmt/format.h"

#include "base/configuration.h"
#include "base/register.h"
#include "communication/context.h"
#include "communication/output_message.h"
#include "crypto/aes_randomness_generator.h"
#include "share/arithmetic_gmw_share.h"
#include "utility/data_storage.h"
#include "utility/helpers.h"
#include "utility/logger.h"

namespace ABYN::Gates::Arithmetic {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new ArithmeticShare) output
//

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticInputGate : public Interfaces::InputGate {
 public:
  ArithmeticInputGate(const std::vector<T> &input, std::size_t input_owner,
                      std::weak_ptr<Backend> backend)
      : input_(input) {
    input_owner_id_ = input_owner;
    backend_ = backend;
    InitializationHelper();
  }

  ArithmeticInputGate(std::vector<T> &&input, std::size_t input_owner,
                      std::weak_ptr<Backend> backend)
      : input_(std::move(input)) {
    input_owner_id_ = input_owner;
    backend_ = backend;
    InitializationHelper();
  }

  void InitializationHelper() {
    static_assert(!std::is_same_v<T, bool>);

    gate_id_ = GetRegister()->NextGateId();
    arithmetic_sharing_id_ = GetRegister()->NextArithmeticSharingId(input_.size());
    GetLogger()->LogTrace(
        fmt::format("Created an ArithmeticInputGate with global id {}", gate_id_));
    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(input_, backend_))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, input_owner_id_);
    GetLogger()->LogDebug(
        fmt::format("Allocate an ArithmeticInputGate with following properties: {}", gate_info));
  }

  ~ArithmeticInputGate() final = default;

  void EvaluateSetup() final {
    auto my_id = GetRegister()->GetConfig()->GetMyId();
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      // we always generate seeds for the input sharing
      // before we start evaluating the circuit
    } else {
      auto &rand_generator = GetRegister()
                                 ->GetConfig()
                                 ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
                                 ->GetTheirRandomnessGenerator();

      while (!rand_generator->IsInitialized()) {
        rand_generator->GetInitializedCondition()->WaitFor(std::chrono::milliseconds(1));
      }
    }
    SetSetupIsReady();
  }

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void EvaluateOnline() final {
    assert(setup_is_ready_);

    auto my_id = GetConfig()->GetMyId();
    std::vector<T> result;

    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      result.resize(input_.size());
      auto log_string = std::string("");
      for (auto i = 0u; i < GetConfig()->GetNumOfParties(); ++i) {
        if (i == my_id) {
          continue;
        }
        auto randomness =
            std::move(GetConfig()
                          ->GetCommunicationContext(i)
                          ->GetMyRandomnessGenerator()
                          ->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));
        if constexpr (ABYN_VERBOSE_DEBUG) {
          log_string.append(fmt::format("id#{}:{} ", i, randomness.at(0)));
        }
        for (auto j = 0u; j < result.size(); ++j) {
          result.at(j) += randomness.at(j);
        }
      }
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) = input_.at(j) - result.at(j);
      }

      if constexpr (ABYN_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            input_owner_id_, gate_id_, input_.at(0), result.at(0), log_string);
        GetLogger()->LogTrace(s);
      }
    } else {
      auto &rand_generator = GetConfig()
                                 ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
                                 ->GetTheirRandomnessGenerator();

      result =
          std::move(rand_generator->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));

      if constexpr (ABYN_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "Arithmetic input sharing (gate#{}) of Party's#{} input, got a share "
            "{} from the seed",
            gate_id_, input_owner_id_, result.at(0));
        GetLogger()->LogTrace(s);
      }
    }
    auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(my_wire);
    my_wire->GetMutableValuesOnWire() = std::move(result);
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
    GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
  }
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = GetOutputArithmeticWire();
    auto result = std::make_shared<Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  Wires::ArithmeticWirePtr<T> GetOutputArithmeticWire() {
    auto result = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(result);
    return result;
  }

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticOutputGate : public Gates::Interfaces::OutputGate {
 public:
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticOutputGate(const Wires::ArithmeticWirePtr<T> &parent, std::size_t output_owner) {
    assert(parent);

    if (parent->GetProtocol() != MPCProtocol::ArithmeticGMW) {
      auto sharing_type = Helpers::Print::ToString(parent->GetProtocol());
      throw(
          std::runtime_error((fmt::format("Arithmetic output gate expects an arithmetic share, "
                                          "got a share of type {}",
                                          sharing_type))));
    }

    backend_ = parent->GetBackend();
    parent_ = {parent};
    output_owner_ = output_owner;

    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    gate_id_ = GetRegister()->NextGateId();

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    if (GetConfig()->GetMyId() == static_cast<std::size_t>(output_owner_)) {
      is_my_output_ = true;
    }

    std::vector<T> placeholder_vector(parent->GetNumOfParallelValues());
    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(placeholder_vector, backend_))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, output_owner_);
    GetLogger()->LogTrace(
        fmt::format("Allocate an ArithmeticOutputGate with following properties: {}", gate_info));
  }

  ArithmeticOutputGate(const Shares::ArithmeticSharePtr<T> &parent, std::size_t output_owner)
      : ArithmeticOutputGate(parent->GetArithmeticWire(), output_owner) {
    assert(parent);
  }

  ArithmeticOutputGate(const Shares::SharePtr &parent, std::size_t output_owner)
      : ArithmeticOutputGate(std::dynamic_pointer_cast<Shares::ArithmeticShare<T>>(parent),
                             output_owner) {
    assert(parent);
  }

  ~ArithmeticOutputGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final {
    assert(setup_is_ready_);

    auto arithmetic_wire = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_.at(0));
    assert(arithmetic_wire);

    std::vector<T> output_ = arithmetic_wire->GetValuesOnWire();

    if (is_my_output_) {
      // wait until all conditions are fulfilled
      while (!parent_.at(0)->IsReady()) {
        parent_.at(0)->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
      }

      auto config = GetConfig();

      std::vector<std::vector<T>> shared_outputs_(GetConfig()->GetNumOfParties());

      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        if (i == config->GetMyId()) {
          continue;
        }
        bool success = false;
        auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
        assert(shared_outputs_.at(i).size() == 0);
        while (!success) {
          auto message = data_storage->GetOutputMessage(gate_id_);
          if (message != nullptr) {
            shared_outputs_.at(i) =
                std::move(Helpers::FromByteVector<T>(*message->wires()->Get(0)->payload()));
            assert(shared_outputs_.at(i).size() == output_.size());
            success = true;
          }
        }
      }

      shared_outputs_.at(config->GetMyId()) = output_;
      output_ = std::move(Helpers::AddVectors(shared_outputs_));

      if constexpr (ABYN_VERBOSE_DEBUG) {
        std::string shares{""};
        for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
          shares.append(
              fmt::format("id#{}:{} ", i, Helpers::Print::ToString(shared_outputs_.at(i))));
        }

        auto result = std::move(Helpers::Print::ToString(output_));

        GetLogger()->LogTrace(
            fmt::format("Received output shares: {} from other parties, "
                        "reconstructed result is {}",
                        shares, result));
      }

      auto arithmetic_output_wire =
          std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
      assert(arithmetic_output_wire);
      arithmetic_output_wire->GetMutableValuesOnWire() = output_;
    } else {
      auto payload = Helpers::ToByteVector(output_);
      auto output_message = ABYN::Communication::BuildOutputMessage(gate_id_, payload);
      GetRegister()->Send(output_owner_, output_message);
    }
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
    GetLogger()->LogDebug(fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
  }

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::mutex m;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticAdditionGate : public ABYN::Gates::Interfaces::TwoGate {
 public:
  ArithmeticAdditionGate(const ABYN::Wires::ArithmeticWirePtr<T> &a,
                         const ABYN::Wires::ArithmeticWirePtr<T> &b) {
    parent_a_ = {std::static_pointer_cast<ABYN::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<ABYN::Wires::Wire>(b)};
    backend_ = parent_a_.at(0)->GetBackend();

    assert(parent_a_.at(0)->GetNumOfParallelValues() == parent_b_.at(0)->GetNumOfParallelValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    gate_id_ = GetRegister()->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    std::vector<T> placeholder_vector;
    placeholder_vector.resize(parent_a_.at(0)->GetNumOfParallelValues());
    output_wires_ = {std::move(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(placeholder_vector, backend_)))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger()->LogTrace(
        fmt::format("Created an ArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ArithmeticAdditionGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final {
    assert(setup_is_ready_);

    while (!parent_a_.at(0)->IsReady()) {
      parent_a_.at(0)->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
    }
    while (!parent_b_.at(0)->IsReady()) {
      parent_a_.at(0)->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
    }

    auto wire_a = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    std::vector<T> output;
    output = Helpers::AddVectors(wire_a->GetValuesOnWire(), wire_b->GetValuesOnWire());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValuesOnWire() = std::move(output);

    SetOnlineIsReady();

    GetRegister()->IncrementEvaluatedGatesCounter();
    GetLogger()->LogDebug(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticAdditionGate() = delete;

  ArithmeticAdditionGate(Gate &) = delete;

 protected:
};
}