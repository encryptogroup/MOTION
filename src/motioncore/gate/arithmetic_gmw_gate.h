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

#include "gate.h"

#include <fmt/format.h>
#include <boost/fiber/future.hpp>

#include "base/configuration.h"
#include "base/register.h"
#include "communication/context.h"
#include "communication/fbs_headers/message_generated.h"
#include "communication/fbs_headers/output_message_generated.h"
#include "communication/output_message.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "data_storage/data_storage.h"
#include "share/arithmetic_gmw_share.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"
#include "utility/logger.h"

namespace MOTION::Gates::Arithmetic {

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
class ArithmeticInputGate final : public Interfaces::InputGate {
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
    output_wires_ = {std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<MOTION::Wires::ArithmeticWire<T>>(input_, backend_))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                 input_owner_id_);
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
      auto &rand_generator =
          GetRegister()
              ->GetConfig()
              ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
              ->GetTheirRandomnessGenerator();

      while (!rand_generator->IsInitialized()) {
        rand_generator->GetInitializedCondition()->WaitFor(std::chrono::milliseconds(1));
      }
    }
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void EvaluateOnline() final {
    WaitSetup();
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
        if constexpr (MOTION_VERBOSE_DEBUG) {
          log_string.append(fmt::format("id#{}:{} ", i, randomness.at(0)));
        }
        for (auto j = 0u; j < result.size(); ++j) {
          result.at(j) += randomness.at(j);
        }
      }
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) = input_.at(j) - result.at(j);
      }

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            input_owner_id_, gate_id_, input_.at(0), result.at(0), log_string);
        GetLogger()->LogTrace(s);
      }
    } else {
      auto &rand_generator =
          GetConfig()
              ->GetCommunicationContext(static_cast<std::size_t>(input_owner_id_))
              ->GetTheirRandomnessGenerator();

      result =
          std::move(rand_generator->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "Arithmetic input sharing (gate#{}) of Party's#{} input, got a share "
            "{} from the seed",
            gate_id_, input_owner_id_, result.at(0));
        GetLogger()->LogTrace(s);
      }
    }
    auto my_wire = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(my_wire);
    my_wire->GetMutableValues() = std::move(result);

    GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
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

constexpr std::size_t ALL = std::numeric_limits<std::int64_t>::max();

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticOutputGate final : public Gates::Interfaces::OutputGate {
 public:
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticOutputGate(const Wires::ArithmeticWirePtr<T> &parent, std::size_t output_owner = ALL) {
    assert(parent);

    if (parent->GetProtocol() != MPCProtocol::ArithmeticGMW) {
      auto sharing_type = Helpers::Print::ToString(parent->GetProtocol());
      throw(
          std::runtime_error((fmt::format("Arithmetic output gate expects an arithmetic share, "
                                          "got a share of type {}",
                                          sharing_type))));
    }

    parent_ = {parent};
    backend_ = parent->GetBackend();

    // values we need repeatedly
    const auto config = GetConfig();
    const auto my_id = config->GetMyId();
    const auto num_parties = config->GetNumOfParties();

    if (static_cast<std::size_t>(output_owner) >= num_parties &&
        static_cast<std::size_t>(output_owner) != ALL) {
      throw std::runtime_error(
          fmt::format("Invalid output owner: {} of {}", output_owner, num_parties));
    }

    output_owner_ = output_owner;
    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;
    gate_id_ = GetRegister()->NextGateId();
    is_my_output_ = my_id == static_cast<std::size_t>(output_owner_) ||
                    static_cast<std::size_t>(output_owner_) == ALL;

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    // XXX: remove placeholder_vector when we can create uninitialized wires
    std::vector<T> placeholder_vector(parent->GetNumOfSIMDValues());
    output_wires_ = {std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<MOTION::Wires::ArithmeticWire<T>>(placeholder_vector, backend_))};

    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    // Tell the DataStorages that we want to receive OutputMessages from the
    // other parties.
    if (is_my_output_) {
      output_message_futures_.reserve(num_parties);
      for (size_t i = 0; i < num_parties; ++i) {
        if (i == my_id) {
          // We don't send a message to ourselves.
          // Just store an invalid future here.
          output_message_futures_.emplace_back();
          continue;
        }
        const auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
        // Get a future that will eventually contain the received data.
        output_message_futures_.push_back(data_storage->RegisterForOutputMessage(gate_id_));
      }
    }

    if constexpr (MOTION_DEBUG) {
      auto gate_info = fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_,
                                   output_owner_);
      GetLogger()->LogDebug(
          fmt::format("Allocate an ArithmeticOutputGate with following properties: {}", gate_info));
    }
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

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    // setup needs to be done first
    WaitSetup();
    assert(setup_is_ready_);

    // data we need repeatedly
    const auto config = GetConfig();
    auto my_id = config->GetMyId();
    auto num_parties = config->GetNumOfParties();

    // note that arithmetic gates have only a single wire
    auto arithmetic_wire = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_.at(0));
    assert(arithmetic_wire);
    // wait for parent wire to obtain a value
    arithmetic_wire->GetIsReadyCondition()->Wait();
    // initialize output with local share
    auto output = arithmetic_wire->GetValues();

    // we need to send shares to one other party:
    if (!is_my_output_) {
      auto payload = Helpers::ToByteVector(output);
      auto output_message = MOTION::Communication::BuildOutputMessage(gate_id_, payload);
      GetRegister()->Send(output_owner_, std::move(output_message));
    }
    // we need to send shares to all other parties:
    else if (output_owner_ == ALL) {
      auto payload = Helpers::ToByteVector(output);
      for (auto i = 0ull; i < num_parties; ++i) {
        if (i == my_id) continue;
        auto output_message = MOTION::Communication::BuildOutputMessage(gate_id_, payload);
        GetRegister()->Send(i, std::move(output_message));
      }
    }

    // we receive shares from other parties
    if (is_my_output_) {
      // collect shares from all parties
      std::vector<std::vector<T>> shared_outputs;
      shared_outputs.reserve(num_parties);

      for (std::size_t i = 0; i < num_parties; ++i) {
        if (i == my_id) {
          shared_outputs.push_back(output);
          continue;
        }
        const auto output_message = output_message_futures_.at(i).get();
        auto message = Communication::GetMessage(output_message.data());
        auto output_message_ptr = Communication::GetOutputMessage(message->payload()->data());
        assert(output_message_ptr);
        assert(output_message_ptr->wires()->size() == 1);

        shared_outputs.push_back(
            Helpers::FromByteVector<T>(*output_message_ptr->wires()->Get(0)->payload()));
        assert(shared_outputs.at(i).size() == parent_.at(0)->GetNumOfSIMDValues());
        {
          // replace promise/future pair
          // XXX: this should be replaced by some channel construct
          const auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
          output_message_futures_.at(i) = data_storage->RegisterForOutputMessage(gate_id_);
        }
      }

      // reconstruct the shared value
      if constexpr (MOTION_VERBOSE_DEBUG) {
        // we need to copy since we have to keep shared_outputs for the debug output below
        output = Helpers::AddVectors(shared_outputs);
      } else {
        // we can move
        output = Helpers::AddVectors(std::move(shared_outputs));
      }

      // set the value of the output wire
      auto arithmetic_output_wire =
          std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
      assert(arithmetic_output_wire);
      arithmetic_output_wire->GetMutableValues() = output;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        std::string shares{""};
        for (auto i = 0u; i < num_parties; ++i) {
          shares.append(
              fmt::format("id#{}:{} ", i, Helpers::Print::ToString(shared_outputs.at(i))));
        }
        auto result = Helpers::Print::ToString(output);
        GetLogger()->LogTrace(
            fmt::format("Received output shares: {} from other parties, "
                        "reconstructed result is {}",
                        shares, result));
      }
    }

    // we are done with this gate
    if constexpr (MOTION_DEBUG) {
      GetLogger()->LogDebug(fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
    }
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
  }

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<boost::fibers::future<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticAdditionGate final : public MOTION::Gates::Interfaces::TwoGate {
 public:
  ArithmeticAdditionGate(const MOTION::Wires::ArithmeticWirePtr<T> &a,
                         const MOTION::Wires::ArithmeticWirePtr<T> &b) {
    parent_a_ = {std::static_pointer_cast<MOTION::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<MOTION::Wires::Wire>(b)};
    backend_ = parent_a_.at(0)->GetBackend();

    assert(parent_a_.at(0)->GetNumOfSIMDValues() == parent_b_.at(0)->GetNumOfSIMDValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    gate_id_ = GetRegister()->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    std::vector<T> placeholder_vector;
    placeholder_vector.resize(parent_a_.at(0)->GetNumOfSIMDValues());
    output_wires_ = {std::move(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<MOTION::Wires::ArithmeticWire<T>>(placeholder_vector, backend_)))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger()->LogDebug(
        fmt::format("Created an ArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ArithmeticAdditionGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition()->Wait();
    parent_b_.at(0)->GetIsReadyCondition()->Wait();

    auto wire_a = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    std::vector<T> output;
    output = Helpers::AddVectors(wire_a->GetValues(), wire_b->GetValues());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger()->LogDebug(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  MOTION::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<MOTION::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticAdditionGate() = delete;

  ArithmeticAdditionGate(Gate &) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticSubtractionGate final : public MOTION::Gates::Interfaces::TwoGate {
 public:
  ArithmeticSubtractionGate(const MOTION::Wires::ArithmeticWirePtr<T> &a,
                            const MOTION::Wires::ArithmeticWirePtr<T> &b) {
    parent_a_ = {std::static_pointer_cast<MOTION::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<MOTION::Wires::Wire>(b)};
    backend_ = parent_a_.at(0)->GetBackend();

    assert(parent_a_.at(0)->GetNumOfSIMDValues() == parent_b_.at(0)->GetNumOfSIMDValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    gate_id_ = GetRegister()->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    std::vector<T> placeholder_vector;
    placeholder_vector.resize(parent_a_.at(0)->GetNumOfSIMDValues());
    output_wires_ = {std::move(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<MOTION::Wires::ArithmeticWire<T>>(placeholder_vector, backend_)))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger()->LogDebug(
        fmt::format("Created an ArithmeticSubtractionGate with following properties: {}", gate_info));
  }

  ~ArithmeticSubtractionGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);

    parent_a_.at(0)->GetIsReadyCondition()->Wait();
    parent_b_.at(0)->GetIsReadyCondition()->Wait();

    auto wire_a = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    std::vector<T> output = Helpers::SubVectors(wire_a->GetValues(), wire_b->GetValues());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValues() = std::move(output);

    GetLogger()->LogDebug(fmt::format("Evaluated ArithmeticSubtractionGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  MOTION::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<MOTION::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticSubtractionGate() = delete;

  ArithmeticSubtractionGate(Gate &) = delete;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticMultiplicationGate final : public MOTION::Gates::Interfaces::TwoGate {
 public:
  ArithmeticMultiplicationGate(const MOTION::Wires::ArithmeticWirePtr<T> &a,
                               const MOTION::Wires::ArithmeticWirePtr<T> &b) {
    parent_a_ = {std::static_pointer_cast<MOTION::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<MOTION::Wires::Wire>(b)};
    backend_ = parent_a_.at(0)->GetBackend();

    assert(parent_a_.at(0)->GetNumOfSIMDValues() == parent_b_.at(0)->GetNumOfSIMDValues());

    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    const std::vector<T> tmp_v(parent_a_.at(0)->GetNumOfSIMDValues());

    d_ = std::make_shared<Wires::ArithmeticWire<T>>(tmp_v, backend_);
    GetRegister()->RegisterNextWire(d_);
    e_ = std::make_shared<Wires::ArithmeticWire<T>>(tmp_v, backend_);
    GetRegister()->RegisterNextWire(e_);

    d_out_ = std::make_shared<ArithmeticOutputGate<T>>(d_);
    e_out_ = std::make_shared<ArithmeticOutputGate<T>>(e_);

    GetRegister()->RegisterNextGate(d_out_);
    GetRegister()->RegisterNextGate(e_out_);

    gate_id_ = GetRegister()->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    output_wires_ = {std::move(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<MOTION::Wires::ArithmeticWire<T>>(tmp_v, backend_)))};
    for (auto &w : output_wires_) {
      GetRegister()->RegisterNextWire(w);
    }

    auto backend = backend_.lock();
    assert(backend);

    num_mts_ = parent_a_.at(0)->GetNumOfSIMDValues();
    mt_offset_ = GetMTProvider()->template RequestArithmeticMTs<T>(num_mts_);

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger()->LogDebug(fmt::format(
        "Created an ArithmeticMultiplicationGate with following properties: {}", gate_info));
  }

  ~ArithmeticMultiplicationGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);
    parent_a_.at(0)->GetIsReadyCondition()->Wait();
    parent_b_.at(0)->GetIsReadyCondition()->Wait();

    auto mt_provider = GetMTProvider();
    mt_provider->WaitFinished();
    const auto &mts = mt_provider->template GetIntegerAll<T>();
    {
      const auto x = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_a_.at(0));
      assert(x);
      d_->GetMutableValues() = std::vector<T>(mts.a.begin() + mt_offset_,
                                              mts.a.begin() + mt_offset_ + x->GetNumOfSIMDValues());
      auto &d_v = d_->GetMutableValues();
      const auto &x_v = x->GetValues();
      for (auto i = 0ull; i < d_v.size(); ++i) {
        d_v.at(i) += x_v.at(i);
      }
      d_->SetOnlineFinished();

      const auto y = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_b_.at(0));
      assert(y);
      e_->GetMutableValues() = std::vector<T>(mts.b.begin() + mt_offset_,
                                              mts.b.begin() + mt_offset_ + x->GetNumOfSIMDValues());
      auto &e_v = e_->GetMutableValues();
      const auto &y_v = y->GetValues();
      for (auto i = 0ull; i < e_v.size(); ++i) {
        e_v.at(i) += y_v.at(i);
      }
      e_->SetOnlineFinished();
    }

    d_out_->WaitOnline();
    e_out_->WaitOnline();

    const auto &d_clear = d_out_->GetOutputWires().at(0);
    const auto &e_clear = e_out_->GetOutputWires().at(0);

    d_clear->GetIsReadyCondition()->Wait();
    e_clear->GetIsReadyCondition()->Wait();

    const auto d_w = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(d_clear);
    const auto x_i_w = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_a_.at(0));
    const auto e_w = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(e_clear);
    const auto y_i_w = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_b_.at(0));

    assert(d_w);
    assert(x_i_w);
    assert(e_w);
    assert(y_i_w);

    auto out = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(out);
    out->GetMutableValues() =
        std::vector<T>(mts.c.begin() + mt_offset_,
                       mts.c.begin() + mt_offset_ + parent_a_.at(0)->GetNumOfSIMDValues());

    const auto &d = d_w->GetValues();
    const auto &s_x = x_i_w->GetValues();
    const auto &e = e_w->GetValues();
    const auto &s_y = y_i_w->GetValues();

    if (GetConfig()->GetMyId() == (gate_id_ % GetConfig()->GetNumOfParties())) {
      for (auto i = 0ull; i < out->GetNumOfSIMDValues(); ++i) {
        out->GetMutableValues().at(i) +=
            (d.at(i) * s_y.at(i)) + (e.at(i) * s_x.at(i)) - (e.at(i) * d.at(i));
      }
    } else {
      for (auto i = 0ull; i < out->GetNumOfSIMDValues(); ++i) {
        out->GetMutableValues().at(i) += (d.at(i) * s_y.at(i)) + (e.at(i) * s_x.at(i));
      }
    }

    GetLogger()->LogDebug(
        fmt::format("Evaluated ArithmeticMultiplicationGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  MOTION::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<MOTION::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<MOTION::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticMultiplicationGate() = delete;

  ArithmeticMultiplicationGate(Gate &) = delete;

 private:
  Wires::ArithmeticWirePtr<T> d_, e_;
  std::shared_ptr<ArithmeticOutputGate<T>> d_out_, e_out_;

  std::size_t num_mts_, mt_offset_;
};
}  // namespace MOTION::Gates::Arithmetic
