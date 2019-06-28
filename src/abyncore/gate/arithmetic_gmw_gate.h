#pragma once

#include "gate.h"

#include "fmt/format.h"

#include "communication/context.h"
#include "communication/output_message.h"
#include "share/share.h"
#include "utility/data_storage.h"
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
class ArithmeticInputGate : public ABYN::Gates::Interfaces::InputGate {
 public:
  ArithmeticInputGate(const std::vector<T> &input, std::size_t input_owner,
                      std::weak_ptr<ABYN::Register> reg)
      : input_(input) {
    input_owner_ = input_owner;
    register_ = reg;
    InitializationHelper();
  }

  ArithmeticInputGate(std::vector<T> &&input, std::size_t input_owner,
                      std::weak_ptr<ABYN::Register> reg)
      : input_(std::move(input)) {
    input_owner_ = input_owner;
    register_ = reg;
    InitializationHelper();
  }

  void InitializationHelper() {
    static_assert(!std::is_same_v<T, bool>);
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    gate_id_ = shared_ptr_reg->NextGateId();
    arithmetic_sharing_id_ = shared_ptr_reg->NextArithmeticSharingId(input_.size());
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Created an ArithmeticInputGate with global id {}", gate_id_));
    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(input_, register_))};
    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, input_owner_);
    shared_ptr_reg->GetLogger()->LogDebug(
        fmt::format("Allocate an ArithmeticInputGate with following properties: {}", gate_info));
  }

  ~ArithmeticInputGate() final = default;

  void EvaluateSetup() final {
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);
    auto my_id = shared_ptr_reg->GetConfig()->GetMyId();
    if (static_cast<std::size_t>(input_owner_) == my_id) {
      // we always generate seeds for the input sharing
      // before we start evaluating the circuit
    } else {
      auto &rand_generator = shared_ptr_reg->GetConfig()
                                 ->GetCommunicationContext(static_cast<std::size_t>(input_owner_))
                                 ->GetTheirRandomnessGenerator();
      Helpers::WaitFor(rand_generator->IsInitialized());
    }
    SetSetupIsReady();
  }

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void EvaluateOnline() final {
    assert(setup_is_ready_);

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);
    auto my_id = shared_ptr_reg->GetConfig()->GetMyId();
    std::vector<T> result;

    if (static_cast<std::size_t>(input_owner_) == my_id) {
      result.resize(input_.size());
      auto log_string = std::string("");
      for (auto i = 0u; i < shared_ptr_reg->GetConfig()->GetNumOfParties(); ++i) {
        if (i == my_id) {
          continue;
        }
        auto randomness =
            std::move(shared_ptr_reg->GetConfig()
                          ->GetCommunicationContext(i)
                          ->GetMyRandomnessGenerator()
                          ->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));
        log_string.append(fmt::format("id#{}:{} ", i, randomness.at(0)));
        for (auto j = 0u; j < result.size(); ++j) {
          result.at(j) += randomness.at(j);
        }
      }
      for (auto j = 0u; j < result.size(); ++j) {
        result.at(j) = input_.at(j) - result.at(j);
      }

      auto s = fmt::format(
          "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my "
          "share: {}, expected shares of other parties: {}",
          input_owner_, gate_id_, input_.at(0), result.at(0), log_string);
      shared_ptr_reg->GetLogger()->LogTrace(s);
    } else {
      auto &rand_generator = shared_ptr_reg->GetConfig()
                                 ->GetCommunicationContext(static_cast<std::size_t>(input_owner_))
                                 ->GetTheirRandomnessGenerator();

      result =
          std::move(rand_generator->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));

      auto s = fmt::format(
          "Arithmetic input sharing (gate#{}) of Party's#{} input, got a share "
          "{} from the seed",
          gate_id_, input_owner_, result.at(0));
      shared_ptr_reg->GetLogger()->LogTrace(s);
    }
    auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(my_wire);
    my_wire->GetMutableValuesOnWire() = std::move(result);
    SetOnlineIsReady();
    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
  }
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire = GetOutputArithmeticWire();
    auto result = std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Wires::ArithmeticWirePtr<T> GetOutputArithmeticWire() {
    auto result = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(result);
    return result;
  }

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticOutputGate : public ABYN::Gates::Interfaces::OutputGate {
 public:
  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  ABYN::Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<ABYN::Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  ArithmeticOutputGate(const ABYN::Wires::ArithmeticWirePtr<T> &parent, std::size_t output_owner) {
    if (parent->GetProtocol() != Protocol::ArithmeticGMW) {
      auto sharing_type = Helpers::Print::ToString(parent->GetProtocol());
      throw(
          std::runtime_error((fmt::format("Arithmetic output gate expects an arithmetic share, "
                                          "got a share of type {}",
                                          sharing_type))));
    }

    parent_ = {parent};
    output_owner_ = output_owner;

    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    register_ = parent->GetRegister();
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    gate_id_ = shared_ptr_reg->NextGateId();

    RegisterWaitingFor(parent_.at(0)->GetWireId());
    parent_.at(0)->RegisterWaitingGate(gate_id_);

    if (shared_ptr_reg->GetConfig()->GetMyId() == static_cast<std::size_t>(output_owner_)) {
      is_my_output_ = true;
    }

    std::vector<T> placeholder_vector(parent->GetNumOfParallelValues());
    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(placeholder_vector, register_))};
    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, output_owner_);
    shared_ptr_reg->GetLogger()->LogTrace(
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

    auto arithmetic_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_.at(0));
    assert(arithmetic_wire);

    std::vector<T> output_ = arithmetic_wire->GetValuesOnWire();

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    if (is_my_output_) {
      // wait until all conditions are fulfilled
      Helpers::WaitFor(parent_.at(0)->IsReady());

      auto &config = shared_ptr_reg->GetConfig();

      std::vector<std::vector<T>> shared_outputs_(shared_ptr_reg->GetConfig()->GetNumOfParties());

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
          if (!success) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
          }
        }
      }

      shared_outputs_.at(config->GetMyId()) = output_;
      output_ = std::move(Helpers::AddVectors(shared_outputs_));

      std::string shares{""};
      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        shares.append(fmt::format("id#{}:{} ", i, Helpers::Print::ToString(shared_outputs_.at(i))));
      }

      auto result = std::move(Helpers::Print::ToString(output_));

      shared_ptr_reg->GetLogger()->LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, result));

      auto arithmetic_output_wire =
          std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
      assert(arithmetic_output_wire);
      arithmetic_output_wire->GetMutableValuesOnWire() = output_;
    } else {
      auto payload = Helpers::ToByteVector(output_);
      auto output_message = ABYN::Communication::BuildOutputMessage(gate_id_, payload);
      shared_ptr_reg->Send(output_owner_, output_message);
    }
    SetOnlineIsReady();
    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
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
    register_ = parent_a_.at(0)->GetRegister();

    assert(parent_a_.at(0)->GetNumOfParallelValues() == parent_b_.at(0)->GetNumOfParallelValues());

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    gate_id_ = shared_ptr_reg->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    std::vector<T> placeholder_vector;
    placeholder_vector.resize(parent_a_.at(0)->GetNumOfParallelValues());
    output_wires_ = {std::move(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(placeholder_vector, register_)))};
    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Created an ArithmeticAdditionGate with following properties: {}", gate_info));
  }

  ~ArithmeticAdditionGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final {
    assert(setup_is_ready_);

    Helpers::WaitFor(parent_a_.at(0)->IsReady());
    Helpers::WaitFor(parent_b_.at(0)->IsReady());

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

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
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