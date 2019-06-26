#pragma once

#include <atomic>
#include <iostream>
#include <unordered_set>
#include <vector>

#include "fmt/format.h"

#include "base/register.h"
#include "communication/context.h"
#include "communication/output_message.h"
#include "crypto/aes_randomness_generator.h"
#include "share/share.h"
#include "utility/constants.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "utility/typedefs.h"

namespace ABYN::Gates {
namespace Interfaces {

//
//  inputs are not defined in the Gate class but only in the child classes
//
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class Gate {
 public:
  virtual ~Gate(){
      /*  std::scoped_lock lock(mutex_);
        if(auto shared_ptr_core = core_.lock()) {
          shared_ptr_core->UnregisterGate(gate_id_);
        }*/
  };

  virtual void Evaluate() = 0;

  const std::vector<ABYN::Wires::WirePtr> &GetOutputWires() const { return output_wires_; }

  void RegisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    wire_dependencies_.insert(wire_id);
  }

  void UnregisterWaitingFor(std::size_t wire_id) {
    std::scoped_lock lock(mutex_);
    if (wire_dependencies_.size() > 0 &&
        wire_dependencies_.find(wire_id) != wire_dependencies_.end()) {
      wire_dependencies_.erase(wire_id);
    }
    IfReadyAddToProcessingQueue();
  }

  bool DependenciesAreReady() { return wire_dependencies_.size() == 0; }

  void SetSetupIsReady() { setup_is_ready_ = true; }

  void SetOnlineIsReady() {
    online_is_ready_ = true;
    for (auto &wire : output_wires_) {
      assert(wire);
      wire->SetOnlineFinished();
    }
  }

  bool &SetupIsReady() { return setup_is_ready_; }

  std::int64_t GetID() const { return gate_id_; }

  Gate(Gate &) = delete;

 protected:
  std::vector<Wires::WirePtr> output_wires_;
  std::weak_ptr<Register> register_;
  std::int64_t gate_id_ = -1;
  std::unordered_set<std::size_t> wire_dependencies_;

  GateType gate_type_ = InvalidGate;
  bool setup_is_ready_ = false;
  bool online_is_ready_ = false;
  bool requires_online_interaction_ = false;

  bool added_to_active_queue = false;

  Gate() = default;

 private:
  void IfReadyAddToProcessingQueue() {
    if (DependenciesAreReady() && !added_to_active_queue) {
      auto shared_ptr_reg = register_.lock();
      assert(shared_ptr_reg);
      shared_ptr_reg->AddToActiveQueue(gate_id_);
      added_to_active_queue = true;
    }
  }

  std::mutex mutex_;
};

using GatePtr = std::shared_ptr<Gate>;

//
//     | <- one abstract input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

class OneGate : public Gate {
 public:
  ~OneGate() override = default;

  void Evaluate() override = 0;

  OneGate(OneGate &) = delete;

 protected:
  std::vector<ABYN::Wires::WirePtr> parent_;

  OneGate() = default;
};

//
//     | <- one abstract (perhaps !SharePointer) input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class InputGate : public OneGate {
 public:
 protected:
  ~InputGate() override = default;

  InputGate() { gate_type_ = GateType::InputGate; }

  InputGate(InputGate &) = delete;

  std::int64_t input_owner_ = -1;
};

using InputGatePtr = std::shared_ptr<InputGate>;

//
//     | <- one SharePtr input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- abstract output
//

class OutputGate : public OneGate {
 public:
  ~OutputGate() override = default;

  OutputGate(OutputGate &) = delete;

  OutputGate() { gate_type_ = GateType::InputGate; }

 protected:
  std::int64_t output_owner_ = -1;
};

using OutputGatePtr = std::shared_ptr<OutputGate>;

//
//   |    | <- two SharePtrs input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class TwoGate : public Gate {
 protected:
  std::vector<ABYN::Wires::WirePtr> parent_a_;
  std::vector<ABYN::Wires::WirePtr> parent_b_;

  TwoGate() = default;

 public:
  ~TwoGate() override = default;

  void Evaluate() override = 0;
};

//
//  | |... |  <- n SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

class nInputGate : public Gate {
 protected:
  std::vector<ABYN::Wires::WirePtr> parents_;

  nInputGate() = default;

 public:
  ~nInputGate() override = default;
};

}  // namespace Interfaces

namespace Arithmetic {

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

  // non-interactive input sharing based on distributed in advance randomness
  // seeds
  void Evaluate() final {
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);
    auto my_id = shared_ptr_reg->GetConfig()->GetMyId();
    std::vector<T> result;
    if (static_cast<std::size_t>(input_owner_) == my_id) {
      result.resize(input_.size());
      SetSetupIsReady();  // we always generate the seed for input sharing
                          // before we start evaluating the circuit

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
      Helpers::WaitFor(rand_generator->IsInitialized());
      SetSetupIsReady();

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
 protected:
  std::vector<T> output_;
  std::vector<std::vector<T>> shared_outputs_;

  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  const bool &parent_finished_;

  std::mutex m;

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

  ArithmeticOutputGate(const ABYN::Wires::ArithmeticWirePtr<T> &parent, std::size_t output_owner)
      : parent_finished_(parent->IsReady()) {
    if (parent->GetProtocol() != Protocol::ArithmeticGMW) {
      auto sharing_type = Helpers::Print::ToString(parent->GetProtocol());
      throw(
          std::runtime_error((fmt::format("Arithmetic output gate expects an arithmetic share, "
                                          "got a share of type {}",
                                          sharing_type))));
    }

    parent_ = {parent};
    output_owner_ = output_owner;
    output_.resize(parent->GetNumOfParallelValues());
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

    output_wires_ = {std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(output_, register_))};
    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, owner {}", sizeof(T) * 8, gate_id_, output_owner_);
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Allocate an ArithmeticOutputGate with following properties: {}", gate_info));
  }

  ArithmeticOutputGate(const ABYN::Shares::ArithmeticSharePtr<T> &parent, std::size_t output_owner)
      : ArithmeticOutputGate(parent->GetArithmeticWire(), output_owner) {}

  ~ArithmeticOutputGate() final = default;

  void Evaluate() final {
    auto arithmetic_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_.at(0));
    assert(arithmetic_wire);
    output_ = arithmetic_wire->GetValuesOnWire();

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    if (is_my_output_) {
      // wait until all conditions are fulfilled
      Helpers::WaitFor(parent_finished_);

      auto &config = shared_ptr_reg->GetConfig();
      shared_outputs_.resize(shared_ptr_reg->GetConfig()->GetNumOfParties());

      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        if (i == config->GetMyId()) {
          continue;
        }
        bool success = false;
        auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
        assert(shared_outputs_.at(i).size() == 0);
        while (!success) {
          auto message = data_storage.GetOutputMessage(gate_id_);
          if (message != nullptr) {
            shared_outputs_.at(i) =
                std::move(Helpers::FromByteVector<T>(*message->wires()->Get(0)->payload()));
            assert(shared_outputs_.at(i).size() == output_.size());
            success = true;
          }
          if (!success) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
          };
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
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticAdditionGate : public ABYN::Gates::Interfaces::TwoGate {
 public:
  ArithmeticAdditionGate(const ABYN::Wires::ArithmeticWirePtr<T> &a,
                         const ABYN::Wires::ArithmeticWirePtr<T> &b)
      : parent_a_finished_(a->IsReady()), parent_b_finished_(b->IsReady()) {
    parent_a_ = {std::static_pointer_cast<ABYN::Wires::Wire>(a)};
    parent_b_ = {std::static_pointer_cast<ABYN::Wires::Wire>(b)};
    register_ = parent_a_.at(0)->GetRegister();

    assert(parent_a_.at(0)->GetNumOfParallelValues() == parent_b_.at(0)->GetNumOfParallelValues());
    output_.resize(parent_a_.at(0)->GetNumOfParallelValues());
    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    gate_id_ = shared_ptr_reg->NextGateId();

    RegisterWaitingFor(parent_a_.at(0)->GetWireId());
    parent_a_.at(0)->RegisterWaitingGate(gate_id_);

    RegisterWaitingFor(parent_b_.at(0)->GetWireId());
    parent_b_.at(0)->RegisterWaitingGate(gate_id_);

    output_wires_ = {std::move(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<ABYN::Wires::ArithmeticWire<T>>(output_, register_)))};
    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info =
        fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                    parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Created an ArithmeticAdditionGate with following properties: {}", gate_info));

    SetSetupIsReady();
  }

  ~ArithmeticAdditionGate() final = default;

  void Evaluate() final {
    Helpers::WaitFor(parent_a_finished_);
    Helpers::WaitFor(parent_b_finished_);

    auto wire_a = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_a_.at(0));
    auto wire_b = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(parent_b_.at(0));

    assert(wire_a);
    assert(wire_b);

    output_ = Helpers::AddVectors(wire_a->GetValuesOnWire(), wire_b->GetValuesOnWire());

    auto arithmetic_wire =
        std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(output_wires_.at(0));
    arithmetic_wire->GetMutableValuesOnWire() = std::move(output_);
    assert(output_.size() == 0);

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
  const bool &parent_a_finished_;
  const bool &parent_b_finished_;
  std::vector<T> output_;
};

}  // namespace Arithmetic

namespace GMW {

class GMWInputGate : public Gates::Interfaces::InputGate {
 public:
  GMWInputGate(const ENCRYPTO::BitVector &input, std::size_t party_id, std::weak_ptr<Register> reg)
      : input_({input}), bits_(input.GetSize()), party_id_(party_id) {
    register_ = reg;
    InitializationHelper();
  }

  GMWInputGate(ENCRYPTO::BitVector &&input, std::size_t party_id, std::weak_ptr<Register> reg)
      : input_({std::move(input)}), bits_(input.GetSize()), party_id_(party_id) {
    register_ = reg;
    InitializationHelper();
  }

  GMWInputGate(const std::vector<ENCRYPTO::BitVector> &input, std::size_t party_id,
               std::weak_ptr<Register> reg)
      : input_(input), party_id_(party_id) {
    bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
    register_ = reg;
    InitializationHelper();
  }

  GMWInputGate(std::vector<ENCRYPTO::BitVector> &&input, std::size_t party_id,
               std::weak_ptr<Register> reg)
      : input_(std::move(input)), party_id_(party_id) {
    bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
    register_ = reg;
    InitializationHelper();
  }

  /*
    GMWInputGate(const std::vector<std::byte> &input, std::size_t party_id,
                 std::weak_ptr<Register> reg, std::size_t bits = 0)
        : input_({input}), bits_(bits), party_id_(party_id) {
      register_ = reg;
      InitializationHelper();
    }

    GMWInputGate(std::vector<std::byte> &&input, std::size_t party_id, std::weak_ptr<Register> reg,
                 std::size_t bits = 0)
        : input_({std::move(input)}), bits_(bits), party_id_(party_id) {
      register_ = reg;
      InitializationHelper();
    }

    GMWInputGate(const std::vector<std::vector<std::byte>> &input, std::size_t party_id,
                 std::weak_ptr<Register> reg, std::size_t bits = 0)
        : input_({input}), bits_(bits), party_id_(party_id) {
      register_ = reg;
      InitializationHelper();
    }

    GMWInputGate(std::vector<std::vector<std::byte>> &&input, std::size_t party_id,
                 std::weak_ptr<Register> reg, std::size_t bits = 0)
        : input_({std::move(input)}), bits_(bits), party_id_(party_id) {
      register_ = reg;
      InitializationHelper();
    }*/

  void InitializationHelper() {
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    if (party_id_ >= shared_ptr_reg->GetConfig()->GetNumOfParties()) {
      throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", party_id_,
                                           shared_ptr_reg->GetConfig()->GetNumOfParties()));
    }

    gate_id_ = shared_ptr_reg->NextGateId();

    assert(input_.size() > 0u);           // assert >=1 wire
    assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
    // assert SIMD lengths of all wires are equal
    assert(ABYN::Helpers::Compare::Dimensions(input_));

    boolean_sharing_id_ = shared_ptr_reg->NextBooleanGMWSharingId(input_.size() * bits_);
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Created a BooleanGMWInputGate with global id {}", gate_id_));

    output_wires_.reserve(input_.size());
    for (auto &v : input_) {
      auto wire = std::make_shared<Wires::GMWWire>(v, shared_ptr_reg, bits_);
      output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(wire));
    }

    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info = fmt::format("gate id {},", gate_id_);
    shared_ptr_reg->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMWInputGate with following properties: {}", gate_info));
  }

  ~GMWInputGate() final = default;

  void Evaluate() final {
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    auto my_id = shared_ptr_reg->GetConfig()->GetMyId();
    // we always generate the seed for input sharing before we start evaluating
    // the circuit
    if (party_id_ == my_id) {
      SetSetupIsReady();
    }

    std::vector<ENCRYPTO::BitVector> result(input_.size());
    auto sharing_id = boolean_sharing_id_;
    for (auto i = 0ull; i < result.size(); ++i) {
      if (party_id_ == my_id) {
        result.at(i) = input_.at(i);
        auto log_string = std::string("");
        for (auto j = 0u; j < shared_ptr_reg->GetConfig()->GetNumOfParties(); ++j) {
          if (j == my_id) {
            continue;
          }

          auto &rand_generator =
              shared_ptr_reg->GetConfig()->GetCommunicationContext(j)->GetMyRandomnessGenerator();
          auto randomness = std::move(rand_generator->GetBits(sharing_id, bits_));
          log_string.append(fmt::format("id#{}:{} ", j, randomness.AsString()));

          result.at(i) ^= randomness;
        }
        sharing_id += bits_;
        auto s = fmt::format(
            "My (id#{}) Boolean input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            party_id_, gate_id_, input_.at(i).AsString(), result.at(i).AsString(), log_string);
        shared_ptr_reg->GetLogger()->LogTrace(s);
      } else {
        auto &rand_generator = shared_ptr_reg->GetConfig()
                                   ->GetCommunicationContext(party_id_)
                                   ->GetTheirRandomnessGenerator();
        Helpers::WaitFor(rand_generator->IsInitialized());
        auto randomness = std::move(rand_generator->GetBits(sharing_id, bits_));
        result.at(i) = randomness;

        auto s = fmt::format(
            "Boolean input sharing (gate#{}) of Party's#{} input, got a "
            "share {} from the seed",
            gate_id_, party_id_, result.at(i).AsString());
        shared_ptr_reg->GetLogger()->LogTrace(s);
        sharing_id += bits_;
      }
    }
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_wires_.at(i));
      assert(my_wire);
      auto buf = result.at(i);
      my_wire->GetMutableValuesOnWire() = buf;
    }
    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated Boolean GMWInputGate with id#{}", gate_id_));

    SetSetupIsReady();
    SetOnlineIsReady();
  };

  const Shares::GMWSharePtr GetOutputAsGMWShare() {
    auto result = std::make_shared<Shares::GMWShare>(output_wires_);
    assert(result);
    return result;
  }

 private:
  /// two-dimensional vector for storing the raw inputs
  std::vector<ENCRYPTO::BitVector> input_;

  std::size_t bits_;                ///< Number of parallel values on wires
  std::size_t party_id_;            ///< Indicates whether which party shares the input
  std::size_t boolean_sharing_id_;  ///< Sharing ID for Boolean GMW for generating
                                    ///< correlated randomness using AES CTR
};

class GMWOutputGate : public Interfaces::OutputGate {
 protected:
  std::vector<ENCRYPTO::BitVector> output_;
  std::vector<std::vector<ENCRYPTO::BitVector>> shared_outputs_;

  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  const bool &parent_finished_;

  std::mutex m;

 public:
  GMWOutputGate(const std::vector<Wires::WirePtr> &parent, std::size_t output_owner)
      : parent_finished_(parent.at(0)->IsReady()) {
    if (parent.at(0)->GetProtocol() != Protocol::BooleanGMW) {
      auto sharing_type = Helpers::Print::ToString(parent.at(0)->GetProtocol());
      throw std::runtime_error(
          fmt::format("Boolean output gate expects an Boolean share, "
                      "got a share of type {}",
                      sharing_type));
    }

    if (parent.size() == 0) {
      throw std::runtime_error("Trying to construct an output gate with no wires");
    }

    parent_ = parent;

    output_owner_ = output_owner;
    output_.resize(parent.size());
    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    register_ = parent.at(0)->GetRegister();
    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    if (output_owner >= shared_ptr_reg->GetConfig()->GetNumOfParties()) {
      throw std::runtime_error(fmt::format("Invalid output owner: {} of {}", output_owner,
                                           shared_ptr_reg->GetConfig()->GetNumOfParties()));
    }

    gate_id_ = shared_ptr_reg->NextGateId();

    for (auto &wire : parent_) {
      RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
      wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
    }

    if (shared_ptr_reg->GetConfig()->GetMyId() == static_cast<std::size_t>(output_owner_)) {
      is_my_output_ = true;
    }

    for (auto &bv : output_) {
      output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(
          std::make_shared<Wires::GMWWire>(bv, register_)));
    }

    for (auto &wire : output_wires_) {
      shared_ptr_reg->RegisterNextWire(wire);
    }

    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Allocate an Boolean GMWOutputGate with following properties: {}", gate_info));

    SetSetupIsReady();
  }

  ~GMWOutputGate() final = default;

  void Evaluate() final {
    std::vector<Wires::GMWWirePtr> wires;
    {
      std::size_t i = 0;
      for (auto &wire : parent_) {
        auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wire);
        assert(gmw_wire);
        wires.push_back(gmw_wire);
        output_.at(i) = wires.at(wires.size() - 1)->GetValuesOnWire();
      }
    }

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    if (is_my_output_) {
      // wait until all conditions are fulfilled
      for (auto &wire : wires) {
        Helpers::WaitFor(wire->IsReady());
      }

      auto &config = shared_ptr_reg->GetConfig();
      shared_outputs_.resize(shared_ptr_reg->GetConfig()->GetNumOfParties());

      for (auto i = 0ull; i < config->GetNumOfParties(); ++i) {
        if (i == config->GetMyId()) {
          continue;
        }
        bool success = false;
        auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
        shared_outputs_.at(i).resize(output_.size());
        while (!success) {
          auto message = data_storage.GetOutputMessage(gate_id_);
          if (message != nullptr) {
            for (auto j = 0ull; j < message->wires()->size(); ++j) {
              auto payload = message->wires()->Get(j)->payload();
              auto ptr = reinterpret_cast<const std::byte *>(payload->data());
              std::vector<std::byte> byte_vector(ptr, ptr + payload->size());
              shared_outputs_.at(i).at(j) =
                  ENCRYPTO::BitVector(byte_vector, parent_.at(0)->GetNumOfParallelValues());
              assert(shared_outputs_.at(i).size() == output_.size());
              success = true;
            }
          }
          if (!success) {
            std::this_thread::sleep_for(std::chrono::microseconds(100));
          };
        }
      }

      shared_outputs_.at(config->GetMyId()) = output_;
      output_ = std::move(Helpers::XORBitVectors(shared_outputs_));

      std::string shares{""};
      for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
        shares.append(fmt::format("id#{}:{} ", i, shared_outputs_.at(i).at(0).AsString()));
      }

      shared_ptr_reg->GetLogger()->LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, output_.at(0).AsString()));

    } else {
      std::vector<std::vector<uint8_t>> payloads;
      for (auto i = 0ull; i < output_wires_.size(); ++i) {
        auto size = output_.at(i).GetData().size();
        auto data_ptr = reinterpret_cast<const uint8_t *>(output_.at(i).GetData().data());
        payloads.emplace_back(data_ptr, data_ptr + size);
      }
      auto output_message = ABYN::Communication::BuildOutputMessage(gate_id_, payloads);
      shared_ptr_reg->Send(output_owner_, output_message);
    }
    std::vector<Wires::GMWWirePtr> gmw_output_wires;
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      gmw_output_wires.push_back(
          std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_wires_.at(i)));
      assert(gmw_output_wires.at(i));
      gmw_output_wires.at(i)->GetMutableValuesOnWire() = output_.at(i);
    }
    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated Boolean GMWOutputGate with id#{}", gate_id_));
    SetOnlineIsReady();
  }

  const Shares::GMWSharePtr GetOutputAsGMWShare() const {
    auto result = std::make_shared<Shares::GMWShare>(output_wires_);
    assert(result);
    return result;
  }

  const Shares::SharePtr GetOutputAsShare() const {
    auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
    assert(result);
    return result;
  }
};

class GMWXORGate : public Gates::Interfaces::TwoGate {
 public:
  GMWXORGate(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b)
      : parent_a_finished_(a->GetWires().at(0)->IsReady()),
        parent_b_finished_(b->GetWires().at(0)->IsReady()) {
    parent_a_ = a->GetWires();
    parent_b_ = b->GetWires();

    assert(parent_a_.size() > 0);
    assert(parent_b_.size() == parent_b_.size());

    register_ = parent_a_.at(0)->GetRegister();

    requires_online_interaction_ = false;
    gate_type_ = GateType::NonInteractiveGate;

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    gate_id_ = shared_ptr_reg->NextGateId();

    for (auto &wire : parent_a_) {
      RegisterWaitingFor(wire->GetWireId());
      wire->RegisterWaitingGate(gate_id_);
    }

    for (auto &wire : parent_b_) {
      RegisterWaitingFor(wire->GetWireId());
      wire->RegisterWaitingGate(gate_id_);
    }

    output_wires_.resize(parent_a_.size());
    const ENCRYPTO::BitVector tmp_bv(a->GetNumOfParallelValues());
    for (auto &w : output_wires_) {
      w = std::move(std::static_pointer_cast<Wires::Wire>(
          std::make_shared<Wires::GMWWire>(tmp_bv, register_)));
    }

    for (auto &w : output_wires_) {
      shared_ptr_reg->RegisterNextWire(w);
    }

    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Created a BooleanGMW XOR gate with following properties: {}", gate_info));

    SetSetupIsReady();
  }

  ~GMWXORGate() final = default;

  void Evaluate() final {
    for (auto &wire : parent_a_) {
      Helpers::WaitFor(wire->IsReady());
    }

    for (auto &wire : parent_b_) {
      Helpers::WaitFor(wire->IsReady());
    }

    for (auto i = 0ull; i < parent_a_.size(); ++i) {
      auto wire_a = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(i));
      auto wire_b = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(i));

      assert(wire_a);
      assert(wire_b);

      auto output = wire_a->GetValuesOnWire() ^ wire_b->GetValuesOnWire();

      auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
      assert(gmw_wire);
      gmw_wire->GetMutableValuesOnWire() = std::move(output);
    }

    SetOnlineIsReady();

    auto shared_ptr_reg = register_.lock();
    assert(shared_ptr_reg);

    shared_ptr_reg->IncrementEvaluatedGatesCounter();
    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Evaluated BooleanGMW XOR Gate with id#{}", gate_id_));
  }

  const Shares::GMWSharePtr GetOutputAsGMWShare() const {
    auto result = std::make_shared<Shares::GMWShare>(output_wires_);
    assert(result);
    return result;
  }

  const Shares::SharePtr GetOutputAsShare() const {
    auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
    assert(result);
    return result;
  }

  GMWXORGate() = delete;

  GMWXORGate(const Gate &) = delete;

 protected:
  const bool &parent_a_finished_;
  const bool &parent_b_finished_;
};

}  // namespace GMW
}  // namespace ABYN::Gates