#ifndef GATE_H
#define GATE_H

#include <iostream>
#include <vector>
#include <unordered_set>
#include <atomic>

#include "abynparty/core.h"
#include "share/share.h"

#include "utility/typedefs.h"
#include "utility/constants.h"
#include "utility/helpers.h"

#include "communication/output_message.h"

namespace ABYN::Gates::Interfaces {

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

  class Gate : public std::enable_shared_from_this<Gate> {
  public:
    virtual ~Gate() {
      std::scoped_lock lock(mutex_);
      core_->UnregisterGate(gate_id_);
    };

    virtual void Evaluate() = 0;

    const ABYN::Shares::SharePtr &GetOutputShare() const {
      return output_share_;
    }

    const std::shared_ptr<Gate> GetShared() { return shared_from_this(); }

    void RegisterWaitingFor(std::size_t wire_id) {
      std::scoped_lock lock(mutex_);
      wire_dependencies_.insert(wire_id);
    }

    void UnregisterWaitingFor(std::size_t wire_id) {
      std::scoped_lock lock(mutex_);
      if (wire_dependencies_.size() > 0 && wire_dependencies_.find(wire_id) != wire_dependencies_.end()) {
        wire_dependencies_.erase(wire_id);
      }
      IfReadyAddToProcessingQueue();
    }

    bool DependenciesAreReady() {
      return wire_dependencies_.size() == 0;
    }

    void SetSetupIsReady() {
      setup_is_ready_ = true;
    }

    void SetOnlineIsReady() {
      online_is_ready_ = true;
      assert(output_share_);
      for (auto &wire : output_share_->GetWires()) {
        wire->SetOnlineFinished();
      }
    }

    bool &SetupIsReady() { return setup_is_ready_; }

    Gate(Gate &) = delete;

  protected:
    ABYN::Shares::SharePtr output_share_;
    ABYN::CorePtr core_;
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
        core_->AddToActiveQueue(gate_id_);
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
    ~OneGate() override {}

    void Evaluate() override = 0;

  protected:
    ABYN::Shares::SharePtr parent_;

    OneGate() {}

    OneGate(OneGate &) = delete;

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

  };

  using InputGatePtr = std::shared_ptr<InputGate>;


//
//     | <- one SharePointer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- abstract output
//

  class OutputGate : public OneGate {
  public:
    OutputGate(const ABYN::Shares::SharePtr &parent, std::size_t output_owner) {
      core_ = parent->GetCore();
      parent_ = parent;
      output_owner_ = output_owner;
      gate_type_ = InteractiveGate;
    }

    void Evaluate() override = 0;

    ~OutputGate() override = default;

    OutputGate(OutputGate &) = delete;

  protected:

    OutputGate() = default;

    std::int64_t output_owner_ = -1;
  };

  using OutputGatePtr = std::shared_ptr<OutputGate>;

//
//   |    | <- two SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

  class TwoGate : public Gate {

  protected:
    ABYN::Shares::SharePtr parent_a_;
    ABYN::Shares::SharePtr parent_b_;

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
    std::vector<ABYN::Shares::SharePtr> parents_;

    nInputGate() {}

  public:
    virtual ~nInputGate() {}

    virtual void Evaluate() {}

  };

} //Interfaces

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

//TODO Implement interactive sharing

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticInputGate : public ABYN::Gates::Interfaces::InputGate {
  public:
    ArithmeticInputGate(const std::vector<T> &input, std::size_t party_id, const ABYN::CorePtr &core) :
        input_(input), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    ArithmeticInputGate(std::vector<T> &&input, std::size_t party_id, const ABYN::CorePtr &core) :
        input_(std::move(input)), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    void InitializationHelper() {
      static_assert(!std::is_same_v<T, bool>);
      gate_id_ = core_->NextGateId();
      core_->RegisterNextGate(static_cast<Gate *>(this));
      arithmetic_sharing_id_ = core_->NextArithmeticSharingId(input_.size());
      core_->GetLogger()->LogTrace(fmt::format("Created an ArithmeticInputGate with global id {}", gate_id_));
      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::ArithmeticShare<T>>(input_, core_)));

      auto gate_info = fmt::format("uint{}_t type, gate id {},", sizeof(T) * 8, gate_id_);
      core_->GetLogger()->LogDebug(fmt::format("Allocate an ArithmeticInputGate with following properties: {}",
                                               gate_info));
    }

    ~ArithmeticInputGate() final = default;

    //non-interactive input sharing based on distributed in advance randomness seeds
    void Evaluate() final {
      auto my_id = core_->GetConfig()->GetMyId();
      std::vector<T> result;
      if (party_id_ == my_id) {
        result.resize(input_.size());
        SetSetupIsReady(); //we always generate the seed for input sharing before we start evaluating the circuit

        auto log_string = std::string("");
        for (auto i = 0u; i < core_->GetConfig()->GetNumOfParties(); ++i) {
          if (i == my_id) { continue; }
          auto randomness = std::move(core_->GetConfig()->GetCommunicationContext(i)->GetMyRandomnessGenerator()
                                          ->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));
          log_string.append(fmt::format("id#{}:{} ", i, randomness.at(0)));
          for (auto j = 0u; j < result.size(); ++j) { result.at(j) += randomness.at(j); }
        }
        for (auto j = 0u; j < result.size(); ++j) { result.at(j) = input_.at(j) - result.at(j); }

        auto s = fmt::format(
            "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my share: {}, expected shares of other parties: {}",
            party_id_, gate_id_, input_.at(0) + result.at(0), input_.at(0), log_string);
        core_->GetLogger()->LogTrace(s);
      } else {
        auto &rand_generator = core_->GetConfig()->GetCommunicationContext(party_id_)->GetTheirRandomnessGenerator();
        Helpers::WaitFor(rand_generator->IsInitialized());
        SetSetupIsReady();

        result = std::move(rand_generator->template GetUnsigned<T>(arithmetic_sharing_id_, input_.size()));

        auto s = fmt::format("Arithmetic input sharing (gate#{}) of Party's#{} input, got a share {} from the seed",
                             gate_id_, party_id_, result.at(0));
        core_->GetLogger()->LogTrace(s);
      }
      auto my_wire = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_)->GetArithmeticWire();
      assert(my_wire);
      my_wire->GetMutableValuesOnWire() = std::move(result);
      SetOnlineIsReady();
      core_->IncrementEvaluatedGatesCounter();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_);
      assert(result);
      return result;
    }

  private:
    std::size_t arithmetic_sharing_id_;

    std::vector<T> input_;

    //indicates whether this party shares the input
    std::size_t party_id_;
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticOutputGate : public ABYN::Gates::Interfaces::OutputGate {
  protected:
    std::vector<T> output_;
    std::vector<std::vector<T>> shared_outputs_;

    //indicates whether this party obtains the output
    bool is_my_output_ = false;

    const bool &parent_finished_;

    std::mutex m;

  public:

    ArithmeticOutputGate(const ABYN::Shares::ArithmeticSharePtr<T> &parent, std::size_t output_owner) :
        parent_finished_(parent->Finished()) {
      if (parent->GetSharingType() != Protocol::ArithmeticGMW) {
        auto sharing_type = Helpers::Print::ToString(parent->GetSharingType());
        throw (std::runtime_error((fmt::format(
            "Arithmetic output gate expects an arithmetic share, got a share of type {}", sharing_type))));
      }
      parent_ = parent;
      output_owner_ = output_owner;
      output_.resize(parent->GetNumOfParallelValues());
      requires_online_interaction_ = true;
      gate_type_ = GateType::InteractiveGate;

      core_ = parent->GetCore();
      gate_id_ = core_->NextGateId();
      core_->RegisterNextGate(static_cast<Gate *>(this));

      RegisterWaitingFor(parent->GetWires().at(0)->GetWireId());
      parent->GetArithmeticWire()->RegisterWaitingGate(gate_id_);

      if (core_->GetConfig()->GetMyId() == static_cast<std::size_t>(output_owner_)) { is_my_output_ = true; }

      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::ArithmeticShare<T>>(output_, core_)));

      auto gate_info = fmt::format("uint{}_t type, gate id {},", sizeof(T) * 8, gate_id_);
      core_->GetLogger()->LogTrace(fmt::format("Allocate an ArithmeticOutputGate with following properties: {}",
                                               gate_info));
    }

    ~ArithmeticOutputGate() final = default;

    void Evaluate() final {
      auto wires = parent_->GetWires();
      assert(wires.size() == 1); //we expect exactly 1 wire in arithmetic shares
      auto arithmetic_wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(wires.at(0));
      assert(arithmetic_wire); //we expect the wire pointer to exist and dynamic cast to work correctly
      output_ = arithmetic_wire->GetValuesOnWire();

      if (is_my_output_) {
        //wait until all conditions are fulfilled
        Helpers::WaitFor(this->parent_finished_);
        auto &config = core_->GetConfig();
        shared_outputs_.resize(core_->GetConfig()->GetNumOfParties());

        for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
          if (i == config->GetMyId()) { continue; }
          bool success = false;
          auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
          assert(shared_outputs_.at(i).size() == 0);
          while (!success) {
            auto message = data_storage.GetOutputMessage(gate_id_);
            if (message != nullptr) {
              shared_outputs_.at(i) = std::move(Helpers::FromByteVector<T>(*message->wires()->Get(0)->payload()));
              success = true;
            }
            if (!success) { std::this_thread::sleep_for(std::chrono::microseconds(100)); };
          }
        }


        shared_outputs_.at(config->GetMyId()) = output_;
        output_ = std::move(Helpers::AddVectors(shared_outputs_));

        std::string shares{""};
        for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
          shares.append(fmt::format("id#{}:{} ", i, Helpers::Print::ToString(shared_outputs_.at(i))));
        }

        auto result = std::move(Helpers::Print::ToString(output_));

        core_->GetLogger()->LogTrace(
            fmt::format("Received output shares: {} from other parties, reconstructed result is {}", shares, result));

        std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_share_->GetWires().at(0))
            ->GetMutableValuesOnWire() = output_;
      } else {
        auto payload = Helpers::ToByteVector(output_);
        auto output_message = ABYN::Communication::BuildOutputMessage(gate_id_, payload);
        core_->Send(output_owner_, output_message);
      }
      SetOnlineIsReady();
      core_->IncrementEvaluatedGatesCounter();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    const ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_);
      assert(result);
      return result;
    }
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticAdditionGate : public ABYN::Gates::Interfaces::TwoGate {
  public:

    ArithmeticAdditionGate(const ABYN::Shares::ArithmeticSharePtr<T> &a,
                           const ABYN::Shares::ArithmeticSharePtr<T> &b) :
        parent_a_finished_(a->Finished()), parent_b_finished_(b->Finished()) {
      parent_a_ = std::static_pointer_cast<Shares::Share>(a);
      parent_b_ = std::static_pointer_cast<Shares::Share>(b);
      core_ = parent_a_->GetCore();

      assert(parent_a_->GetNumOfParallelValues() == parent_b_->GetNumOfParallelValues());
      output_.resize(parent_a_->GetNumOfParallelValues());
      requires_online_interaction_ = false;
      gate_type_ = GateType::NonInteractiveGate;

      gate_id_ = core_->NextGateId();
      core_->RegisterNextGate(static_cast<Gate *>(this));

      RegisterWaitingFor(parent_a_->GetWires().at(0)->GetWireId());
      parent_a_->GetWires().at(0)->RegisterWaitingGate(gate_id_);

      RegisterWaitingFor(parent_b_->GetWires().at(0)->GetWireId());
      parent_b_->GetWires().at(0)->RegisterWaitingGate(gate_id_);

      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::ArithmeticShare<T>>(output_, core_)));

      auto gate_info = fmt::format("uint{}_t type, gate id {}, parents: {}, {}", sizeof(T) * 8, gate_id_,
                                   Wires::Wire::PrintIds(parent_a_->GetWires()),
                                   Wires::Wire::PrintIds(parent_b_->GetWires()));
      core_->GetLogger()->LogTrace(fmt::format("Allocate an ArithmeticAdditionGate with following properties: {}",
                                               gate_info));

      SetSetupIsReady();
    }

    ~ArithmeticAdditionGate() final = default;

    void Evaluate() final {
      Helpers::WaitFor(parent_a_finished_);
      Helpers::WaitFor(parent_b_finished_);

      auto wire_a = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_a_->GetWires().at(0));
      auto wire_b = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(parent_b_->GetWires().at(0));

      assert(wire_a);
      assert(wire_b);

      output_ = Helpers::AddVectors(wire_a->GetValuesOnWire(), wire_b->GetValuesOnWire());

      auto arithmetic_share = std::dynamic_pointer_cast<Shares::ArithmeticShare<T>>(output_share_);
      arithmetic_share->GetArithmeticWire()->GetMutableValuesOnWire() = output_;
      output_.clear();

      SetOnlineIsReady();
      core_->IncrementEvaluatedGatesCounter();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_);
      assert(result);
      return result;
    }

    ArithmeticAdditionGate() = delete;

    ArithmeticAdditionGate(Gate &) = delete;

  protected:
    const bool &parent_a_finished_;
    const bool &parent_b_finished_;
    std::vector<T> output_;
  };

}

namespace ABYN::Gates::GMW {
  class GMWInputGate : public ABYN::Gates::Interfaces::InputGate {
  public:
    GMWInputGate(const std::vector<u8> &input, std::size_t party_id, const ABYN::CorePtr &core, std::size_t bits = 0) :
        input_({input}), bits_(bits), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    GMWInputGate(std::vector<u8> &&input, std::size_t party_id, const ABYN::CorePtr &core, std::size_t bits = 0) :
        input_({std::move(input)}), bits_(bits), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    GMWInputGate(const std::vector<std::vector<u8>> &input, std::size_t party_id, const ABYN::CorePtr &core,
                 std::size_t bits = 0) : input_({input}), bits_(bits), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    GMWInputGate(std::vector<std::vector<u8>> &&input, std::size_t party_id, const ABYN::CorePtr &core,
                 std::size_t bits = 0) : input_({std::move(input)}), bits_(bits), party_id_(party_id) {
      core_ = core;
      InitializationHelper();
    }

    void InitializationHelper() {
      gate_id_ = core_->NextGateId();
      core_->RegisterNextGate(static_cast<Gate *>(this));

      assert(input_.size() > 0);                          //assert >=1 wire
      assert(input_.at(0).size() > 0);                    //assert >=1 SIMD bits
      assert(ABYN::Helpers::Compare::Dimensions(input_)); //assert SIMD lengths of all wires are equal

      if (bits_ == 0) { bits_ = input_.at(0).size() * 8; }

      auto input_size = input_.at(0).size();
      boolean_sharing_id_ = core_->NextBooleanGMWSharingId(input_.size() * input_size * 8);
      core_->GetLogger()->LogTrace(fmt::format("Created an ArithmeticInputGate with global id {}", gate_id_));
      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::GMWShare>(input_, core_, bits_)));

      auto gate_info = fmt::format("gate id {},", gate_id_);
      core_->GetLogger()->LogDebug(fmt::format(
          "Allocate an ArithmeticInputGate with following properties: {}", gate_info));
    }

    ~GMWInputGate() final = default;

    void Evaluate() final {
      auto my_id = core_->GetConfig()->GetMyId();
      //we always generate the seed for input sharing before we start evaluating the circuit
      if (party_id_ == my_id) { SetSetupIsReady(); }

      std::vector<CBitVector> result(input_.size());
      auto sharing_id = boolean_sharing_id_;
      for (auto i = 0ull; i < result.size(); ++i) {
        if (party_id_ == my_id) {
          result.at(i).CreateExact(bits_);
          auto log_string = std::string("");
          for (auto j = 0u; j < core_->GetConfig()->GetNumOfParties(); ++j) {
            if (j == my_id) { continue; }

            auto &rand_generator = core_->GetConfig()->GetCommunicationContext(j)->GetMyRandomnessGenerator();
            auto randomness_vector = std::move(rand_generator->GetBits(sharing_id, bits_));

            log_string.append(fmt::format("id#{}:{} ", j, randomness_vector.at(0)));
            CBitVector randomness;
            randomness.AttachBuf(randomness_vector.data(), randomness_vector.size());
            result.at(i).XOR(&randomness);
            randomness.DetachBuf();
            sharing_id += bits_;
          }
          auto s = fmt::format(
              "My (id#{}) arithmetic input sharing for gate#{}, my input: {}, my share: {}, expected shares of other parties: {}",
              party_id_, gate_id_, input_.at(0).at(0) ^ result.at(0).GetByte(0), input_.at(0).at(0), log_string);
          core_->GetLogger()->LogTrace(s);
        } else {
          auto &rand_generator = core_->GetConfig()->GetCommunicationContext(party_id_)->GetTheirRandomnessGenerator();
          Helpers::WaitFor(rand_generator->IsInitialized());
          SetSetupIsReady();
          auto randomness_v = std::move(rand_generator->GetBits(sharing_id, bits_));
          result.at(i).Copy(randomness_v.data(), 0, randomness_v.size());

          auto s = fmt::format("Arithmetic input sharing (gate#{}) of Party's#{} input, got a share {} from the seed",
                               gate_id_, party_id_, result.at(0).GetByte(0));
          core_->GetLogger()->LogTrace(s);
          sharing_id += bits_;
        }
      }
      auto my_wires = output_share_->GetWires();
      for (auto i = 0ull; i < my_wires.size(); ++i) {
        auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(my_wires.at(i));
        assert(my_wire);
        auto buf = result.at(i).GetArr();
        result.at(i).DetachBuf();
        my_wire->GetMutableValuesOnWire().AttachBuf(buf);
      }
      SetOnlineIsReady();
      core_->IncrementEvaluatedGatesCounter();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
    };

    const ABYN::Shares::GMWSharePtr GetOutputGMWShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::GMWShare>(output_share_);
      assert(result);
      return result;
    }

  private:
    std::vector<std::vector<u8>> input_;

    std::size_t bits_;

    //indicates whether this party shares the input
    std::size_t party_id_;

    std::size_t boolean_sharing_id_;

    std::vector<CBitVector> output;
  };
}

#endif //GATE_H
