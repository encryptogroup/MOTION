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

//TODO: rearrange this code into multiple files

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
      assert(gate_id_ >= 0);
      core_->UnregisterGate(gate_id_);
    };

    virtual void Evaluate() = 0;

    const ABYN::Shares::SharePtr &GetOutputShare() {
      return output_share_;
    }

    std::shared_ptr<Gate> GetShared() { return shared_from_this(); }

    void RegisterWaitingFor(size_t wire_id) {
      std::scoped_lock lock(mutex_);
      wire_dependencies_.insert(wire_id);
    }

    void UnregisterWaitingFor(size_t wire_id) {
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
      std::scoped_lock lock(mutex_);
      setup_is_ready_ = true;
    }

    void SetOnlineIsReady() {
      std::scoped_lock lock(mutex_);
      online_is_ready_ = true;
      assert(output_share_);
      for (auto &wire : output_share_->GetWires()) {
        wire->SetOnlineFinished();
      }
    }

    bool &SetupIsReady() { return setup_is_ready_; }

  protected:
    ABYN::Shares::SharePtr output_share_;
    ABYN::CorePtr core_;
    ssize_t gate_id_ = -1;
    std::unordered_set<size_t> wire_dependencies_;
    GateType gate_type_ = InvalidGate;

    bool setup_is_ready_ = false;
    bool online_is_ready_ = false;
    bool requires_online_interaction_ = false;
    bool added_to_active_queue = false;

    Gate() {}

  private:
    void IfReadyAddToProcessingQueue() {
      if (DependenciesAreReady() && !added_to_active_queue) {
        core_->AddToActiveQueue(gate_id_);
        added_to_active_queue = true;
      }
    }

    Gate(Gate &) = delete;

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
    virtual ~OneGate() {}

    virtual void Evaluate() = 0;

  protected:
    ABYN::Shares::SharePtr parent_;

    OneGate() {}

  private:
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
    virtual ~InputGate() {}

    InputGate() { gate_type_ = GateType::InputGate; }

  private:
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
    OutputGate(const ABYN::Shares::SharePtr &parent, size_t output_owner) {
      core_ = parent->GetCore();
      parent_ = parent;
      output_owner_ = output_owner;
      gate_type_ = InteractiveGate;
      assert(output_owner_ >= 0);
    }

    virtual void Evaluate() = 0;

    virtual ~OutputGate() {}

  protected:
    OutputGate() {}

    OutputGate(OutputGate &) = delete;

    ssize_t output_owner_ = -1;
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

    TwoGate() {}

  public:

    virtual ~TwoGate() {}

    virtual void Evaluate() = 0;
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

  protected:
    std::vector<T> input_;

    //indicates whether this party shares the input
    size_t party_id_ = false;

  public:
    ArithmeticInputGate(const std::vector<T> &input, size_t party_id, const ABYN::CorePtr &core) :
        input_(input), party_id_(party_id) {
      core_ = core;
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

    ArithmeticInputGate(std::vector<T> &&input, size_t party_id, const ABYN::CorePtr &core) :
        ArithmeticInputGate(input, party_id, core) {}

    virtual ~ArithmeticInputGate() {}

    //non-interactive input sharing based on distributed in advance randomness seeds
    void Evaluate() override final {
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
      core_->NotifyEvaluatedGate();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticInputGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_);
      assert(result);
      return result;
    }

  private:
    ssize_t arithmetic_sharing_id_ = -1;


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

    ArithmeticOutputGate(const ABYN::Shares::ArithmeticSharePtr<T> &parent, size_t output_owner) :
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

      if (core_->GetConfig()->GetMyId() == static_cast<size_t>(output_owner_)) { is_my_output_ = true; }

      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::ArithmeticShare<T>>(output_, core_)));

      auto gate_info = fmt::format("uint{}_t type, gate id {},", sizeof(T) * 8, gate_id_);
      core_->GetLogger()->LogTrace(fmt::format("Allocate an ArithmeticOutputGate with following properties: {}",
                                               gate_info));
    }

    virtual ~ArithmeticOutputGate() {};

    void Evaluate() override final {
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
      core_->NotifyEvaluatedGate();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticOutputGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
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

    virtual ~ArithmeticAdditionGate() {}

    void Evaluate() override final {
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
      core_->NotifyEvaluatedGate();
      core_->GetLogger()->LogTrace(fmt::format("Evaluated ArithmeticAdditionGate with id#{}", gate_id_));
    }

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    ABYN::Shares::ArithmeticSharePtr<T> GetOutputArithmeticShare() {
      auto result = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(output_share_);
      assert(result);
      return result;
    }

  protected:
    const bool &parent_a_finished_;
    const bool &parent_b_finished_;
    std::vector<T> output_;

    ArithmeticAdditionGate() = delete;

    ArithmeticAdditionGate(Gate &) = delete;
  };
}


#endif //GATE_H
