#ifndef GATE_H
#define GATE_H

#include <iostream>
#include <vector>

#include "abynparty/abyncore.h"
#include "share/share.h"
#include "utility/typedefs.h"
#include "utility/constants.h"

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

  class Gate {
  public:
    virtual ~Gate() {};

    virtual void Evaluate() = 0;

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;

  protected:
    ABYN::Shares::SharePtr output_share_;
    ABYN::ABYNCorePtr core_;
    ssize_t gate_id_ = -1;
    size_t n_parallel_values_ = 1;

    Gate() {};

  private:
    Gate(Gate &) = delete;
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
    virtual ~OneGate() {};

    virtual void Evaluate() = 0;

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;

  protected:
    ABYN::Shares::SharePtr parent_;

    OneGate() {};

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

    virtual void Evaluate() = 0;

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;

  protected:
    virtual ~InputGate() {};

    InputGate() {};

  private:
    InputGate(InputGate &) = delete;

  };


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
    OutputGate(ABYN::Shares::SharePtr &parent, const ABYN::ABYNCorePtr &core) {
      core_ = core;
      parent_ = parent;
    };

    virtual void Evaluate() = 0;

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;

    virtual ~OutputGate() {};
  };

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

    TwoGate() {};

  public:

    virtual ~TwoGate() {};

    virtual void Evaluate() = 0;

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;
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

    nInputGate() {};

  public:
    virtual ~nInputGate() {};

    virtual void Evaluate() {}

    virtual const ABYN::Shares::SharePtr &GetOutputShare() = 0;
  };
}

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
  class ArithmeticInputGate : ABYN::Gates::Interfaces::InputGate {

  protected:
    T input_;

    //indicates whether this party shares the input
    size_t party_id_ = false;

  public:
    ArithmeticInputGate(T input, size_t party_id, const ABYN::ABYNCorePtr &core) :
    party_id_(party_id) {
      core_ = core;
      gate_id_ = core_->NextGateId();
      if (party_id_ == core_->GetConfig()->GetMyId()) { input_ = input; } //in case this is my input
      core_->GetLogger()->LogTrace(fmt::format("Created an ArithmeticInputGate with global id {}", gate_id_));
    };

    virtual ~ArithmeticInputGate() {};

    //non-interactive input sharing based on distributed in advance randomness seeds
    void Evaluate() override final {
      auto my_id = core_->GetConfig()->GetMyId();
      if (party_id_ == my_id) {
        T diff = 0;
        std::string log_string{};
        for (auto i = 0u; i < core_->GetConfig()->GetNumOfParties(); ++i) {
          if (i == my_id) { continue; }
          auto r = core_->GetConfig()->GetParty(i)->GetMyRandomnessGenerator()
              ->template GetUnsigned<T>(gate_id_);
          log_string.append(fmt::format("id#{}:{} ", r));
          diff += r;
        }
        input_ -= diff;

        auto s = fmt::format(
            "My (id#{}) arithmetic input sharing, my input: {}, my share: {}, expected shares of other parties: {}",
                             party_id_, input_, log_string);
        core_->GetLogger()->LogTrace(s);
      } else {
        input_ = core_->GetConfig()->GetParty(party_id_)->GetMyRandomnessGenerator()
            ->template GetUnsigned<T>(gate_id_);

        auto s = fmt::format("Arithmetic input sharing of Party#{} input, got a share {} from the seed",
                             party_id_, input_);
        core_->GetLogger()->LogTrace(s);
      }
      output_share_ = std::move(
          std::static_pointer_cast<ABYN::Shares::Share>(
              std::make_shared<ABYN::Shares::ArithmeticShare<T>>(input_, core_)));
    };

    //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
    const ABYN::Shares::SharePtr &GetOutputShare() override final { return output_share_; };
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticOutputGate : ABYN::Gates::Interfaces::OutputGate {
  protected:
    T output_;
    std::vector<T> shares_of_others_parties_;

    //indicates whether this party obtains the output
    bool my_output_ = false;
    bool others_get_output_ = false;
  public:
    ArithmeticOutputGate(ABYN::Shares::ArithmeticSharePtr<T> &previous_gate, size_t id, const ABYNCorePtr &core) {
      core_ = core;
      // TODO: implement
    }

    virtual ~ArithmeticOutputGate() {};

    void Evaluate() override final {
      //TODO: implement
      ;
    }

    ABYN::Shares::SharePtr &GetOutputShare() override final { return output_; };
  };
}


#endif //GATE_H
