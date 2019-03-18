#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include <memory>
#include <omp.h>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/constants.h"
#include "utility/configuration.h"
#include "abynparty/backend.h"
#include "gate/gate.h"
#include "share/share.h"
//#include "OTExtension/ot/ot-ext.h"

namespace ABYN {

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticSharePtr = ABYN::Shares::ArithmeticSharePtr<T>;

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticShare = ABYN::Shares::ArithmeticShare<T>;

  class Party {

  private:
    ConfigurationPtr config_;
    BackendPtr backend_;

    //Let's make only ABYNConfiguration be copyable
    Party() = delete;

    Party(Party &party) = delete;

    void EvaluateCircuit();

    void Finish();

  protected:


  public:

    Party(std::vector<CommunicationContextPtr> &parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(parties, my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::vector<CommunicationContextPtr> &&parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(std::move(parties), my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::initializer_list<CommunicationContextPtr> &list_parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(list_parties, my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::initializer_list<CommunicationContextPtr> &&list_parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(std::move(list_parties), my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(ConfigurationPtr &configuration) : config_(configuration) {}

    ~Party() {
      backend_->WaitForConnectionEnd();
      backend_->GetLogger()->LogInfo("ABYNParty has been deallocated");
    }

    ConfigurationPtr GetConfiguration() { return config_; }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> IN(std::size_t party_id, T input = 0) {
      std::vector<T> input_vector{input};
      return IN(party_id, std::move(input_vector));
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> IN(std::size_t party_id, const std::vector<T> &input_vector = 0) {
      auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
          input_vector, party_id, backend_->GetCore());
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return in_gate->GetOutputArithmeticShare();
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> IN(std::size_t party_id, std::vector<T> &&input_vector = 0) {
      auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
          std::move(input_vector), party_id, backend_->GetCore());
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return in_gate->GetOutputArithmeticShare();
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> OUT(ArithmeticSharePtr<T> parent, std::size_t output_owner) {
      assert(parent);
      auto out_gate = std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<T>>(parent, output_owner);
      auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
      backend_->RegisterGate(out_gate_cast);
      return out_gate->GetOutputArithmeticShare();
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ArithmeticSharePtr<T> ADD(const ArithmeticSharePtr<T> &a, const ArithmeticSharePtr<T> &b) {
      assert(a);
      assert(b);
      auto addition_gate = std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(a, b);
      auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
      backend_->RegisterGate(addition_gate_cast);
      return addition_gate->GetOutputArithmeticShare();
    }

    std::size_t GetNumOfParties() { return config_->GetNumOfParties(); }

    void Connect();

    void Run(std::size_t repeats = 1);

    static std::vector<std::unique_ptr<Party>> GetNLocalParties(std::size_t num_parties, u16 port);

    const auto &GetLogger() { return backend_->GetLogger(); }
  };

  using PartyPtr = std::unique_ptr<Party>;

}
#endif //ABYNPARTY_H
