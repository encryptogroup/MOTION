#pragma once

#include <fmt/format.h>
#include <omp.h>
#include <memory>
#include <vector>

#include "base/backend.h"
#include "configuration.h"
#include "gate/gate.h"
#include "share/share.h"
#include "utility/constants.h"
#include "utility/typedefs.h"

namespace ABYN {

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticSharePtr = Shares::ArithmeticSharePtr<T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticShare = Shares::ArithmeticShare<T>;

class Party {
 public:
  Party(std::vector<Communication::ContextPtr> &parties, std::size_t my_id);

  Party(std::vector<Communication::ContextPtr> &&parties, std::size_t my_id);

  Party(std::initializer_list<Communication::ContextPtr> &list_parties,
        std::size_t my_id);

  Party(std::initializer_list<Communication::ContextPtr> &&list_parties,
        std::size_t my_id);

  Party(ConfigurationPtr &configuration) : config_(configuration) {}

  ~Party();

  ConfigurationPtr GetConfiguration() { return config_; }

  template <ABYN::Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr IN(const std::vector<T> &input, std::size_t party_id,
                            std::size_t bits = 0) {
    switch (P) {
      case ABYN::Protocol::ArithmeticGMW: {
        return ArithmeticGMWInput(party_id, input);
      }
      case ABYN::Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, input);
      }
      case ABYN::Protocol::BMR: {
        throw(std::runtime_error("BMR protocol is not implemented yet"));
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <ABYN::Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr IN(std::vector<T> &&input, std::size_t party_id, std::size_t bits = 0) {
    switch (P) {
      case ABYN::Protocol::ArithmeticGMW: {
        return ArithmeticGMWInput(party_id, std::move(input));
      }
      case ABYN::Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, std::move(input));
      }
      case ABYN::Protocol::BMR: {
        throw(std::runtime_error("BMR input gate is not implemented yet"));
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <ABYN::Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr IN(T input, std::size_t party_id, std::size_t bits = 0) {
    if constexpr (std::is_same_v<T, bool>) {
      static_assert(P != ABYN::Protocol::ArithmeticGMW);
      return BooleanGMWInput(party_id, input);
    } else {
      return IN<P, T>(std::vector<T>{input}, party_id, bits);
    }
  }

  ABYN::Shares::SharePtr OUT(ABYN::Shares::SharePtr parent, std::size_t output_owner);

  ABYN::Shares::SharePtr ADD(const ABYN::Shares::SharePtr &a, const ABYN::Shares::SharePtr &b);

  std::size_t GetNumOfParties() { return config_->GetNumOfParties(); }

  void Connect();

  void Run(std::size_t repeats = 1);

  static std::vector<std::unique_ptr<Party>> GetNLocalParties(std::size_t num_parties,
                                                              std::uint16_t port);

  const auto &GetLogger() { return backend_->GetLogger(); }

 private:
  ConfigurationPtr config_;
  BackendPtr backend_;

  Party() = delete;

  // Let's make only Configuration be copyable
  Party(Party &party) = delete;

  void EvaluateCircuit();

  void Finish();

  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, bool input = false);

  // if \param bits is set to 0, the bit-length of the input vector is taken
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, const ENCRYPTO::BitVector &input);
  /*
  // if \param bits is set to 0, the bit-length of the input vector is taken
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                         const std::vector<std::byte> &input,
                                         std::size_t bits = 0) {
    auto in_gate =
        std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, backend_->GetRegister(), bits);
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
  };

  // if \param bits is set to 0, the bit-length of the input vector is taken
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, std::vector<std::byte> &&input,
                                         std::size_t bits = 0) {
    auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id,
                                                              backend_->GetRegister(), bits);
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
  };

  // if \param bits is set to 0, the bit-length of the input vector is taken
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                         std::vector<std::vector<std::uint8_t>> &input,
                                         std::size_t bits = 0) {
    auto in_gate =
        std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, backend_->GetRegister(), bits);
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
  };

  // if \param bits is set to 0, the bit-length of the input vector is taken
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                         std::vector<std::vector<std::uint8_t>> &&input,
                                         std::size_t bits = 0) {
    auto in_gate = std::make_shared<ABYN::Gates::GMW::GMWInputGate>(std::move(input), party_id,
                                                                    backend_->GetRegister(), bits);
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<ABYN::Shares::Share>(in_gate->GetOutputAsGMWShare());
  };
*/
  // if \param bits is set to 0, the bit-length of the input vector is taken
  template <typename T>
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, const std::vector<T> &input,
                                         std::size_t bits = 0) {
    throw(std::runtime_error("BooleanGMWInput for arbitrary types is not implemented yet"));
  }

  // if \param bits is set to 0, the bit-length of the input vector is taken
  template <typename T>
  ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, std::vector<T> &&input,
                                         std::size_t bits = 0) {
    throw(std::runtime_error("BooleanGMWInput for arbitrary types is not implemented yet"));
  }

  ABYN::Shares::SharePtr BooleanGMWOutput(const ABYN::Shares::SharePtr &parent,
                                          std::size_t output_owner) {
    assert(parent);
    auto out_gate = std::make_shared<Gates::GMW::GMWOutputGate>(parent->GetWires(), output_owner);
    auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
    backend_->RegisterGate(out_gate_cast);
    return std::static_pointer_cast<ABYN::Shares::Share>(out_gate->GetOutputAsShare());
  }

  // if \param bits is set to 0, the bit-length of the input vector is taken
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, T input = 0) {
    std::vector<T> input_vector{input};
    return IN(party_id, std::move(input_vector));
  };

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id,
                                            const std::vector<T> &input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        input_vector, party_id, backend_->GetRegister());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, std::vector<T> &&input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        std::move(input_vector), party_id, backend_->GetRegister());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWOutput(const ArithmeticSharePtr<T> &parent,
                                             std::size_t output_owner) {
    assert(parent);
    auto out_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<T>>(parent, output_owner);
    auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
    backend_->RegisterGate(out_gate_cast);
    return std::static_pointer_cast<ABYN::Shares::Share>(out_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWOutput(const ABYN::Shares::SharePtr &parent,
                                             std::size_t output_owner) {
    assert(parent);
    auto casted_parent_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(parent);
    assert(casted_parent_ptr);
    return ArithmeticGMWOutput(casted_parent_ptr, output_owner);
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWAddition(const ArithmeticSharePtr<T> &a,
                                               const ArithmeticSharePtr<T> &b) {
    assert(a);
    assert(b);
    auto wire_a = a->GetArithmeticWire();
    auto wire_b = b->GetArithmeticWire();
    auto addition_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(wire_a, wire_b);
    auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
    backend_->RegisterGate(addition_gate_cast);
    return std::static_pointer_cast<ABYN::Shares::Share>(
        addition_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ABYN::Shares::SharePtr ArithmeticGMWAddition(const ABYN::Shares::SharePtr &a,
                                               const ABYN::Shares::SharePtr &b) {
    assert(a);
    assert(b);
    auto casted_parent_a_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(a);
    auto casted_parent_b_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(b);
    assert(casted_parent_a_ptr);
    assert(casted_parent_b_ptr);
    return ArithmeticGMWAddition(casted_parent_a_ptr, casted_parent_b_ptr);
  }
};

using PartyPtr = std::unique_ptr<Party>;
}  // namespace ABYN