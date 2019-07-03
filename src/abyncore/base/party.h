#pragma once

#include <fmt/format.h>
#include <omp.h>
#include <memory>
#include <vector>

#include "base/backend.h"
#include "configuration.h"
#include "gate/arithmetic_gmw_gate.h"
#include "gate/boolean_gmw_gate.h"
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
  Party() = delete;

  // Let's make only Configuration be copyable
  Party(Party &party) = delete;

  Party(std::vector<Communication::ContextPtr> &parties, std::size_t my_id);

  Party(std::vector<Communication::ContextPtr> &&parties, std::size_t my_id);

  Party(std::initializer_list<Communication::ContextPtr> &&list_parties, std::size_t my_id);

  Party(ConfigurationPtr &configuration)
      : config_(configuration), backend_(std::make_shared<Backend>(config_)) {}

  ~Party();

  ConfigurationPtr GetConfiguration() { return config_; }

  template <Protocol P>
  Shares::SharePtr IN(const std::vector<ENCRYPTO::BitVector> &input, std::size_t party_id) {
    static_assert(P != Protocol::ArithmeticGMW);
    switch (P) {
      case Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, input);
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P>
  Shares::SharePtr IN(std::vector<ENCRYPTO::BitVector> &&input, std::size_t party_id) {
    static_assert(P != Protocol::ArithmeticGMW);
    switch (P) {
      case Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, std::move(input));
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P>
  Shares::SharePtr IN(const ENCRYPTO::BitVector &input, std::size_t party_id) {
    static_assert(P != Protocol::ArithmeticGMW);
    switch (P) {
      case Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, input);
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P>
  Shares::SharePtr IN(ENCRYPTO::BitVector &&input, std::size_t party_id) {
    static_assert(P != Protocol::ArithmeticGMW);
    switch (P) {
      case Protocol::BooleanGMW: {
        return BooleanGMWInput(party_id, std::move(input));
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(const std::vector<T> &input, std::size_t party_id) {
    switch (P) {
      case Protocol::ArithmeticGMW: {
        return ArithmeticGMWInput(party_id, input);
      }
      case Protocol::BooleanGMW: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BooleanGMW, "
                        "consider using TODO function for the input")));
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(std::vector<T> &&input, std::size_t party_id) {
    switch (P) {
      case Protocol::ArithmeticGMW: {
        return ArithmeticGMWInput(party_id, std::move(input));
      }
      case Protocol::BooleanGMW: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BooleanGMW, "
                        "consider using TODO function for the input")));
      }
      case Protocol::BMR: {
        static_assert(P != Protocol::BMR, "BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <Protocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(T input, std::size_t party_id) {
    if constexpr (std::is_same_v<T, bool>) {
      static_assert(P != Protocol::ArithmeticGMW, "Invalid input");
      return BooleanGMWInput(party_id, input);
    } else {
      return IN<P, T>(std::vector<T>{input}, party_id);
    }
  }

  Shares::SharePtr XOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
    assert(a);
    assert(b);
    assert(a->GetSharingType() != Protocol::ArithmeticGMW);
    assert(a->GetSharingType() == b->GetSharingType());
    switch (a->GetSharingType()) {
      case Protocol::BooleanGMW: {
        return BooleanGMWXOR(a, b);
      }
      case Protocol::BMR: {
        throw std::runtime_error("BMR protocol is not implemented yet");
        // TODO
      }
      default: {
        throw(std::runtime_error("Unknown protocol"));
      }
    }
  }

  Shares::SharePtr OUT(Shares::SharePtr parent, std::size_t output_owner);

  Shares::SharePtr ADD(const Shares::SharePtr &a, const Shares::SharePtr &b);

  std::size_t GetNumOfParties() { return config_->GetNumOfParties(); }

  void Connect();

  void Run(std::size_t repeats = 1);

  static std::vector<std::unique_ptr<Party>> GetNLocalParties(std::size_t num_parties,
                                                              std::uint16_t port,
                                                              bool logging = false);

  const auto &GetLogger() { return backend_->GetLogger(); }

 private:
  ConfigurationPtr config_;
  BackendPtr backend_;

  void EvaluateCircuit();

  void Finish();

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, bool input = false);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, const ENCRYPTO::BitVector &input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, ENCRYPTO::BitVector &&input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                   const std::vector<ENCRYPTO::BitVector> &input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, std::vector<ENCRYPTO::BitVector> &&input);

  Shares::SharePtr BooleanGMWXOR(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b);

  Shares::SharePtr BooleanGMWXOR(const Shares::SharePtr &a, const Shares::SharePtr &b);

  Shares::SharePtr BooleanGMWOutput(const Shares::SharePtr &parent, std::size_t output_owner);

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, T input = 0) {
    std::vector<T> input_vector{input};
    return IN(party_id, std::move(input_vector));
  };

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, const std::vector<T> &input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        input_vector, party_id, backend_->GetRegister());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, std::vector<T> &&input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        std::move(input_vector), party_id, backend_->GetRegister());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    backend_->RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWOutput(const ArithmeticSharePtr<T> &parent,
                                       std::size_t output_owner) {
    assert(parent);
    auto out_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<T>>(parent, output_owner);
    auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
    backend_->RegisterGate(out_gate_cast);
    return std::static_pointer_cast<Shares::Share>(out_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWOutput(const Shares::SharePtr &parent, std::size_t output_owner) {
    assert(parent);
    auto casted_parent_ptr = std::dynamic_pointer_cast<Shares::ArithmeticShare<T>>(parent);
    assert(casted_parent_ptr);
    return ArithmeticGMWOutput(casted_parent_ptr, output_owner);
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWAddition(const ArithmeticSharePtr<T> &a,
                                         const ArithmeticSharePtr<T> &b) {
    assert(a);
    assert(b);
    auto wire_a = a->GetArithmeticWire();
    auto wire_b = b->GetArithmeticWire();
    auto addition_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(wire_a, wire_b);
    auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
    backend_->RegisterGate(addition_gate_cast);
    return std::static_pointer_cast<Shares::Share>(addition_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWAddition(const Shares::SharePtr &a, const Shares::SharePtr &b) {
    assert(a);
    assert(b);
    auto casted_parent_a_ptr = std::dynamic_pointer_cast<Shares::ArithmeticShare<T>>(a);
    auto casted_parent_b_ptr = std::dynamic_pointer_cast<Shares::ArithmeticShare<T>>(b);
    assert(casted_parent_a_ptr);
    assert(casted_parent_b_ptr);
    return ArithmeticGMWAddition(casted_parent_a_ptr, casted_parent_b_ptr);
  }
};

using PartyPtr = std::unique_ptr<Party>;
}  // namespace ABYN