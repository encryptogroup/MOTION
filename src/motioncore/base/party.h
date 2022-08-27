// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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

#include <fmt/format.h>
#include <memory>
#include <span>
#include <vector>

#include "base/backend.h"
#include "base/configuration.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share.h"
#include "utility/typedefs.h"

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion {

class Logger;

class Party {
 public:
  Party() = delete;

  // Let's make only Configuration be copyable
  Party(Party& party) = delete;

  Party(std::unique_ptr<communication::CommunicationLayer> communication_layer);

  ~Party();

  ConfigurationPointer GetConfiguration() { return configuration_; }

  template <MpcProtocol P>
  SharePointer In(std::span<const BitVector<>> input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MpcProtocol::kArithmeticGmw);
    static_assert(P != MpcProtocol::kArithmeticConstant);
    static_assert(P != MpcProtocol::kAstra);
    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBmr: {
        return backend_->BmrInput(party_id, input);
      }
      case MpcProtocol::kGarbledCircuit: {
        return backend_->GarbledCircuitInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P>
  std::pair<SharePointer, ReusableFiberPromise<std::vector<BitVector<>>>*> In(
      std::size_t input_owner_id, std::size_t number_of_wires, std::size_t number_of_simd) {
    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanGmw, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBmr: {
        // TODO implement
        static_assert(P != MpcProtocol::kBmr, "Not implemented yet");
        // return backend_->BmrInput(party_id, input);
      }
      case MpcProtocol::kGarbledCircuit: {
        return backend_->GarbledCircuitInput(input_owner_id, number_of_wires, number_of_simd);
      }
      default: {
        throw std::runtime_error(fmt::format("Unknown or unimplemented MPC protocol with id {}",
                                             static_cast<unsigned int>(P)));
      }
    }
  }

  template <MpcProtocol P>
  SharePointer In(std::vector<BitVector<>>&& input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MpcProtocol::kArithmeticGmw);
    static_assert(P != MpcProtocol::kArithmeticConstant);
    static_assert(P != MpcProtocol::kAstra);
    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        return backend_->BooleanGmwInput(party_id, std::move(input));
      }
      case MpcProtocol::kBmr: {
        return backend_->BmrInput(party_id, input);
      }
      case MpcProtocol::kGarbledCircuit: {
        return backend_->GarbledCircuitInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P>
  SharePointer In(const BitVector<>& input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MpcProtocol::kArithmeticGmw);
    static_assert(P != MpcProtocol::kArithmeticConstant);
    static_assert(P != MpcProtocol::kAstra);
    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBmr: {
        return backend_->BmrInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P>
  SharePointer In(BitVector<>&& input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MpcProtocol::kArithmeticGmw);
    static_assert(P != MpcProtocol::kArithmeticConstant);
    static_assert(P != MpcProtocol::kAstra);
    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        // TODO implement
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
        // return backend_->BooleanGmwInput(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        return backend_->BooleanGmwInput(party_id, std::move(input));
      }
      case MpcProtocol::kBmr: {
        return backend_->BmrInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P, typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
  SharePointer In(const std::vector<T>& input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    switch (P) {
      case MpcProtocol::kArithmeticConstant: {
        if constexpr (std::is_unsigned_v<T>) {
          return backend_->ConstantArithmeticGmwInput<T>(input);
        } else {
          return backend_->ConstantArithmeticGmwInput<std::make_unsigned_t<T>>(
              ToTwosComplement<T>(input));
        }
      }
      case MpcProtocol::kArithmeticGmw: {
        if constexpr (std::is_unsigned_v<T>) {
          return backend_->ArithmeticGmwInput<T>(party_id, input);
        } else {
          return backend_->ArithmeticGmwInput<std::make_unsigned_t<T>>(party_id,
                                                                       ToTwosComplement<T>(input));
        }
      }
      case MpcProtocol::kAstra: {
        return backend_->AstraInput<T>(party_id, input);
      }
      case MpcProtocol::kBooleanGmw: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BooleanGMW, "
            "consider using TODO function for the input");
      }
      case MpcProtocol::kBmr: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BMR, "
            "consider using TODO function for the input");
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P, typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
  SharePointer In(std::vector<T>&& input,
                  std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    switch (P) {
      case MpcProtocol::kArithmeticConstant: {
        if constexpr (std::is_unsigned_v<T>) {
          return backend_->ConstantArithmeticGmwInput<T>(input);
        } else {
          return backend_->ConstantArithmeticGmwInput<std::make_unsigned_t<T>>(
              ToTwosComplement<T>(input));
        }
      }
      case MpcProtocol::kArithmeticGmw: {
        if constexpr (std::is_unsigned_v<T>) {
          return backend_->ArithmeticGmwInput<T>(party_id, input);
        } else {
          return backend_->ArithmeticGmwInput<std::make_unsigned_t<T>>(party_id,
                                                                       ToTwosComplement<T>(input));
        }
      }
      case MpcProtocol::kAstra: {
        return backend_->AstraInput<T>(party_id, std::move(input));
      }
      case MpcProtocol::kBooleanGmw: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BooleanGMW, "
                        "consider using TODO function for the input")));
      }
      case MpcProtocol::kBmr: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BMR, "
                        "consider using TODO function for the input")));
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P, typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
  SharePointer In(T input, std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    if constexpr (std::is_same_v<T, bool>) {
      if constexpr (P == MpcProtocol::kBooleanGmw)
        return backend_->BooleanGmwInput(party_id, input);
      else
        return backend_->BmrInput(party_id, input);
    } else {
      return In<P, T>(std::vector<T>{input}, party_id);
    }
  }

  template <MpcProtocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer SharedIn(T input) {
    switch (P) {
      case MpcProtocol::kArithmeticConstant: {
        static_assert(P != MpcProtocol::kArithmeticConstant, "Not implemented yet");
      }
      case MpcProtocol::kArithmeticGmw: {
        encrypto::motion::RegisterPointer register_pointer{backend_->GetRegister()};

        encrypto::motion::WirePointer wire =
            register_pointer->EmplaceWire<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
                input, *backend_);
        wire->SetOnlineFinished();

        return std::make_shared<encrypto::motion::proto::arithmetic_gmw::Share<T>>(wire);
      }
      case MpcProtocol::kAstra: {
        static_assert(P != MpcProtocol::kAstra, "Not implemented yet");
      }
      case MpcProtocol::kBooleanGmw: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BooleanGMW, "
            "consider using TODO function for the input");
      }
      case MpcProtocol::kBmr: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BMR, "
            "consider using TODO function for the input");
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer SharedIn(const std::vector<T>& input) {
    switch (P) {
      case MpcProtocol::kArithmeticConstant: {
        static_assert(P != MpcProtocol::kArithmeticConstant, "Not implemented yet");
      }
      case MpcProtocol::kArithmeticGmw: {
        encrypto::motion::RegisterPointer register_pointer{backend_->GetRegister()};

        encrypto::motion::WirePointer wire =
            register_pointer->EmplaceWire<encrypto::motion::proto::arithmetic_gmw::Wire<T>>(
                input, *backend_);
        wire->SetOnlineFinished();

        return std::make_shared<encrypto::motion::proto::arithmetic_gmw::Share<T>>(wire);
      }
      case MpcProtocol::kAstra: {
        static_assert(P != MpcProtocol::kAstra, "Not implemented yet");
      }
      case MpcProtocol::kBooleanGmw: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BooleanGMW, "
            "consider using TODO function for the input");
      }
      case MpcProtocol::kBmr: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BMR, "
            "consider using TODO function for the input");
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  template <MpcProtocol P>
  SharePointer SharedIn(std::span<const BitVector<>> input) {
    static_assert(P != MpcProtocol::kArithmeticGmw);
    static_assert(P != MpcProtocol::kArithmeticConstant);
    static_assert(P != MpcProtocol::kAstra);

    switch (P) {
      case MpcProtocol::kBooleanConstant: {
        static_assert(P != MpcProtocol::kBooleanConstant, "Not implemented yet");
      }
      case MpcProtocol::kBooleanGmw: {
        std::vector<encrypto::motion::WirePointer> wires(input.size());
        encrypto::motion::RegisterPointer register_pointer{backend_->GetRegister()};

        for (std::size_t i = 0; i < wires.size(); i++) {
          wires[i] = register_pointer->EmplaceWire<encrypto::motion::proto::boolean_gmw::Wire>(
              input[i], *backend_);
          wires[i]->SetOnlineFinished();
        }

        return std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires);
      }
      case MpcProtocol::kBmr: {
        static_assert(P != MpcProtocol::kBmr, "Not implemented yet");
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<unsigned int>(P))));
      }
    }
  }

  SharePointer Out(SharePointer parent, std::size_t output_owner);

  /// \brief Evaluates the constructed gates a predefined number of times.
  /// This is realized via repeatedly calling Party::Clear() after each evaluation.
  /// If Connect() was not called yet, it is called automatically at the beginning of this method.
  /// @param repetitions Number of iterations.
  void Run(std::size_t repetitions = 1);

  /// \brief Destroys all the gates and wires that were constructed until now.
  void Reset();

  /// \brief Interprets the gates and wires as newly created, i.e., Party::Run()
  /// can be executed again.
  void Clear();

  const auto& GetLogger() { return logger_; }

  /// \brief Sends a termination message to all of the connected parties.
  /// In case a TCP connection is used, this will internally be interpreted as a signal to
  /// disconnect.
  ///
  /// This method is executed by the Party destructor, but if the parties are run
  /// locally, e.g., for testing purposes, the user SHALL ensure that Party::Finish() is run in
  /// parallel or otherwise the desctructors will likely be called sequentially which will result in
  /// a deadlock, since both connected parties must have sent a termination message and the
  /// destructor will wait for the other party to send the signal.
  /// It is allowed to call Party::Finish() multiple times.
  void Finish();

  auto& GetBackend() { return backend_; }

 private:
  ConfigurationPointer configuration_;
  std::shared_ptr<Logger> logger_;
  BackendPointer backend_;
  std::atomic<bool> finished_ = false;

  void EvaluateCircuit();
};

/// \brief constructs number_of_parties motion::Party's *locally* connected via TCP.
/// @param number_of_parties Number of motion::Party's to construct.
/// @param port TCP port offset.
/// @param logging Enables/disables logging completely.
std::vector<std::unique_ptr<Party>> MakeLocallyConnectedParties(const std::size_t number_of_parties,
                                                                std::uint16_t port,
                                                                const bool logging = false);

using PartyPointer = std::unique_ptr<Party>;

}  // namespace encrypto::motion
