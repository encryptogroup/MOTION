// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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
#include <vector>

#include "base/backend.h"
#include "base/configuration.h"
#include "utility/typedefs.h"

namespace MOTION {

class Logger;

namespace Communication{
  class CommunicationLayer;
}

class Party {
 public:
  Party() = delete;

  // Let's make only Configuration be copyable
  Party(Party &party) = delete;

  Party(std::unique_ptr<Communication::CommunicationLayer> parties);

  ~Party();

  ConfigurationPtr GetConfiguration() { return config_; }

  Communication::CommunicationLayer& get_communication_layer() {
    return *communication_layer_;
  }

  template <MPCProtocol P>
  Shares::SharePtr IN(const std::vector<ENCRYPTO::BitVector<>> &input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MPCProtocol::ArithmeticGMW);
    static_assert(P != MPCProtocol::ArithmeticConstant);
    switch (P) {
      case MPCProtocol::BooleanConstant: {
        // TODO implement
        static_assert(P != MPCProtocol::BooleanConstant, "Not implemented yet");
        // return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BooleanGMW: {
        return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BMR: {
        return backend_->BMRInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P>
  Shares::SharePtr IN(std::vector<ENCRYPTO::BitVector<>> &&input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MPCProtocol::ArithmeticGMW);
    static_assert(P != MPCProtocol::ArithmeticConstant);
    switch (P) {
      case MPCProtocol::BooleanConstant: {
        // TODO implement
        static_assert(P != MPCProtocol::BooleanConstant, "Not implemented yet");
        // return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BooleanGMW: {
        return backend_->BooleanGMWInput(party_id, std::move(input));
      }
      case MPCProtocol::BMR: {
        return backend_->BMRInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P>
  Shares::SharePtr IN(const ENCRYPTO::BitVector<> &input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MPCProtocol::ArithmeticGMW);
    static_assert(P != MPCProtocol::ArithmeticConstant);
    switch (P) {
      case MPCProtocol::BooleanConstant: {
        // TODO implement
        static_assert(P != MPCProtocol::BooleanConstant, "Not implemented yet");
        // return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BooleanGMW: {
        return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BMR: {
        return backend_->BMRInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P>
  Shares::SharePtr IN(ENCRYPTO::BitVector<> &&input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    static_assert(P != MPCProtocol::ArithmeticGMW);
    static_assert(P != MPCProtocol::ArithmeticConstant);
    switch (P) {
      case MPCProtocol::BooleanConstant: {
        // TODO implement
        static_assert(P != MPCProtocol::BooleanConstant, "Not implemented yet");
        // return backend_->BooleanGMWInput(party_id, input);
      }
      case MPCProtocol::BooleanGMW: {
        return backend_->BooleanGMWInput(party_id, std::move(input));
      }
      case MPCProtocol::BMR: {
        return backend_->BMRInput(party_id, input);
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(const std::vector<T> &input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    switch (P) {
      case MPCProtocol::ArithmeticConstant: {
        return backend_->ConstantArithmeticGMWInput(input);
      }
      case MPCProtocol::ArithmeticGMW: {
        return backend_->ArithmeticGMWInput(party_id, input);
      }
      case MPCProtocol::BooleanGMW: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BooleanGMW, "
            "consider using TODO function for the input");
      }
      case MPCProtocol::BMR: {
        throw std::runtime_error(
            "Non-binary types have to be converted to BitVectors in BMR, "
            "consider using TODO function for the input");
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(std::vector<T> &&input,
                      std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    switch (P) {
      case MPCProtocol::ArithmeticConstant: {
        return backend_->ConstantArithmeticGMWInput(std::move(input));
      }
      case MPCProtocol::ArithmeticGMW: {
        return backend_->ArithmeticGMWInput(party_id, std::move(input));
      }
      case MPCProtocol::BooleanGMW: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BooleanGMW, "
                        "consider using TODO function for the input")));
      }
      case MPCProtocol::BMR: {
        throw(std::runtime_error(
            fmt::format("Non-binary types have to be converted to BitVectors in BMR, "
                        "consider using TODO function for the input")));
      }
      default: {
        throw(std::runtime_error(
            fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(P))));
      }
    }
  }

  template <MPCProtocol P, typename T = std::uint8_t,
            typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr IN(T input, std::size_t party_id = std::numeric_limits<std::size_t>::max()) {
    if constexpr (std::is_same_v<T, bool>) {
      if constexpr (P == MPCProtocol::BooleanGMW)
        return backend_->BooleanGMWInput(party_id, input);
      else
        return backend_->BMRInput(party_id, input);
    } else {
      return IN<P, T>(std::vector<T>{input}, party_id);
    }
  }

  Shares::SharePtr XOR(const Shares::SharePtr &a, const Shares::SharePtr &b);

  Shares::SharePtr OUT(Shares::SharePtr parent, std::size_t output_owner);

  Shares::SharePtr ADD(const Shares::SharePtr &a, const Shares::SharePtr &b);

  Shares::SharePtr AND(const Shares::SharePtr &a, const Shares::SharePtr &b);

  /// \brief Evaluates the constructed gates a predefined number of times.
  /// This is realized via repeatedly calling Party::Clear() after each evaluation.
  /// If Connect() was not called yet, it is called automatically at the beginning of this method.
  /// @param repeats Number of iterations.
  void Run(std::size_t repeats = 1);

  /// \brief Destroys all the gates and wires that were constructed until now.
  void Reset();

  /// \brief Interprets the gates and wires as newly created, i.e., Party::Run()
  /// can be executed again.
  void Clear();

  const auto &GetLogger() { return logger_; }

  /// \brief Sends a termination message to all of the connected parties.
  /// In case a TCP connection is used, this will internally be interpreted as a signal to
  /// disconnect.
  ///
  /// This method is executed by the MOTION::Party destructor, but if the parties are run locally,
  /// e.g., for testing purposes, the user SHALL ensure that Party::Finish() is run in parallel
  /// or otherwise the desctructors will likely be called sequentially which will result in a
  /// deadlock, since both connected parties must have sent a termination message and the
  /// destructor will wait for the other party to send the signal.
  /// It is allowed to call Party::Finish() multiple times.
  void Finish();

  auto &GetBackend() { return backend_; }

 private:
  std::unique_ptr<Communication::CommunicationLayer> communication_layer_;
  ConfigurationPtr config_;
  std::shared_ptr<Logger> logger_;
  BackendPtr backend_;
  std::atomic<bool> finished_ = false;
  std::atomic<bool> connected_ = false;

  void EvaluateCircuit();
};

/// \brief Gets a std::vector of std::unique_ptrs to locally constructed MOTION parties connected
/// via TCP.
/// @param num_parties Number of MOTION parties.
/// @param port TCP port offset.
/// @param logging Enables/disables logging completely.
std::vector<std::unique_ptr<Party>> GetNLocalParties(const std::size_t num_parties,
                                                     std::uint16_t port,
                                                     const bool logging = false);

using PartyPtr = std::unique_ptr<Party>;
}  // namespace MOTION
