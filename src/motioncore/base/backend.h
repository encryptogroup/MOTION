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

#include <memory>

#include "flatbuffers/flatbuffers.h"

#include "gate/arithmetic_gmw_gate.h"

static_assert(FLATBUFFERS_LITTLEENDIAN);

namespace ENCRYPTO::ObliviousTransfer {
class OTProvider;
}

namespace MOTION {
class MTProvider;

class Logger;
using LoggerPtr = std::shared_ptr<Logger>;

class Configuration;
using ConfigurationPtr = std::shared_ptr<Configuration>;

class Register;
using RegisterPtr = std::shared_ptr<Register>;

namespace Shares {
class GMWShare;
using GMWSharePtr = std::shared_ptr<GMWShare>;
}  // namespace Shares

namespace Gates::Interfaces {
class Gate;
using GatePtr = std::shared_ptr<Gate>;

class InputGate;
using InputGatePtr = std::shared_ptr<InputGate>;
}  // namespace Gates::Interfaces

namespace Communication {
class Handler;
using HandlerPtr = std::shared_ptr<Handler>;
}  // namespace Communication

class Backend : public std::enable_shared_from_this<Backend> {
 public:
  Backend() = delete;

  Backend(ConfigurationPtr &config);

  ~Backend() = default;

  const ConfigurationPtr &GetConfig() const noexcept { return config_; }

  const LoggerPtr &GetLogger() const noexcept;

  const RegisterPtr &GetRegister() const noexcept { return register_; }

  std::size_t NextGateId() const;

  void InitializeCommunicationHandlers();

  void SendHelloToOthers();

  void VerifyHelloMessages();

  void Send(std::size_t party_id, flatbuffers::FlatBufferBuilder &&message);

  void RegisterInputGate(const Gates::Interfaces::InputGatePtr &input_gate);

  void RegisterGate(const Gates::Interfaces::GatePtr &gate);

  void EvaluateSequential();

  void EvaluateParallel();

  void TerminateCommunication();

  void WaitForConnectionEnd();

  const Gates::Interfaces::GatePtr &GetGate(std::size_t gate_id) const;

  const std::vector<Gates::Interfaces::GatePtr> &GetInputGates() const;

  void Reset();

  void Clear();

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, bool input = false);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, const ENCRYPTO::BitVector<> &input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id, ENCRYPTO::BitVector<> &&input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                   const std::vector<ENCRYPTO::BitVector<>> &input);

  Shares::SharePtr BooleanGMWInput(std::size_t party_id,
                                   std::vector<ENCRYPTO::BitVector<>> &&input);

  Shares::SharePtr BooleanGMWXOR(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b);

  Shares::SharePtr BooleanGMWXOR(const Shares::SharePtr &a, const Shares::SharePtr &b);

  Shares::SharePtr BooleanGMWAND(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b);

  Shares::SharePtr BooleanGMWAND(const Shares::SharePtr &a, const Shares::SharePtr &b);

  Shares::SharePtr BooleanGMWOutput(const Shares::SharePtr &parent, std::size_t output_owner);

  Shares::SharePtr BMRInput(std::size_t party_id, bool input = false);

  Shares::SharePtr BMRInput(std::size_t party_id, const ENCRYPTO::BitVector<> &input);

  Shares::SharePtr BMRInput(std::size_t party_id, ENCRYPTO::BitVector<> &&input);

  Shares::SharePtr BMRInput(std::size_t party_id, const std::vector<ENCRYPTO::BitVector<>> &input);

  Shares::SharePtr BMRInput(std::size_t party_id, std::vector<ENCRYPTO::BitVector<>> &&input);

  Shares::SharePtr BMROutput(const Shares::SharePtr &parent, std::size_t output_owner);

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, T input = 0) {
    std::vector<T> input_vector{input};
    return ArithmeticGMWInput(party_id, std::move(input_vector));
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, const std::vector<T> &input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        input_vector, party_id, weak_from_this());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, std::vector<T> &&input_vector) {
    auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
        std::move(input_vector), party_id, weak_from_this());
    auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
    RegisterInputGate(in_gate_cast);
    return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  Shares::SharePtr ArithmeticGMWOutput(const Shares::ArithmeticSharePtr<T> &parent,
                                       std::size_t output_owner) {
    assert(parent);
    auto out_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<T>>(parent, output_owner);
    auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
    RegisterGate(out_gate_cast);
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
  Shares::SharePtr ArithmeticGMWAddition(const Shares::ArithmeticSharePtr<T> &a,
                                         const Shares::ArithmeticSharePtr<T> &b) {
    assert(a);
    assert(b);
    auto wire_a = a->GetArithmeticWire();
    auto wire_b = b->GetArithmeticWire();
    auto addition_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(wire_a, wire_b);
    auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
    RegisterGate(addition_gate_cast);
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

  /// \brief Blocking wait for synchronizing between parties. Called in Clear() and Reset()
  void Sync();

  void ComputeBaseOTs();

  void ImportBaseOTs(std::size_t i);

  void ImportBaseOTs();

  void ExportBaseOTs();

  void GenerateFixedKeyAESKey();

  void OTExtensionSetup();

  auto &GetOTProvider(const std::size_t i) { return ot_provider_.at(i); };

  auto &GetMTProvider() { return mt_provider_; };

 private:
  ConfigurationPtr config_;
  RegisterPtr register_;

  std::vector<Communication::HandlerPtr> communication_handlers_;
  std::vector<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTProvider>> ot_provider_;
  std::shared_ptr<MTProvider> mt_provider_;

  bool share_inputs_{true};
  bool require_base_ots_{false};
  bool base_ots_finished_{false};
  bool ot_extension_finished_{false};

  bool NeedOTs();
};

using BackendPtr = std::shared_ptr<Backend>;
}  // namespace MOTION
