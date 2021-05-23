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

#include <flatbuffers/flatbuffers.h>
#include <span>

#include "protocols/arithmetic_gmw/arithmetic_gmw_gate.h"
#include "protocols/constant/constant_gate.h"

static_assert(FLATBUFFERS_LITTLEENDIAN);

namespace encrypto::motion::communication {

class CommunicationLayer;

}  // namespace encrypto::motion::communication

namespace encrypto::motion::proto::boolean_gmw {

class Share;
using SharePointer = std::shared_ptr<Share>;

}  // namespace encrypto::motion::proto::boolean_gmw

namespace encrypto::motion::proto::bmr {

class Provider;

}  // namespace encrypto::motion::proto::bmr

namespace encrypto::motion {

class OtProvider;
class OtProviderManager;
class BaseOtProvider;
class BaseProvider;

class Gate;
using GatePointer = std::shared_ptr<Gate>;
class InputGate;
using InputGatePointer = std::shared_ptr<InputGate>;

class MtProvider;
class SpProvider;
class SbProvider;

struct RunTimeStatistics;

struct SenderMessage;
struct ReceiverMessage;

class Logger;
using LoggerPointer = std::shared_ptr<Logger>;

class Configuration;
using ConfigurationPointer = std::shared_ptr<Configuration>;

class Register;
using RegisterPointer = std::shared_ptr<Register>;

class GateExecutor;

class Backend : public std::enable_shared_from_this<Backend> {
 public:
  Backend() = delete;

  Backend(communication::CommunicationLayer& communication_layer,
          ConfigurationPointer& configuration, std::shared_ptr<Logger> logger);

  ~Backend();

  const ConfigurationPointer& GetConfiguration() const noexcept { return configuration_; }

  const LoggerPointer& GetLogger() const noexcept;

  const RegisterPointer& GetRegister() const noexcept { return register_; }

  std::size_t NextGateId() const;

  void Send(std::size_t party_id, flatbuffers::FlatBufferBuilder&& message);

  void RegisterInputGate(const InputGatePointer& input_gate);

  void RegisterGate(const GatePointer& gate);

  void RunPreprocessing();

  void EvaluateSequential();

  void EvaluateParallel();

  const GatePointer& GetGate(std::size_t gate_id) const;

  const std::vector<GatePointer>& GetInputGates() const;

  void Reset();

  void Clear();

  SharePointer BooleanGmwInput(std::size_t party_id, bool input = false);

  SharePointer BooleanGmwInput(std::size_t party_id, const BitVector<>& input);

  SharePointer BooleanGmwInput(std::size_t party_id, BitVector<>&& input);

  SharePointer BooleanGmwInput(std::size_t party_id, std::span<const BitVector<>> input);

  SharePointer BooleanGmwInput(std::size_t party_id, std::vector<BitVector<>>&& input);

  SharePointer BooleanGmwXor(const proto::boolean_gmw::SharePointer& a,
                             const proto::boolean_gmw::SharePointer& b);

  SharePointer BooleanGmwXor(const SharePointer& a, const SharePointer& b);

  SharePointer BooleanGmwAnd(const proto::boolean_gmw::SharePointer& a,
                             const proto::boolean_gmw::SharePointer& b);

  SharePointer BooleanGmwAnd(const SharePointer& a, const SharePointer& b);

  SharePointer BooleanGmwMux(const proto::boolean_gmw::SharePointer& a,
                             const proto::boolean_gmw::SharePointer& b,
                             const proto::boolean_gmw::SharePointer& selection);

  SharePointer BooleanGmwMux(const SharePointer& a, const SharePointer& b,
                             const SharePointer& selection);

  SharePointer BooleanGmwOutput(const SharePointer& parent, std::size_t output_owner);

  SharePointer BmrInput(std::size_t party_id, bool input = false);

  SharePointer BmrInput(std::size_t party_id, const BitVector<>& input);

  SharePointer BmrInput(std::size_t party_id, BitVector<>&& input);

  SharePointer BmrInput(std::size_t party_id, std::span<const BitVector<>> input);

  SharePointer BmrInput(std::size_t party_id, std::vector<BitVector<>>&& input);

  SharePointer BmrOutput(const SharePointer& parent, std::size_t output_owner);

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ConstantArithmeticGmwInput(T input = 0) {
    return ConstantArithmeticGmwInput({input});
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ConstantArithmeticGmwInput(const std::vector<T>& input_vector) {
    auto input_gate = std::make_shared<proto::ConstantArithmeticInputGate<T>>(input_vector, *this);
    RegisterGate(input_gate);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ConstantArithmeticGmwInput(std::vector<T>&& input_vector) {
    auto input_gate =
        std::make_shared<proto::ConstantArithmeticInputGate<T>>(std::move(input_vector), *this);
    RegisterGate(input_gate);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwInput(std::size_t party_id, T input = 0) {
    std::vector<T> input_vector{input};
    return ArithmeticGmwInput(party_id, std::move(input_vector));
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwInput(std::size_t party_id, const std::vector<T>& input_vector) {
    auto input_gate =
        std::make_shared<proto::arithmetic_gmw::InputGate<T>>(input_vector, party_id, *this);
    auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
    RegisterInputGate(input_gate_cast);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwInput(std::size_t party_id, std::vector<T>&& input_vector) {
    auto input_gate = std::make_shared<proto::arithmetic_gmw::InputGate<T>>(std::move(input_vector),
                                                                            party_id, *this);
    auto input_gate_cast = std::static_pointer_cast<InputGate>(input_gate);
    RegisterInputGate(input_gate_cast);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwOutput(const proto::arithmetic_gmw::SharePointer<T>& parent,
                                   std::size_t output_owner) {
    assert(parent);
    auto output_gate = std::make_shared<proto::arithmetic_gmw::OutputGate<T>>(parent, output_owner);
    auto out_gate_cast = std::static_pointer_cast<Gate>(output_gate);
    RegisterGate(out_gate_cast);
    return std::static_pointer_cast<Share>(output_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwOutput(const SharePointer& parent, std::size_t output_owner) {
    assert(parent);
    auto casted_parent_pointer = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(parent);
    assert(casted_parent_pointer);
    return ArithmeticGmwOutput(casted_parent_pointer, output_owner);
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwAddition(const proto::arithmetic_gmw::SharePointer<T>& a,
                                     const proto::arithmetic_gmw::SharePointer<T>& b) {
    assert(a);
    assert(b);
    auto wire_a = a->GetArithmeticWire();
    auto wire_b = b->GetArithmeticWire();
    auto addition_gate = std::make_shared<proto::arithmetic_gmw::AdditionGate<T>>(wire_a, wire_b);
    auto addition_gate_cast = std::static_pointer_cast<Gate>(addition_gate);
    RegisterGate(addition_gate_cast);
    return std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwAddition(const SharePointer& a, const SharePointer& b) {
    assert(a);
    assert(b);
    auto casted_parent_a_ptr = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(a);
    auto casted_parent_b_ptr = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(b);
    assert(casted_parent_a_ptr);
    assert(casted_parent_b_ptr);
    return ArithmeticGmwAddition(casted_parent_a_ptr, casted_parent_b_ptr);
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwSubtraction(const proto::arithmetic_gmw::SharePointer<T>& a,
                                        const proto::arithmetic_gmw::SharePointer<T>& b) {
    assert(a);
    assert(b);
    auto wire_a = a->GetArithmeticWire();
    auto wire_b = b->GetArithmeticWire();
    auto sub_gate = std::make_shared<proto::arithmetic_gmw::SubtractionGate<T>>(wire_a, wire_b);
    auto sub_gate_cast = std::static_pointer_cast<Gate>(sub_gate);
    RegisterGate(sub_gate_cast);
    return std::static_pointer_cast<Share>(sub_gate->GetOutputAsArithmeticShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ArithmeticGmwSubtraction(const SharePointer& a, const SharePointer& b) {
    assert(a);
    assert(b);
    auto casted_parent_a_ptr = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(a);
    auto casted_parent_b_ptr = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(b);
    assert(casted_parent_a_ptr);
    assert(casted_parent_b_ptr);
    return ArithmeticGmwSubtraction(casted_parent_a_ptr, casted_parent_b_ptr);
  }

  /// \brief Blocking wait for synchronizing between parties. Called in Clear() and Reset()
  void Synchronize();

  void ComputeBaseOts();

  void ImportBaseOts(std::size_t i, const ReceiverMessage& messages);

  void ImportBaseOts(std::size_t i, const SenderMessage& messages);

  std::pair<ReceiverMessage, SenderMessage> ExportBaseOts(std::size_t i);

  void OtExtensionSetup();

  communication::CommunicationLayer& GetCommunicationLayer() { return communication_layer_; };

  BaseProvider& GetBaseProvider() { return *motion_base_provider_; };

  proto::bmr::Provider& GetBmrProvider() { return *bmr_provider_; };

  auto& GetBaseOtProvider() { return base_ot_provider_; };

  OtProvider& GetOtProvider(std::size_t party_id);

  auto& GetMtProvider() { return mt_provider_; };

  auto& GetSpProvider() { return sp_provider_; };

  auto& GetSbProvider() { return sb_provider_; };

  const auto& GetRunTimeStatistics() const { return run_time_statistics_; }

  auto& GetMutableRunTimeStatistics() { return run_time_statistics_; }

 private:
  std::list<RunTimeStatistics> run_time_statistics_;

  communication::CommunicationLayer& communication_layer_;
  std::shared_ptr<Logger> logger_;
  ConfigurationPointer configuration_;
  RegisterPointer register_;
  std::unique_ptr<GateExecutor> gate_executor_;

  std::unique_ptr<BaseProvider> motion_base_provider_;
  std::unique_ptr<BaseOtProvider> base_ot_provider_;
  std::unique_ptr<OtProviderManager> ot_provider_manager_;
  std::shared_ptr<MtProvider> mt_provider_;
  std::shared_ptr<SpProvider> sp_provider_;
  std::shared_ptr<SbProvider> sb_provider_;
  std::unique_ptr<proto::bmr::Provider> bmr_provider_;

  bool require_base_ots_{false};
  bool base_ots_finished_{false};
  bool ot_extension_finished_{false};

  bool NeedOts();
};

using BackendPointer = std::shared_ptr<Backend>;

}  // namespace encrypto::motion
