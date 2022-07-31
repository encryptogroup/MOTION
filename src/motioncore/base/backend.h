// MIT License
//
// Copyright (c) 2019-2022 Oleksandr Tkachenko, Arianne Roselina Prananto
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

namespace encrypto::motion::proto {

namespace bmr {
class Provider;
}
namespace garbled_circuit {
class Provider;
}

}  // namespace encrypto::motion::proto

namespace encrypto::motion::proto::astra {

template <typename T>
class Share;
template <typename T>
using SharePointer = std::shared_ptr<Share<T>>;

}  // namespace encrypto::motion::proto::astra

namespace encrypto::motion {

class BaseOtProvider;
class BaseProvider;
class Kk13OtProvider;
class Kk13OtProviderManager;
class OtProvider;
class OtProviderManager;

class Gate;
using GatePointer = std::shared_ptr<Gate>;
class InputGate;
using InputGatePointer = std::shared_ptr<InputGate>;

class GarbledCircuitProvider;
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
  Backend(const Backend&) = delete;

  Backend(std::unique_ptr<communication::CommunicationLayer> communication_layer,
          ConfigurationPointer configuration, std::shared_ptr<Logger> logger);

  ~Backend();

  const ConfigurationPointer& GetConfiguration() const noexcept { return configuration_; }

  const LoggerPointer& GetLogger() const noexcept;

  const RegisterPointer& GetRegister() const noexcept { return register_; }

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
    auto input_gate =
        register_->EmplaceGate<proto::ConstantArithmeticInputGate<T>>(input_vector, *this);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsShare());
  }

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  SharePointer ConstantArithmeticGmwInput(std::vector<T>&& input_vector) {
    auto input_gate =
        register_->EmplaceGate<proto::ConstantArithmeticInputGate<T>>(input_vector, *this);
    return std::static_pointer_cast<Share>(input_gate->GetOutputAsShare());
  }

  template <typename T>
  SharePointer ArithmeticGmwInput(std::size_t party_id, T input = 0);

  template <typename T>
  SharePointer ArithmeticGmwInput(std::size_t party_id, const std::vector<T>& input_vector);

  template <typename T>
  SharePointer ArithmeticGmwInput(std::size_t party_id, std::vector<T>&& input_vector);

  template <typename T>
  SharePointer ArithmeticGmwOutput(const proto::arithmetic_gmw::SharePointer<T>& parent,
                                   std::size_t output_owner);

  template <typename T>
  SharePointer ArithmeticGmwOutput(const SharePointer& parent, std::size_t output_owner);

  template <typename T>
  SharePointer AstraInput(std::size_t party_id, T input = 0);

  template <typename T>
  SharePointer AstraInput(std::size_t party_id, std::vector<T> input);

  template <typename T>
  SharePointer AstraOutput(const proto::astra::SharePointer<T>& parent, std::size_t output_owner);

  template <typename T>
  SharePointer AstraOutput(const SharePointer& parent, std::size_t output_owner);

  SharePointer GarbledCircuitInput(std::size_t party_id, bool input = false);

  SharePointer GarbledCircuitInput(std::size_t party_id, const BitVector<>& input);

  SharePointer GarbledCircuitInput(std::size_t party_id, BitVector<>&& input);

  SharePointer GarbledCircuitInput(std::size_t party_id, std::span<const BitVector<>> input);

  SharePointer GarbledCircuitInput(std::size_t party_id, std::vector<BitVector<>>&& input);

  std::pair<SharePointer, ReusableFiberPromise<std::vector<BitVector<>>>*>
  GarbledCircuitInput(std::size_t party_id, std::size_t number_of_wires,
                      std::size_t number_of_simd);

  SharePointer GarbledCircuitOutput(const SharePointer& parent, std::size_t output_owner);

  /// \brief Blocking wait for synchronizing between parties. Called in Clear() and Reset()
  void Synchronize();

  void ComputeBaseOts();

  void OtExtensionSetup();

  communication::CommunicationLayer& GetCommunicationLayer() { return *communication_layer_; }

  BaseProvider& GetBaseProvider() { return *motion_base_provider_; }

  proto::bmr::Provider& GetBmrProvider() { return *bmr_provider_; }

  BaseOtProvider& GetBaseOtProvider() { return *base_ot_provider_; }

  OtProvider& GetOtProvider(std::size_t party_id);

  OtProviderManager& GetOtProviderManager() { return *ot_provider_manager_; }

  Kk13OtProvider& GetKk13OtProvider(std::size_t party_id);

  Kk13OtProviderManager& GetKk13OtProviderManager() { return *kk13_ot_provider_manager_; }

  auto& GetMtProvider() { return *mt_provider_; }

  auto& GetSpProvider() { return *sp_provider_; }

  auto& GetSbProvider() { return *sb_provider_; }

  auto& GetGarbledCircuitProvider() { return *garbled_circuit_provider_; }

  const auto& GetRunTimeStatistics() const { return run_time_statistics_; }

  auto& GetMutableRunTimeStatistics() { return run_time_statistics_; }

 private:
  std::list<RunTimeStatistics> run_time_statistics_;

  std::unique_ptr<communication::CommunicationLayer> communication_layer_;
  std::shared_ptr<Logger> logger_;
  ConfigurationPointer configuration_;
  RegisterPointer register_;
  std::unique_ptr<GateExecutor> gate_executor_;

  std::unique_ptr<BaseProvider> motion_base_provider_;
  std::unique_ptr<BaseOtProvider> base_ot_provider_;
  std::unique_ptr<proto::garbled_circuit::Provider> garbled_circuit_provider_;
  std::unique_ptr<OtProviderManager> ot_provider_manager_;
  std::unique_ptr<Kk13OtProviderManager> kk13_ot_provider_manager_;
  std::shared_ptr<MtProvider> mt_provider_;
  std::shared_ptr<SpProvider> sp_provider_;
  std::shared_ptr<SbProvider> sb_provider_;
  std::unique_ptr<proto::bmr::Provider> bmr_provider_;
};

using BackendPointer = std::shared_ptr<Backend>;

}  // namespace encrypto::motion
