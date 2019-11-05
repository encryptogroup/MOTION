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

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

#include "utility/typedefs.h"

namespace ENCRYPTO {
class FiberCondition;
}

namespace MOTION {
class Backend;
}

namespace MOTION::Gates::Interfaces {
class Gate;  // forward declaration

using GatePtr = std::shared_ptr<Gate>;
}  // namespace MOTION::Gates::Interfaces

namespace MOTION::Wires {
class Wire {
 public:
  std::size_t GetNumOfSIMDValues() const;

  virtual enum CircuitType GetCircuitType() const = 0;

  virtual enum MPCProtocol GetProtocol() const = 0;

  virtual ~Wire();

  void RegisterWaitingGate(std::size_t gate_id);

  void SetOnlineFinished();

  const auto &GetWaitingGatesIds() const noexcept { return waiting_gate_ids_; }

  const std::atomic<bool> &IsReady() const noexcept;

  std::shared_ptr<ENCRYPTO::FiberCondition> GetIsReadyCondition() const noexcept {
    return is_done_condition_;
  }

  bool IsConstant() const { return is_constant_; }

  std::size_t GetWireId() const { return static_cast<std::size_t>(wire_id_); }

  std::weak_ptr<MOTION::Backend> GetBackend() const { return backend_; }

  static std::string PrintIds(const std::vector<std::shared_ptr<Wires::Wire>> &wires);

  virtual std::size_t GetBitLength() const = 0;

  void Clear() {
    is_done_ = false;
    DynamicClear();
  }

  Wire(const Wire &) = delete;

 protected:
  /// Number of values that are _logically_ processed in parallel
  std::size_t n_simd_ = 0;

  // flagging variables as constants is useful, since this allows for tricks,
  // such as non-interactive multiplication by a constant in (arithmetic) GMW
  std::atomic<bool> is_constant_ = false;

  // is ready flag is needed for callbacks, i.e.,
  // gates will wait for wires to be evaluated to proceed with their evaluation
  std::atomic<bool> is_done_ = false;

  std::shared_ptr<ENCRYPTO::FiberCondition> is_done_condition_;

  std::int64_t wire_id_ = -1;

  std::weak_ptr<Backend> backend_;

  std::unordered_set<std::size_t> waiting_gate_ids_;

  Wire();

  static void SignalReadyToDependency(std::size_t gate_id, std::weak_ptr<Backend> backend);

  void InitializationHelper();

  virtual void DynamicClear(){};

 private:
  std::mutex mutex_;
};

using WirePtr = std::shared_ptr<Wire>;

class BooleanWire : public Wire {
 public:
  ~BooleanWire() override = default;

  CircuitType GetCircuitType() const final { return CircuitType::BooleanCircuitType; }

  MPCProtocol GetProtocol() const override = 0;

  BooleanWire(BooleanWire &) = delete;

 protected:
  BooleanWire() = default;
};

using BooleanWirePtr = std::shared_ptr<BooleanWire>;

}  // namespace MOTION::Wires
