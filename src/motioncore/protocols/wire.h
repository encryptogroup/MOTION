// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "utility/fiber_condition.h"
#include "utility/typedefs.h"

namespace encrypto::motion {

class FiberCondition;
class Backend;

class Gate;  // forward declaration
using GatePointer = std::shared_ptr<Gate>;

class Wire {
 public:
  std::size_t GetNumberOfSimdValues() const;

  virtual enum CircuitType GetCircuitType() const = 0;

  virtual enum MpcProtocol GetProtocol() const = 0;

  virtual ~Wire();

  void SetOnlineFinished();

  const std::atomic<bool>& IsReady() const noexcept;

  const FiberCondition& GetIsReadyCondition() const noexcept { return is_done_condition_; }

  std::size_t GetWireId() const { return static_cast<std::size_t>(wire_id_); }

  Backend& GetBackend() const { return backend_; }

  static std::string PrintIds(const std::vector<std::shared_ptr<Wire>>& wires);

  virtual std::size_t GetBitLength() const = 0;

  void Clear() {
    is_done_ = false;
    DynamicClear();
  }

  virtual bool IsConstant() const noexcept = 0;

  Wire(const Wire&) = delete;

 protected:
  Backend& backend_;

  /// Number of values that are _logically_ processed in parallel
  std::size_t number_of_simd_ = 0;

  // is ready flag is needed for callbacks, i.e.,
  // gates will wait for wires to be evaluated to proceed with their evaluation
  std::atomic<bool> is_done_ = false;

  FiberCondition is_done_condition_;

  std::int64_t wire_id_ = -1;

  Wire(Backend& backend, std::size_t number_of_simd);

  virtual void DynamicClear(){};

 private:
  void InitializationHelper();

  std::mutex mutex_;
};

using WirePointer = std::shared_ptr<Wire>;

class BooleanWire : public Wire {
 public:
  ~BooleanWire() override = default;

  CircuitType GetCircuitType() const final { return CircuitType::kBoolean; }

  BooleanWire(BooleanWire&) = delete;

 protected:
  BooleanWire(Backend& backend, std::size_t number_of_simd) : Wire(backend, number_of_simd) {}
};

using BooleanWirePointer = std::shared_ptr<BooleanWire>;

}  // namespace encrypto::motion
