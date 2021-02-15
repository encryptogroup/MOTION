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
#include <vector>
#include "utility/typedefs.h"

namespace encrypto::motion {

class Wire;  // forward declaration
using WirePointer = std::shared_ptr<Wire>;

class Backend;  // forward declaration
using BackendPointer = std::shared_ptr<Backend>;

class Register;

class Share : public std::enable_shared_from_this<Share> {
 public:
  virtual ~Share() = default;

  virtual std::size_t GetNumberOfSimdValues() const noexcept = 0;

  virtual MpcProtocol GetProtocol() const noexcept = 0;

  virtual CircuitType GetCircuitType() const noexcept = 0;

  virtual std::size_t GetBitLength() const noexcept = 0;

  virtual const std::vector<WirePointer>& GetWires() const noexcept = 0;

  virtual std::vector<WirePointer>& GetMutableWires() noexcept = 0;

  virtual std::vector<std::shared_ptr<Share>> Split() const noexcept = 0;

  virtual std::shared_ptr<Share> GetWire(std::size_t i) const = 0;

  Backend& GetBackend() const { return backend_; }

  std::shared_ptr<Register> GetRegister();

  Share(Share&) = delete;

  Share(const Share&) = delete;

  static std::shared_ptr<Share> Concatenate(const std::vector<std::shared_ptr<Share>>& v);

  bool IsConstant() const noexcept;

 protected:
  Share(Backend& backend) : backend_(backend) {}

  Backend& backend_;
  std::vector<WirePointer> wires_;
};

using SharePointer = std::shared_ptr<Share>;

class BooleanShare : public Share {
 public:
  ~BooleanShare() override = default;

  BooleanShare(BooleanShare&) = delete;

 protected:
  BooleanShare(Backend& backend) : Share(backend) {}
};

using BooleanSharePointer = std::shared_ptr<BooleanShare>;

}  // namespace encrypto::motion
