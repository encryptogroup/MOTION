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

#include <tuple>

namespace ENCRYPTO {
enum PrimitiveOperationType : std::uint8_t {
  XOR = 0,  // for Boolean circuit only
  AND = 1,  // for Boolean circuit only
  MUX = 2,  // for Boolean circuit only
  INV = 3,  // for Boolean circuit only
  OR = 4,   // for Boolean circuit only
  ADD = 4,  // for arithmetic circuit only
  MUL = 5,  // for arithmetic circuit only
  INVALID = 6
};

enum IntegerOperationType : unsigned int {
  INT_ADD = 0,
  INT_DIV = 1,
  INT_GT = 2,
  INT_EQ = 3,
  INT_MUL = 4,
  INT_SUB = 5
};
}  // namespace ENCRYPTO

// TODO: put MOTION namespace into ENCRYPTO namespace

namespace MOTION {

namespace Gates::Interfaces {}
namespace Gates::Arithmetic {}
namespace Gates::Boolean {}
namespace Gates::Yao {}
namespace Gates::Conversion {}

// fast-access aliases for Gates
namespace Arithmetic = Gates::Arithmetic;
namespace Boolean = Gates::Boolean;
namespace Conversion = Gates::Conversion;

enum MPCProtocol : unsigned int {
  ArithmeticGMW = 0,
  BooleanGMW = 1,
  BMR = 2,
  InvalidProtocol = 3  // for checking whether the value is valid
};

enum CircuitType : unsigned int {
  ArithmeticCircuitType = 0,
  BooleanCircuitType = 1,
  InvalidCircuitType = 2  // for checking whether the value is valid
};

enum Role : unsigned int {
  Server = 0,
  Client = 1,
  InvalidRole = 2  // for checking whether the value is valid
};

enum GateType : unsigned int {
  InputGate = 0,
  InteractiveGate = 1,
  NonInteractiveGate = 2,
  InvalidGate = 3
};

}  // namespace MOTION

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MultiplicationTriple = std::tuple<T, T, T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MT = MultiplicationTriple<T>;