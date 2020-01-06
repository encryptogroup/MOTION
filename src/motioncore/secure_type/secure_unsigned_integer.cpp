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

#include "secure_unsigned_integer.h"

#include <fmt/format.h>

#include "algorithm/algorithm_description.h"
#include "base/register.h"
#include "utility/logger.h"
#include "utility/constants.h"

namespace MOTION {

SecureUnsignedInteger::SecureUnsignedInteger(const Shares::SharePtr& other)
    : share_(std::make_unique<Shares::ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger::SecureUnsignedInteger(Shares::SharePtr&& other)
    : share_(std::make_unique<Shares::ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger SecureUnsignedInteger::operator+(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    return *share_ + *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlen = share_->Get()->GetBitLength();
    std::shared_ptr<ENCRYPTO::AlgorithmDescription> add_algo;
    std::string path;

    if (share_->Get()->GetProtocol() == MPCProtocol::BMR)  // BMR, use size-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::ADD, bitlen, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::ADD, bitlen, "_depth");

    if ((add_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      add_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
          ENCRYPTO::AlgorithmDescription::FromBristol(path));
      assert(add_algo);
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
    return SecureUnsignedInteger(s_in.Evaluate(add_algo));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator-(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    return *share_ - *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlen = share_->Get()->GetBitLength();
    std::shared_ptr<ENCRYPTO::AlgorithmDescription> sub_algo;
    std::string path;

    if (share_->Get()->GetProtocol() == MPCProtocol::BMR)  // BMR, use size-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::SUB, bitlen, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::SUB, bitlen, "_depth");

    if ((sub_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      sub_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
          ENCRYPTO::AlgorithmDescription::FromBristol(path));
      assert(sub_algo);
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
    return SecureUnsignedInteger(s_in.Evaluate(sub_algo));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator*(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    return *share_ * *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlen = share_->Get()->GetBitLength();
    std::shared_ptr<ENCRYPTO::AlgorithmDescription> mul_algo;
    std::string path;

    if (share_->Get()->GetProtocol() == MPCProtocol::BMR)  // BMR, use size-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::MUL, bitlen, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::MUL, bitlen, "_depth");

    if ((mul_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      mul_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
          ENCRYPTO::AlgorithmDescription::FromBristol(path));
      assert(mul_algo);
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
    return SecureUnsignedInteger(s_in.Evaluate(mul_algo));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator/(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer division is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlen = share_->Get()->GetBitLength();
    std::shared_ptr<ENCRYPTO::AlgorithmDescription> div_algo;
    std::string path;

    if (share_->Get()->GetProtocol() == MPCProtocol::BMR)  // BMR, use size-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::DIV, bitlen, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::DIV, bitlen, "_depth");

    if ((div_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      div_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
          ENCRYPTO::AlgorithmDescription::FromBristol(path));
      assert(div_algo);
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
    return SecureUnsignedInteger(s_in.Evaluate(div_algo));
  }
}

Shares::ShareWrapper SecureUnsignedInteger::operator>(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlen = share_->Get()->GetBitLength();
    std::shared_ptr<ENCRYPTO::AlgorithmDescription> gt_algo;
    std::string path;

    if (share_->Get()->GetProtocol() == MPCProtocol::BMR)  // BMR, use size-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::GT, bitlen, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(ENCRYPTO::IntegerOperationType::GT, bitlen, "_depth");

    if ((gt_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      gt_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
          ENCRYPTO::AlgorithmDescription::FromBristol(path));
      assert(gt_algo);
      if constexpr (MOTION_DEBUG) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
    return s_in.Evaluate(gt_algo).Split().at(0);
  }
}

Shares::ShareWrapper SecureUnsignedInteger::operator==(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::Boolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    if constexpr (MOTION_DEBUG) {
      if (other->GetProtocol() == MPCProtocol::BMR) {
        logger_->LogDebug("Creating a Boolean equality circuit in BMR");
      } else {
        logger_->LogDebug("Creating a Boolean equality circuit in GMW");
      }
    }
    return this->Get() == other.Get();
  }
}

std::string SecureUnsignedInteger::ConstructPath(const ENCRYPTO::IntegerOperationType type,
                                                 const std::size_t bitlen,
                                                 std::string suffix) const {
  std::string type_str;
  switch (type) {
    case ENCRYPTO::IntegerOperationType::ADD: {
      type_str = "add";
      break;
    }
    case ENCRYPTO::IntegerOperationType::DIV: {
      type_str = "div";
      break;
    }
    case ENCRYPTO::IntegerOperationType::GT: {
      type_str = "gt";
      break;
    }
    case ENCRYPTO::IntegerOperationType::EQ: {
      type_str = "eq";
      break;
    }
    case ENCRYPTO::IntegerOperationType::MUL: {
      type_str = "mul";
      break;
    }
    case ENCRYPTO::IntegerOperationType::SUB: {
      type_str = "sub";
      break;
    }
    default:
      throw std::runtime_error(fmt::format("Invalid integer operation required: {}", type));
  }
  return fmt::format("{}/circuits/int/int_{}{}{}.bristol", MOTION_ROOT_DIR, type_str, bitlen,
                     suffix);
}

}
