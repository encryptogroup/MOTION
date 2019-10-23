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

#include "algorithm/algorithm_description.h"
#include "share/share_wrapper.h"
#include "utility/logger.h"

namespace MOTION {

class SecureUnsignedInteger {
 public:
  SecureUnsignedInteger() = delete;

  SecureUnsignedInteger(const SecureUnsignedInteger& other)
      : SecureUnsignedInteger(*other.share_) {}

  SecureUnsignedInteger(SecureUnsignedInteger&& other)
      : SecureUnsignedInteger(std::move(*other.share_)) {
    other.share_->Get().reset();
  }

  SecureUnsignedInteger(const Shares::ShareWrapper& other) : SecureUnsignedInteger(*other) {}

  SecureUnsignedInteger(Shares::ShareWrapper&& other) : SecureUnsignedInteger(std::move(*other)) {
    other.Get().reset();
  }

  SecureUnsignedInteger(const Shares::SharePtr& other)
      : share_(std::make_unique<Shares::ShareWrapper>(other)),
        logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

  SecureUnsignedInteger(Shares::SharePtr&& other)
      : share_(std::make_unique<Shares::ShareWrapper>(std::move(other))),
        logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

  using IntegerOperationType = ENCRYPTO::IntegerOperationType;

  SecureUnsignedInteger operator+(SecureUnsignedInteger& other) {
    if (share_->Get()->GetCircuitType() != CircuitType::BooleanCircuitType) {
      // use primitive operation in arithmetic GMW
      return *share_ + *other.share_;
    } else {  // BooleanCircuitType
      const auto bitlen = share_->Get()->GetBitLength();
      std::shared_ptr<ENCRYPTO::AlgorithmDescription> add_algo;
      std::string path;

      if (share_->Get()->GetProtocol() == BMR)  // BMR, use size-optimized circuit
        path = ConstructPath(IntegerOperationType::INT_ADD, bitlen, "_size");
      else  // GMW, use depth-optimized circuit
        path = ConstructPath(IntegerOperationType::INT_ADD, bitlen, "_depth");

      if (add_algo = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path)) {
        if constexpr (MOTION_DEBUG) {
          logger_->LogDebug(fmt::format(
              "Found in cache Boolean integer addition circuit with file path {}", path));
        }
      } else {
        add_algo = std::make_shared<ENCRYPTO::AlgorithmDescription>(
            ENCRYPTO::AlgorithmDescription::FromBristol(path));
        assert(add_algo);
        if constexpr (MOTION_DEBUG) {
          logger_->LogDebug(
              fmt::format("Read Boolean integer addition circuit from file {}", path));
        }
      }
      const auto s_in{Shares::ShareWrapper::Join({*share_, *other.share_})};
      share_ = std::make_unique<Shares::ShareWrapper>(s_in.Evaluate(add_algo));
    }
  }

 private:
  std::unique_ptr<Shares::ShareWrapper> share_{nullptr};
  std::shared_ptr<Logger> logger_{nullptr};

  std::string ConstructPath(const IntegerOperationType type, const std::size_t bitlen,
                            std::string suffix = "") {
    std::string type_str;
    switch (type) {
      case IntegerOperationType::INT_ADD: {
        type_str = "add";
        break;
      }
      case IntegerOperationType::INT_DIV: {
        type_str = "div";
        break;
      }
      case IntegerOperationType::INT_GT: {
        type_str = "gt";
        break;
      }
      case IntegerOperationType::INT_EQ: {
        type_str = "eq";
        break;
      }
      case IntegerOperationType::INT_MUL: {
        type_str = "mul";
        break;
      }
      case IntegerOperationType::INT_SUB: {
        type_str = "sub";
        break;
      }
      default:
        throw std::runtime_error(fmt::format("Invalid integer operation required: {}", type));
    }
    return fmt::format("{}/circuits/int/int_{}{}{}.bristol", MOTION_ROOT_DIR, type_str, bitlen,
                       suffix);
  }
};  // namespace MOTION
}