// MIT License
//
// Copyright (c) 2021-2022 Oleksandr Tkachenko, Arianne Roselina Prananto, Liang Zhao
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
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "algorithm/boolean_algorithms.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/constant/constant_share_wrapper.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureUnsignedInteger::SecureUnsignedInteger(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger::SecureUnsignedInteger(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureUnsignedInteger SecureUnsignedInteger::operator+(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    // use primitive operation in arithmetic GMW
    return *share_ + *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> addition_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kAdd, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kAdd, bitlength, "_depth");

    if ((addition_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      addition_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(addition_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(addition_algorithm));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator-(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    return *share_ - *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> subtraction_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kSub, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kSub, bitlength, "_depth");

    if ((subtraction_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer subtraction circuit with file path {}", path));
      }
    } else {
      subtraction_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(subtraction_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer subtraction circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(subtraction_algorithm));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator*(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    return *share_ * *other.share_;
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> multiplication_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMul, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMul, bitlength, "_depth");

    if ((multiplication_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer multiplication circuit with file path {}", path));
      }
    } else {
      multiplication_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(multiplication_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer multiplication circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(multiplication_algorithm));
  }
}

SecureUnsignedInteger SecureUnsignedInteger::operator/(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer division is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> division_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kDiv, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kDiv, bitlength, "_depth");

    if ((division_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer division circuit with file path {}", path));
      }
    } else {
      division_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(division_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer division circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureUnsignedInteger(share_input.Evaluate(division_algorithm));
  }
}

ShareWrapper SecureUnsignedInteger::operator<(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      return *other.share_ > *share_;
    }
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> greater_than_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((greater_than_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer greater than circuit with file path {}", path));
      }
    } else {
      greater_than_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(greater_than_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer greater than circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(greater_than_algorithm).Split().at(0);
  }
}

ShareWrapper SecureUnsignedInteger::operator>(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      return *share_ > *other.share_;
    }
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> greater_than_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((greater_than_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      greater_than_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(greater_than_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(greater_than_algorithm).Split().at(0);
  }
}

ShareWrapper SecureUnsignedInteger::operator==(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    if constexpr (kDebug) {
      if (other->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean equality circuit in BMR");
      } else if (share_->Get()->GetProtocol() == MpcProtocol::kGarbledCircuit) {
        logger_->LogDebug("Creating a Boolean equality circuit in YAO");
      } else if (share_->Get()->GetProtocol() == MpcProtocol::kBooleanGmw) {
        logger_->LogDebug("Creating a Boolean equality circuit in GMW");
      }
    }
    return this->Get() == other.Get();
  }
}

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator+(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this + unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator+
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator-(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this - unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator-
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator*(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this * unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator*
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureUnsignedInteger SecureUnsignedInteger::operator/(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this / unsigned_integer_constant;
}

template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureUnsignedInteger SecureUnsignedInteger::operator/
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator<(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this < unsigned_integer_constant;
}

template ShareWrapper SecureUnsignedInteger::operator< <std::uint8_t>(
    const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint16_t>(
    const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint32_t>(
    const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <std::uint64_t>(
    const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator< <__uint128_t>(
    const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator>(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this > unsigned_integer_constant;
}
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator>
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureUnsignedInteger::operator==(const T& constant_value) const {
  SecureUnsignedInteger unsigned_integer_constant =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(constant_value);

  return *this == unsigned_integer_constant;
}
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureUnsignedInteger::operator==
    <__uint128_t>(const __uint128_t& constant_value) const;

ShareWrapper SecureUnsignedInteger::IsZero() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer IsZero is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> equal_zero_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kEQZ, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kEQZ, bitlength, "_depth");

    if ((equal_zero_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      equal_zero_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(equal_zero_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return share_input.Evaluate(equal_zero_algorithm).Split().at(0);
  }
}

SecureUnsignedInteger SecureUnsignedInteger::Mod(
    const SecureUnsignedInteger& secure_unsigned_integer_m) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer mod is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> mod_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMod, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kMod, bitlength, "_depth");

    if ((mod_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer modulo circuit with file path {}", path));
      }
    } else {
      mod_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(mod_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer modulo circuit from file {}", path));
      }
    }
    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, *secure_unsigned_integer_m.share_})};
    return share_input.Evaluate(mod_algorithm);
  }
}

template <typename T>
SecureUnsignedInteger SecureUnsignedInteger::Mod(const T& integer_m) const {
  SecureUnsignedInteger unsigned_integer_constant_m =
      ConstantShareWrapper(*share_).CreateConstantBooleanGmwOrBmrInput<T>(integer_m);

  return (*this).Mod(unsigned_integer_constant_m);
}

template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint8_t>(
    const std::uint8_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint16_t>(
    const std::uint16_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint32_t>(
    const std::uint32_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<std::uint64_t>(
    const std::uint64_t& integer_m) const;
template SecureUnsignedInteger SecureUnsignedInteger::Mod<__uint128_t>(
    const __uint128_t& integer_m) const;

ShareWrapper SecureUnsignedInteger::GE(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer GE is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ge_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer ge circuit with file path {}", path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer ge circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}
ShareWrapper SecureUnsignedInteger::LE(const SecureUnsignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer GE is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ge_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(UnsignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer ge circuit with file path {}", path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer ge circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}

std::string SecureUnsignedInteger::ConstructPath(
    const UnsignedIntegerOperationType type, const std::size_t bitlength, std::string suffix,
    const std::size_t floating_point_bit_length) const {
  std::string operation_type_string;

  switch (type) {
    case UnsignedIntegerOperationType::kAdd: {
      operation_type_string = "add";
      break;
    }
    case UnsignedIntegerOperationType::kSub: {
      operation_type_string = "sub";
      break;
    }
    case UnsignedIntegerOperationType::kMul: {
      operation_type_string = "mul";
      break;
    }
    case UnsignedIntegerOperationType::kDiv: {
      operation_type_string = "div";
      break;
    }
    case UnsignedIntegerOperationType::kGt: {
      operation_type_string = "gt";
      break;
    }
    case UnsignedIntegerOperationType::kEq: {
      operation_type_string = "eq";
      break;
    }
    case UnsignedIntegerOperationType::kEQZ: {
      operation_type_string = "eqz";
      break;
    }
    case UnsignedIntegerOperationType::kGE: {
      operation_type_string = "ge";
      break;
    }
    case UnsignedIntegerOperationType::kMod: {
      operation_type_string = "mod";
      break;
    }

    default:
      throw std::runtime_error(
          fmt::format("Invalid integer operation required: {}", to_string(type)));
  }
  return fmt::format("{}/circuits/unsigned_integer/uint{}_{}{}.bristol", kRootDir, bitlength,
                     operation_type_string, suffix);
}

SecureUnsignedInteger SecureUnsignedInteger::Simdify(std::span<SecureUnsignedInteger> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureUnsignedInteger& i) -> SharePointer { return i.Get().Get(); });
  return SecureUnsignedInteger(ShareWrapper::Simdify(input_as_shares));
}

SecureUnsignedInteger SecureUnsignedInteger::Simdify(std::vector<SecureUnsignedInteger>&& input) {
  return Simdify(input);
}

SecureUnsignedInteger SecureUnsignedInteger::Subset(std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureUnsignedInteger(unwrap.Subset(positions));
}

SecureUnsignedInteger SecureUnsignedInteger::Subset(std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

std::vector<SecureUnsignedInteger> SecureUnsignedInteger::Unsimdify() const {
  auto unsimdify_gate = share_->Get()->GetRegister()->EmplaceGate<UnsimdifyGate>(share_->Get());
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<SecureUnsignedInteger> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return SecureUnsignedInteger(share); });
  return result;
}

SecureUnsignedInteger SecureUnsignedInteger::Out(std::size_t output_owner) const {
  return SecureUnsignedInteger(share_->Out(output_owner));
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template <typename T>
T SecureUnsignedInteger::As() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic)
    return share_->As<T>();
  else if (share_->Get()->GetCircuitType() == CircuitType::kBoolean) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    if constexpr (std::is_unsigned<T>() || std::is_same<T, __uint128_t>()) {
      return encrypto::motion::ToOutput<T>(share_out);
    } else if constexpr (is_specialization<T, std::vector>::value &&
                         std::is_unsigned<typename T::value_type>()) {
      return encrypto::motion::ToVectorOutput<typename T::value_type>(share_out);
    } else {
      throw std::invalid_argument(
          fmt::format("Unsupported output type in SecureUnsignedInteger::As<{}>() for {} Protocol",
                      typeid(T).name(), share_->Get()->GetProtocol()));
    }
  } else {
    throw std::invalid_argument("Unsupported protocol for SecureUnsignedInteger::As()");
  }
}

template <typename T, typename A>
std::vector<T, A> SecureUnsignedInteger::AsVector() const {
  auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
  std::vector<T> as_unsigned_output_vector = encrypto::motion::ToVectorOutput<T>(share_out);

  return as_unsigned_output_vector;
}

template std::uint8_t SecureUnsignedInteger::As() const;
template std::uint16_t SecureUnsignedInteger::As() const;
template std::uint32_t SecureUnsignedInteger::As() const;
template std::uint64_t SecureUnsignedInteger::As() const;
template __uint128_t SecureUnsignedInteger::As() const;

template std::vector<std::uint8_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint16_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint32_t> SecureUnsignedInteger::As() const;
template std::vector<std::uint64_t> SecureUnsignedInteger::As() const;
template std::vector<__uint128_t> SecureUnsignedInteger::As() const;

template std::vector<std::uint8_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint16_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint32_t> SecureUnsignedInteger::AsVector() const;
template std::vector<std::uint64_t> SecureUnsignedInteger::AsVector() const;
template std::vector<__uint128_t> SecureUnsignedInteger::AsVector() const;

}  // namespace encrypto::motion
