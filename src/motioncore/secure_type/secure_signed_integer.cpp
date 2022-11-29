// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Arianne Roselina Prananto
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

#include "secure_signed_integer.h"

#include <fmt/format.h>
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "algorithm/boolean_algorithms.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureSignedInteger::SecureSignedInteger(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureSignedInteger::SecureSignedInteger(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureSignedInteger SecureSignedInteger::operator+(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kAdd, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kAdd, bitlength, "_depth");

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
    // std::cout << "operator+, ShareWrapper::Concatenate" << std::endl;
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};

    // std::cout << "share_input.Evaluate(addition_algorithm" << std::endl;
    return SecureSignedInteger(share_input.Evaluate(addition_algorithm));
  }
}

SecureSignedInteger SecureSignedInteger::operator-(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kSub, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kSub, bitlength, "_depth");

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
    return SecureSignedInteger(share_input.Evaluate(subtraction_algorithm));
  }
}

SecureSignedInteger SecureSignedInteger::operator*(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kMul, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kMul, bitlength, "_depth");

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
    return SecureSignedInteger(share_input.Evaluate(multiplication_algorithm));
  }
}

// ! depth and size circuits are the same, i.e., the depth circuits is not optimized
SecureSignedInteger SecureSignedInteger::operator/(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kDiv, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kDiv, bitlength, "_depth");

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
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureSignedInteger(share_input.Evaluate(division_algorithm));
  }
}

ShareWrapper SecureSignedInteger::operator<(const SecureSignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureSignedInteger::operator>(const SecureSignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer comparison is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGt, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGt, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer addition circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureSignedInteger::operator==(const SecureSignedInteger& other) const {
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
SecureSignedInteger SecureSignedInteger::operator+(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput(constant_value);

  return *this + signed_integer_constant;
}

template SecureSignedInteger SecureSignedInteger::operator+
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator+
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator+
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator+
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator+
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureSignedInteger SecureSignedInteger::operator-(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this - signed_integer_constant;
}

template SecureSignedInteger SecureSignedInteger::operator-
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator-
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator-
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator-
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator-
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureSignedInteger SecureSignedInteger::operator*(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this * signed_integer_constant;
}

template SecureSignedInteger SecureSignedInteger::operator*
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator*
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator*
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator*
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator*
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
SecureSignedInteger SecureSignedInteger::operator/(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this / signed_integer_constant;
}

template SecureSignedInteger SecureSignedInteger::operator/
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator/
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator/
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator/
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template SecureSignedInteger SecureSignedInteger::operator/
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureSignedInteger::operator<(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this < signed_integer_constant;
}

template ShareWrapper SecureSignedInteger::operator< <std::uint8_t>(
    const std::uint8_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator< <std::uint16_t>(
    const std::uint16_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator< <std::uint32_t>(
    const std::uint32_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator< <std::uint64_t>(
    const std::uint64_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator< <__uint128_t>(
    const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureSignedInteger::operator>(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this > signed_integer_constant;
}
template ShareWrapper SecureSignedInteger::operator>
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator>
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator>
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator>
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator>
    <__uint128_t>(const __uint128_t& constant_value) const;

template <typename T, typename>
ShareWrapper SecureSignedInteger::operator==(const T& constant_value) const {
  SecureSignedInteger signed_integer_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value);

  return *this == signed_integer_constant;
}
template ShareWrapper SecureSignedInteger::operator==
    <std::uint8_t>(const std::uint8_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator==
    <std::uint16_t>(const std::uint16_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator==
    <std::uint32_t>(const std::uint32_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator==
    <std::uint64_t>(const std::uint64_t& constant_value) const;
template ShareWrapper SecureSignedInteger::operator==
    <__uint128_t>(const __uint128_t& constant_value) const;

// TODO: implement for other MPC protocols
SecureSignedInteger SecureSignedInteger::MulBooleanBit(
    const ShareWrapper& boolean_gmw_bmr_gc_bit_share_other) const {
  assert(boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBooleanGmw ||
         boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBmr ||
         boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kGarbledCircuit);
  assert(boolean_gmw_bmr_gc_bit_share_other->GetWires().size() == 1);

  SecureSignedInteger result = boolean_gmw_bmr_gc_bit_share_other.XCOTMul(*share_);
  return result;
}

ShareWrapper SecureSignedInteger::IsZero() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer EQZ is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> equal_zero_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kIsZero, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kIsZero, bitlength, "_depth");

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

ShareWrapper SecureSignedInteger::IsNeg() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer is negative operation is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    // std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    // std::string path;

    std::vector<ShareWrapper> boolean_gmw_or_bmr_share_vector = (*share_).Split();

    ShareWrapper boolean_gmw_or_bmr_share_msb_sign = boolean_gmw_or_bmr_share_vector.back();
    return boolean_gmw_or_bmr_share_msb_sign;
  }
}

ShareWrapper SecureSignedInteger::GE(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer GE circuit with file path {}", path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer GE circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}

ShareWrapper SecureSignedInteger::LE(const SecureSignedInteger& other) const {
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
      path = ConstructPath(SignedIntegerOperationType::kGE, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kGE, bitlength, "_depth");

    if ((ge_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer LE circuit with file path {}", path));
      }
    } else {
      ge_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ge_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer LE circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(ge_algorithm).Split().at(0);
  }
}

ShareWrapper SecureSignedInteger::InRange(const SecureSignedInteger& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    // use primitive operation in arithmetic GMW
    throw std::runtime_error("Integer in range is not implemented for arithmetic GMW");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> in_range_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kInRange, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kInRange, bitlength, "_depth");

    if ((in_range_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean integer in_range circuit with file path {}", path));
      }
    } else {
      in_range_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(in_range_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean integer in_range circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(in_range_algorithm).Split().at(0);
  }
}

SecureSignedInteger SecureSignedInteger::Neg(
    const ShareWrapper& boolean_gmw_or_bmr_share_sign) const {
  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_this_vector = share_->Split();

  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_this_invert_vector;

  boolean_gmw_or_bmr_share_this_invert_vector.reserve(boolean_gmw_or_bmr_share_this_vector.size());
  for (ShareWrapper boolean_gmw_or_bmr_share_this_wire : boolean_gmw_or_bmr_share_this_vector) {
    boolean_gmw_or_bmr_share_this_invert_vector.emplace_back(~boolean_gmw_or_bmr_share_this_wire);
    // std::cout << "boolean_gmw_or_bmr_share_this_wire->GetBitLength(): "
    //           << boolean_gmw_or_bmr_share_this_wire->GetBitLength() << std::endl;
  }

  // std::cout << "boolean_gmw_or_bmr_share_this_vector.size(): "
  //           << boolean_gmw_or_bmr_share_this_vector.size() << std::endl;

  // std::cout << "boolean_gmw_or_bmr_share_sign->GetBitLength(): " <<
  // boolean_gmw_or_bmr_share_sign->GetBitLength()
  //           << std::endl;

  // std::cout << "AdderChain" << std::endl;
  ShareWrapper unsigned_integer_twos_complement_with_overflow_bit =
      encrypto::motion::algorithm::AdderChain(boolean_gmw_or_bmr_share_this_invert_vector,
                                              boolean_gmw_or_bmr_share_sign);

  std::vector<ShareWrapper> unsigned_integer_twos_complement_with_overflow_bit_vector =
      unsigned_integer_twos_complement_with_overflow_bit.Split();

  // std::cout << "unsigned_integer_twos_complement_with_overflow_bit_vector.size(): "
  //           << unsigned_integer_twos_complement_with_overflow_bit_vector.size() << std::endl;

  std::vector<ShareWrapper> unsigned_integer_twos_complement_vector(
      unsigned_integer_twos_complement_with_overflow_bit_vector.begin(),
      unsigned_integer_twos_complement_with_overflow_bit_vector.end() - 1);

  // std::cout << "unsigned_integer_twos_complement_vector.size(): "
  //           << unsigned_integer_twos_complement_vector.size() << std::endl;
  // return (boolean_gmw_or_bmr_share_sign.XCOTMul(
  //            ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector))) ^
  //        ((~boolean_gmw_or_bmr_share_sign).XCOTMul(this->Get()));

  // std::cout << "before Mux" << std::endl;

  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_sign_vector(
      unsigned_integer_twos_complement_vector.size(), boolean_gmw_or_bmr_share_sign);

  // return ShareWrapper::Concatenate(boolean_gmw_or_bmr_share_sign_vector)
  //     .Mux(ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector), this->Get());
  return (boolean_gmw_or_bmr_share_sign)
      .Mux(ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector), this->Get());
}

SecureSignedInteger SecureSignedInteger::Neg() const {
  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_this_vector = share_->Split();
  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_this_invert_vector;
  boolean_gmw_or_bmr_share_this_invert_vector.reserve(boolean_gmw_or_bmr_share_this_vector.size());
  for (ShareWrapper boolean_gmw_or_bmr_share_this_wire : boolean_gmw_or_bmr_share_this_vector) {
    boolean_gmw_or_bmr_share_this_invert_vector.emplace_back(~boolean_gmw_or_bmr_share_this_wire);
    // std::cout << "boolean_gmw_or_bmr_share_this_wire->GetBitLength(): "
    //           << boolean_gmw_or_bmr_share_this_wire->GetBitLength() << std::endl;
  }

  // TODO: create constant wire directly
  ShareWrapper constant_boolean_gmw_or_bmr_share_one =
      boolean_gmw_or_bmr_share_this_vector[0] ^ (~boolean_gmw_or_bmr_share_this_vector[0]);

  // std::cout << "boolean_gmw_or_bmr_share_sign->GetBitLength(): " <<
  // boolean_gmw_or_bmr_share_sign->GetBitLength()
  //           << std::endl;

  // std::cout << "AdderChain" << std::endl;
  ShareWrapper unsigned_integer_twos_complement_with_overflow_bit =
      encrypto::motion::algorithm::AdderChain(boolean_gmw_or_bmr_share_this_invert_vector,
                                              constant_boolean_gmw_or_bmr_share_one);

  std::vector<ShareWrapper> unsigned_integer_twos_complement_with_overflow_bit_vector =
      unsigned_integer_twos_complement_with_overflow_bit.Split();

  std::vector<ShareWrapper> unsigned_integer_twos_complement_vector(
      unsigned_integer_twos_complement_with_overflow_bit_vector.begin(),
      unsigned_integer_twos_complement_with_overflow_bit_vector.end() - 1);

  return (ShareWrapper::Concatenate(unsigned_integer_twos_complement_vector));

  // // only for debugging
  // return ((*this));
}

SecureFloatingPointCircuitABY SecureSignedInteger::Int2FL(
    std::size_t floating_point_bit_length) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    std::shared_ptr<AlgorithmDescription> integer_to_floating_point_algorithm;
    std::string path;
    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kInt2FL, bitlength, "_size",
                           floating_point_bit_length);
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(SignedIntegerOperationType::kInt2FL, bitlength, "_depth",
                           floating_point_bit_length);
    if ((integer_to_floating_point_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean integer to floating-point circuit with file path {}", path));
      }
    } else {
      integer_to_floating_point_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(integer_to_floating_point_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean integer to floating circuit from file {}", path));
      }
    }

    // ! we mask the correct result with zero_bits_mask, otherwise, it cannot be converted to
    // bristol format in CBMC-GC, input wire zero_bits_mask must be zero bits
    // TODO: create constant wire directly
    ShareWrapper constant_boolean_gmw_or_bmr_share_zero = (*share_) ^ (*share_);

    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, constant_boolean_gmw_or_bmr_share_zero})};
    const auto evaluation_result = share_input.Evaluate(integer_to_floating_point_algorithm);

    return evaluation_result;
  }
}

SecureFixedPointCircuitCBMC SecureSignedInteger::Int2Fx(std::size_t fraction_bit_size) const {
  // const auto bitlength = share_->Get()->GetBitLength();
  // std::vector<ShareWrapper> boolean_gmw_or_bmr_share_vector = share_->Split();

  // ShareWrapper fixed_point_boolean_gmw_or_bmr_share = *(share_.get()) ^ *(share_.get());
  // std::vector<ShareWrapper> fixed_point_boolean_gmw_or_bmr_share_vector =
  //     fixed_point_boolean_gmw_or_bmr_share.Split();

  // for (std::size_t i = 0; i + f < bitlength; i++) {
  //   fixed_point_boolean_gmw_or_bmr_share_vector[i + f] = boolean_gmw_or_bmr_share_vector[i];
  // }
  // fixed_point_boolean_gmw_or_bmr_share =
  // share_->Concatenate(fixed_point_boolean_gmw_or_bmr_share_vector);

  // return fixed_point_boolean_gmw_or_bmr_share;

  const auto bitlength = share_->Get()->GetBitLength();
  std::vector<ShareWrapper> boolean_gmw_or_bmr_share_vector = share_->Split();

  // ShareWrapper fixed_point_boolean_gmw_or_bmr_share = *(share_.get()) ^ *(share_.get());

  // TODO: create constant wire directly
  ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
      boolean_gmw_or_bmr_share_vector[0] ^ boolean_gmw_or_bmr_share_vector[0];

  std::vector<ShareWrapper> fixed_point_boolean_gmw_or_bmr_share_vector(bitlength);
  for (std::size_t i = 0; i < bitlength; i++) {
    fixed_point_boolean_gmw_or_bmr_share_vector[i] = constant_boolean_gmw_or_bmr_share_zero;
  }

  for (std::size_t i = 0; i + fraction_bit_size < bitlength; i++) {
    fixed_point_boolean_gmw_or_bmr_share_vector[i + fraction_bit_size] =
        boolean_gmw_or_bmr_share_vector[i];
  }
  ShareWrapper fixed_point_boolean_gmw_or_bmr_share =
      share_->Concatenate(fixed_point_boolean_gmw_or_bmr_share_vector);

  return fixed_point_boolean_gmw_or_bmr_share;
}

std::string SecureSignedInteger::ConstructPath(const SignedIntegerOperationType type,
                                               const std::size_t bitlength, std::string suffix,
                                               const std::size_t floating_point_bit_length) const {
  std::string operation_type_string;
  // std::string suffix_tmp = suffix;
  switch (type) {
    case SignedIntegerOperationType::kAdd: {
      operation_type_string = "add";
      break;
    }
    case SignedIntegerOperationType::kSub: {
      operation_type_string = "sub";
      break;
    }
    case SignedIntegerOperationType::kMul: {
      operation_type_string = "mul";
      break;
    }
    case SignedIntegerOperationType::kDiv: {
      operation_type_string = "div";
      break;
    }
    case SignedIntegerOperationType::kGt: {
      operation_type_string = "gt";
      break;
    }
    case SignedIntegerOperationType::kEq: {
      operation_type_string = "eq";
      break;
    }
    case SignedIntegerOperationType::kIsZero: {
      operation_type_string = "is_zero";
      break;
    }
    case SignedIntegerOperationType::kGE: {
      operation_type_string = "ge";
      break;
    }
    case SignedIntegerOperationType::kInRange: {
      operation_type_string = "in_range";
      break;
    }
    case SignedIntegerOperationType::kInt2FL: {
      operation_type_string = "to_float" + std::to_string(floating_point_bit_length);
      break;
    }
      // case SignedIntegerOperationType::kInt2Fx: {
      //   operation_type_string = "int2fx";
      //   suffix_tmp = "";
      //   break;
      // }

    default:
      throw std::runtime_error(
          fmt::format("Invalid integer operation required: {}", to_string(type)));
  }
  return fmt::format("{}/circuits/signed_integer/int{}_{}{}.bristol", kRootDir, bitlength,
                     operation_type_string, suffix);
}

SecureSignedInteger SecureSignedInteger::Simdify(std::span<SecureSignedInteger> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureSignedInteger& i) -> SharePointer { return i.Get().Get(); });
  return SecureSignedInteger(ShareWrapper::Simdify(input_as_shares));
}

SecureSignedInteger SecureSignedInteger::Simdify(std::vector<SecureSignedInteger>&& input) {
  return Simdify(input);
}

SecureSignedInteger SecureSignedInteger::Subset(std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureSignedInteger(unwrap.Subset(positions));
}

SecureSignedInteger SecureSignedInteger::Subset(std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

std::vector<SecureSignedInteger> SecureSignedInteger::Unsimdify() const {
  auto unsimdify_gate = share_->Get()->GetRegister()->EmplaceGate<UnsimdifyGate>(share_->Get());
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<SecureSignedInteger> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return SecureSignedInteger(share); });
  return result;
}

SecureSignedInteger SecureSignedInteger::Out(std::size_t output_owner) const {
  return SecureSignedInteger(share_->Out(output_owner));
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

// modified by Liang Zhao
template <typename T>
T SecureSignedInteger::As() const {
  if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw)
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
    throw std::invalid_argument("Unsupported protocol for SecureSignedInteger::As()");
  }
}

template std::uint8_t SecureSignedInteger::As() const;
template std::uint16_t SecureSignedInteger::As() const;
template std::uint32_t SecureSignedInteger::As() const;
template std::uint64_t SecureSignedInteger::As() const;
// added by Liang Zhao
template __uint128_t SecureSignedInteger::As() const;

template std::vector<std::uint8_t> SecureSignedInteger::As() const;
template std::vector<std::uint16_t> SecureSignedInteger::As() const;
template std::vector<std::uint32_t> SecureSignedInteger::As() const;
template std::vector<std::uint64_t> SecureSignedInteger::As() const;
template std::vector<__uint128_t> SecureSignedInteger::As() const;

template <typename T, typename A>
std::vector<T, A> SecureSignedInteger::AsVector() const {
  auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
  std::vector<T> as_signed_output_vector = encrypto::motion::ToVectorOutput<T>(share_out);

  return as_signed_output_vector;
}

template std::vector<std::uint8_t> SecureSignedInteger::AsVector() const;
template std::vector<std::uint16_t> SecureSignedInteger::AsVector() const;
template std::vector<std::uint32_t> SecureSignedInteger::AsVector() const;
template std::vector<std::uint64_t> SecureSignedInteger::AsVector() const;
// added by Liang Zhao
template std::vector<__uint128_t> SecureSignedInteger::AsVector() const;

}  // namespace encrypto::motion
