// MIT License
//
// Copyright (c) 2022 Liang Zhao
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

#include "secure_fixed_point_circuit_CBMC.h"

#include <fmt/format.h>
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureFixedPointCircuitCBMC::SecureFixedPointCircuitCBMC(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFixedPointCircuitCBMC::SecureFixedPointCircuitCBMC(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator+(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> addition_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kAdd_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kAdd_circuit, bitlength, "_depth");

    // std::cout<<"path: "<<path<<std::endl;

    if ((addition_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point addition circuit with file path {}", path));
      }
    } else {
      addition_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(addition_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point addition circuit from file {}", path));
      }
    }

    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(addition_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator-(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> subtraction_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSub_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSub_circuit, bitlength, "_depth");

    if ((subtraction_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point subtraction circuit with file path {}", path));
      }
    } else {
      subtraction_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(subtraction_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point subtraction circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(subtraction_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator*(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> multiplication_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kMul_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kMul_circuit, bitlength, "_depth");

    if ((multiplication_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point multiplication circuit with file path {}", path));
      }
    } else {
      multiplication_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(multiplication_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point multiplication circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(multiplication_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator/(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> division_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kDiv_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kDiv_circuit, bitlength, "_depth");

    if ((division_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point division circuit with file path {}", path));
      }
    } else {
      division_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(division_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point division circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(division_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Div_Goldschmidt(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> division_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kDiv_Goldschmidt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kDiv_Goldschmidt_circuit, bitlength, "_depth");

    if ((division_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point kDiv_Goldschmidt circuit with file path {}", path));
      }
    } else {
      division_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(division_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point kDiv_Goldschmidt circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(division_algorithm));
  }
}

ShareWrapper SecureFixedPointCircuitCBMC::operator>(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kGt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kGt_circuit, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point comparison circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point comparison circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureFixedPointCircuitCBMC::operator<(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kGt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kGt_circuit, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point comparison circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point comparison circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureFixedPointCircuitCBMC::operator==(
    const SecureFixedPointCircuitCBMC& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
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

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator+(
    const double& constant_value) const {
  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this + fixed_point_constant;
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator-(
    const double& constant_value) const {
  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this - fixed_point_constant;
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator*(
    const double constant_value) const {
  // std::cout << "SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator*" << std::endl;

  // std::cout << "(*share_)->GetProtocol(): " << int((*share_)->GetProtocol()) << std::endl;

  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();

  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this * fixed_point_constant;
}

// ! TODO: replace the circuit with the overflow_free version
// TODO: test if overflow occurs
SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::operator/(
    const double& constant_value) const {
  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this / fixed_point_constant;
}

// TODO: add division that may overflow but more efficient

ShareWrapper SecureFixedPointCircuitCBMC::operator<(const double& constant_value) const {
  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();

  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this < fixed_point_constant;
}

ShareWrapper SecureFixedPointCircuitCBMC::operator>(const double& constant_value) const {
  std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value,
                                                                                num_of_simd, f_);

  return *this > fixed_point_constant;
}
ShareWrapper SecureFixedPointCircuitCBMC::operator==(const double& constant_value) const {
  SecureFixedPointCircuitCBMC fixed_point_constant =
      share_->CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<std::uint64_t>(constant_value, f_);

  return *this == fixed_point_constant;
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::MulBooleanBit(
    const ShareWrapper& boolean_gmw_bmr_gc_bit_share_other) const {
  assert(boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBooleanGmw||boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kBmr||boolean_gmw_bmr_gc_bit_share_other->GetProtocol() == MpcProtocol::kGarbledCircuit);
  assert(boolean_gmw_bmr_gc_bit_share_other->GetWires().size() == 1);

  SecureFixedPointCircuitCBMC result = boolean_gmw_bmr_gc_bit_share_other.XCOTMul(*share_);
  return result;
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Sqrt() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> sqrt_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSqrt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSqrt_circuit, bitlength, "_depth");

    if ((sqrt_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point square root circuit with file path {}", path));
      }
    } else {
      sqrt_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(sqrt_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point square root circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(sqrt_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Sqrt_P0132() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> sqrt_P0132_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSqrt_P0132_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSqrt_P0132_circuit, bitlength, "_depth");

    if ((sqrt_P0132_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point square root P0132 circuit with file path {}",
            path));
      }
    } else {
      sqrt_P0132_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(sqrt_P0132_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point square root P0132 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(sqrt_P0132_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Exp2_P1045() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> exp2_P1045_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kExp2_P1045_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kExp2_P1045_circuit, bitlength, "_depth");

    if ((exp2_P1045_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point exp2 P1045 circuit with file path {}", path));
      }
    } else {
      exp2_P1045_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(exp2_P1045_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point exp2 P1045 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(exp2_P1045_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Exp2_P1045_Neg_0_1() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> exp2_P1045_neg_0_1_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path =
          ConstructPath(FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path =
          ConstructPath(FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit, bitlength, "_depth");

    if ((exp2_P1045_neg_0_1_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean fixed-point kExp2_P1045_Neg_0_1_circuit circuit "
                        "with file path {}",
                        path));
      }
    } else {
      exp2_P1045_neg_0_1_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(exp2_P1045_neg_0_1_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean fixed-point kExp2_P1045_Neg_0_1_circuit circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(exp2_P1045_neg_0_1_algorithm));
  }
}

// TODO: need to generate efficient circuits
SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Log2_P2508() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> log2_P2508_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kLog2_P2508_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kLog2_P2508_circuit, bitlength, "_depth");

    if ((log2_P2508_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean fixed-point log2 circuit with file path {}", path));
      }
    } else {
      log2_P2508_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(log2_P2508_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean fixed-point log2 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(log2_P2508_algorithm));
  }
}

ShareWrapper SecureFixedPointCircuitCBMC::IsNeg() const {
  const auto bitlength = share_->Get()->GetBitLength();
  if (bitlength == 32) {
    // ShareWrapper sign_bit = share_->Split()[bitlength - 1];
    // return sign_bit;
    throw std::runtime_error("32-bit Boolean fixed-point circuit not generated yet");
  } else if (bitlength == 64) {
    ShareWrapper sign_bit = share_->Split()[bitlength - 1];
    return sign_bit;
  } else {
    throw std::runtime_error("Only support 64-bit Boolean fixed-point");
  }
}

ShareWrapper SecureFixedPointCircuitCBMC::IsZero() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> eqz_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kIsZero_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kIsZero_circuit, bitlength, "_depth");

    if ((eqz_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point is_zero circuit with file path {}", path));
      }
    } else {
      eqz_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(eqz_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point is_zero circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return share_input.Evaluate(eqz_algorithm).Split().at(0);
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Ceil() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ceil_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kCeil_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kCeil_circuit, bitlength, "_depth");

    if ((ceil_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean fixed-point ceil circuit with file path {}", path));
      }
    } else {
      ceil_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ceil_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean fixed-point ceil circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(ceil_algorithm));
  }
}

// // directly manipulate boolean bits
// SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Floor() const {
//   if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
//     throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW
//     shares");
//   } else {  // BooleanCircuitType
//     const auto bitlength = share_->Get()->GetBitLength();
//     std::shared_ptr<AlgorithmDescription> ceil_algorithm;
//     std::string path;

//     if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
//       path = ConstructPath(FixedPointOperationType::kFloor_circuit, bitlength, "_size");
//     else  // GMW, use depth-optimized circuit
//       path = ConstructPath(FixedPointOperationType::kFloor_circuit, bitlength, "_depth");

//     if ((ceil_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
//       if constexpr (kDebug) {
//         logger_->LogDebug(
//             fmt::format("Found in cache Boolean fixed-point floor circuit with file path {}",
//             path));
//       }
//     } else {
//       ceil_algorithm =
//           std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
//       assert(ceil_algorithm);
//       if constexpr (kDebug) {
//         logger_->LogDebug(fmt::format("Read Boolean fixed-point floor circuit from file {}",
//         path));
//       }
//     }
//     const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
//     return SecureFixedPointCircuitCBMC(share_input.Evaluate(ceil_algorithm));
//   }
// }

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Floor() const {
  std::vector<ShareWrapper> share_split = share_->Split();
  const auto bitlength = share_->Get()->GetBitLength();
  std::size_t num_of_simd = (*share_)->GetNumberOfSimdValues();

  // std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
  // std::vector<std::uint32_t> vector_of_zero(num_of_simd, 0);
  // ShareWrapper boolean_gmw_bmr_gc_share_zero;
  // ShareWrapper boolean_gmw_bmr_gc_share_zero_bit = boolean_gmw_bmr_gc_share_zero.Split().at(0);

  if (bitlength == 32) {
    throw std::runtime_error("32-bit Boolean fixed-point circuit not generated yet");
  } else if (bitlength == 64) {
    // boolean_gmw_bmr_gc_share_zero =
    //     ShareWrapper(share_->Get()->GetBackend().ConstantBooleanGmwInput(ToInput(vector_of_zero)));

    // TODO: create constant wire directly
    // ShareWrapper constant_boolean_gmw_or_bmr_share_zero = share_split[0] ^ share_split[0];
    ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
        share_->CreateConstantAsBooleanGmwBmrGCInput(false, num_of_simd);

    for (std::size_t i = 0; i < f_; i++) {
      // set all the fraction bits as zero
      share_split[i] = constant_boolean_gmw_or_bmr_share_zero;
    }
  }

  ShareWrapper boolean_gmw_bmr_gc_share_floor = ShareWrapper::Concatenate(share_split);
  return SecureFixedPointCircuitCBMC(boolean_gmw_bmr_gc_share_floor);
}

SecureSignedInteger SecureFixedPointCircuitCBMC::Fx2Int(std::size_t integer_bit_length) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    if (integer_bit_length != 64) {
      throw std::runtime_error("Fixed-point operations only support conversion to 64-bit integers");
    }

    std::shared_ptr<AlgorithmDescription> fx2int_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kFx2Int_circuit, bitlength, "_size",
                           integer_bit_length, 0);
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kFx2Int_circuit, bitlength, "_depth",
                           integer_bit_length, 0);

    if ((fx2int_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean fixed-point to integer circuit with file path {}", path));
      }
    } else {
      fx2int_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(fx2int_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean fixed-point to integer circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureSignedInteger(share_input.Evaluate(fx2int_algorithm));
  }
}

SecureSignedInteger SecureFixedPointCircuitCBMC::RoundedFx2Int() const {
  std::vector<ShareWrapper> fixed_point_boolean_gmw_bmr_gc_share_vector = share_->Split();

  // ShareWrapper constant_boolean_gmw_bmr_gc_share_zero =
  //     fixed_point_boolean_gmw_bmr_gc_share_vector[0] ^
  //     fixed_point_boolean_gmw_bmr_gc_share_vector[0];

  ShareWrapper constant_boolean_gmw_bmr_gc_share_sign =
      fixed_point_boolean_gmw_bmr_gc_share_vector.back();

  std::vector<ShareWrapper> signed_integer_boolean_gmw_bmr_gc_share(k_);
  for (std::size_t i = 0; i < k_; i++) {
    signed_integer_boolean_gmw_bmr_gc_share[i] = constant_boolean_gmw_bmr_gc_share_sign;
  }

  for (std::size_t i = 0; i < (k_ - f_); i++) {
    signed_integer_boolean_gmw_bmr_gc_share[i] =
        fixed_point_boolean_gmw_bmr_gc_share_vector[i + f_];
  }

  return ShareWrapper::Concatenate(signed_integer_boolean_gmw_bmr_gc_share);
}

SecureFloatingPointCircuitABY SecureFixedPointCircuitCBMC::Fx2FL(
    std::size_t floating_point_bit_length) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> fx2fl_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kFx2FL_circuit, bitlength, "_size", 0,
                           floating_point_bit_length);
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kFx2FL_circuit, bitlength, "_depth", 0,
                           floating_point_bit_length);

    if ((fx2fl_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean Fx2FL circuit with file path {}", path));
      }
    } else {
      fx2fl_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(fx2fl_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean Fx2FL circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};

    // std::cout << "111" << std::endl;
    std::size_t num_of_simd = (*share_)->GetNumberOfSimdValues();

    // as the circuit only works for positive fixed-point numbers
    // we manuelly deal with the case when input is negative and the case when input is zero
    ShareWrapper boolean_gmw_bmr_gc_share_input = *share_;
    std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_input_vector = share_->Split();
    ShareWrapper floating_point_boolean_gmw_bmr_gc_share = share_input.Evaluate(fx2fl_algorithm);
    // std::cout << "222" << std::endl;
    std::vector<ShareWrapper> floating_point_boolean_gmw_bmr_gc_share_vector =
        floating_point_boolean_gmw_bmr_gc_share.Split();

    // set the sign bit of floating-point
    floating_point_boolean_gmw_bmr_gc_share_vector.back() =
        floating_point_boolean_gmw_bmr_gc_share_vector.back() ^
        boolean_gmw_bmr_gc_share_input_vector.back();
    // std::cout << "333" << std::endl;

    ShareWrapper floating_point_boolean_gmw_bmr_gc_share_with_sign =
        ShareWrapper::Concatenate(floating_point_boolean_gmw_bmr_gc_share_vector);

    // TODO: create constant share directly
    ShareWrapper constant_floating_point_boolean_gmw_bmr_gc_share_zero =
        floating_point_boolean_gmw_bmr_gc_share_with_sign ^
        floating_point_boolean_gmw_bmr_gc_share_with_sign;

    // std::cout << "444" << std::endl;
    // when the input is zero, the bits of floating-point are all zeros
    ShareWrapper boolean_gmw_bmr_gc_share_input_is_zero =
        SecureFixedPointCircuitCBMC(boolean_gmw_bmr_gc_share_input).IsZero();
    ShareWrapper fixed_point_boolean_gmw_bmr_gc_share_with_sign_or_zero =
        boolean_gmw_bmr_gc_share_input_is_zero.Mux(
            constant_floating_point_boolean_gmw_bmr_gc_share_zero,
            floating_point_boolean_gmw_bmr_gc_share_with_sign);
    // std::cout << "555" << std::endl;

    // // =========
    // ShareWrapper boolean_gmw_bmr_gc_share_input = *share_;
    //     // std::vector<ShareWrapper> boolean_gmw_bmr_gc_share_input_vector = share_->Split();
    //     ShareWrapper floating_point_boolean_gmw_bmr_gc_share =
    //     share_input.Evaluate(fx2fl_algorithm);
    //     // std::vector<ShareWrapper> fixed_point_boolean_gmw_bmr_gc_share_vector =
    //     //     fixed_point_boolean_gmw_bmr_gc_share.Split();

    //     // // set the sign bit of floating-point
    //     // fixed_point_boolean_gmw_bmr_gc_share_vector.back() =
    //     //     fixed_point_boolean_gmw_bmr_gc_share_vector.back() ^
    //     boolean_gmw_bmr_gc_share_input_vector.back();

    //     // ShareWrapper fixed_point_boolean_gmw_bmr_gc_share_with_sign =
    //     //     ShareWrapper::Concatenate(fixed_point_boolean_gmw_bmr_gc_share_vector);

    //     // when the input is zero, the bits of floating-point are all zeros
    //     ShareWrapper boolean_gmw_bmr_gc_share_input_is_zero =
    //         SecureFixedPointCircuitCBMC(boolean_gmw_bmr_gc_share_input).EQZ();
    //     ShareWrapper floating_point_boolean_gmw_bmr_gc_share_with_sign_or_zero =
    //         boolean_gmw_bmr_gc_share_input_is_zero.Mux(boolean_gmw_bmr_gc_share_input,
    //                                             floating_point_boolean_gmw_bmr_gc_share);

    return SecureFloatingPointCircuitABY(fixed_point_boolean_gmw_bmr_gc_share_with_sign_or_zero);
  }
}

// TODO: need to generate efficient circuits
SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Ln() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    return (*this).Log2_P2508() * double(M_LN2);
  }
}
SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Exp() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    return ((*this) * double(M_LOG2E)).Exp2_P1045();
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Neg() const {
  SecureSignedInteger fixed_point_as_signed_integer = SecureSignedInteger(share_->Get());
  SecureSignedInteger fixed_point_as_signed_integer_neg = fixed_point_as_signed_integer.Neg();

  return fixed_point_as_signed_integer_neg.Get();
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Abs() const {
  std::vector<ShareWrapper> fixed_point_boolean_gmw_bmr_gc_share_vector = share_->Split();

  const auto bitlength = share_->Get()->GetBitLength();
  ShareWrapper sign_bit = fixed_point_boolean_gmw_bmr_gc_share_vector[bitlength - 1];

  ShareWrapper fixed_point_boolean_gmw_bmr_gc_share_neg = (*this).Neg().Get();

  return sign_bit.Mux(fixed_point_boolean_gmw_bmr_gc_share_neg, this->Get());
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Sin_P3307_0_1() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> sin_P3307_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSin_P3307_0_1_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kSin_P3307_0_1_circuit, bitlength, "_depth");

    if ((sin_P3307_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean fixed-point exp2 circuit with file path {}", path));
      }
    } else {
      sin_P3307_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(sin_P3307_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean fixed-point exp2 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(sin_P3307_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Sin_P3307_0_4() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    // std::cout << "222" << std::endl;
    // y1 in range (0,4)
    SecureFixedPointCircuitCBMC fixed_point_y1 = *this;
    ShareWrapper boolean_gmw_or_bmr_share_y1_greater_than_2 = fixed_point_y1 > double(2);
    // std::cout << "333" << std::endl;
    ShareWrapper boolean_gmw_or_bmr_share_y2 = boolean_gmw_or_bmr_share_y1_greater_than_2.Mux(
        (fixed_point_y1 - double(2)).Get(), fixed_point_y1.Get());

    // std::cout << "444" << std::endl;

    // y2 in range (0,2),
    SecureFixedPointCircuitCBMC fixed_point_y2 =
        SecureFixedPointCircuitCBMC(boolean_gmw_or_bmr_share_y2);
    ShareWrapper boolean_gmw_or_bmr_share_y2_greater_than_1 = fixed_point_y2 > double(1);
    ShareWrapper boolean_gmw_or_bmr_share_y3 = boolean_gmw_or_bmr_share_y2_greater_than_1.Mux(
        (fixed_point_y2.Neg() + double(2)).Get(), fixed_point_y2.Get());

    // y3 in range (0,1), abs(sin(y3*0.5*pi)) = sin(y1*0.5*pi)
    SecureFixedPointCircuitCBMC fixed_point_y3_sin =
        SecureFixedPointCircuitCBMC(boolean_gmw_or_bmr_share_y3).Sin_P3307_0_1();

    // y4 in range (0,1), sin(y4*0.5*pi) = sin(y1*0.5*pi)
    SecureFixedPointCircuitCBMC fixed_point_y4 = boolean_gmw_or_bmr_share_y1_greater_than_2.Mux(
        fixed_point_y3_sin.Neg().Get(), fixed_point_y3_sin.Get());

    return fixed_point_y4;
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Cos_P3508() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error("Fixed-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> cos_P3508_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr ||
        share_->Get()->GetProtocol() ==
            MpcProtocol::kGarbledCircuit)  // BMR, use size-optimized circuit
      path = ConstructPath(FixedPointOperationType::kCos_P3508_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FixedPointOperationType::kCos_P3508_circuit, bitlength, "_depth");

    if ((cos_P3508_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean fixed-point exp2 circuit with file path {}", path));
      }
    } else {
      cos_P3508_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(cos_P3508_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format("Read Boolean fixed-point exp2 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    return SecureFixedPointCircuitCBMC(share_input.Evaluate(cos_P3508_algorithm));
  }
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Sqr() const { return (*this) * (*this); }

std::string SecureFixedPointCircuitCBMC::ConstructPath(
    const FixedPointOperationType type, const std::size_t bitlength, std::string suffix,
    const std::size_t integer_bit_length, const std::size_t floating_point_bit_length) const {
  std::string operation_type_string;

  std::string k_str = "64";
  std::string f_str = "16";
  std::string circuit_source = "CBMC";

  switch (type) {
    case FixedPointOperationType::kAdd_circuit: {
      operation_type_string = "add";
      break;
    }
    case FixedPointOperationType::kSub_circuit: {
      operation_type_string = "sub";
      break;
    }
    case FixedPointOperationType::kMul_circuit: {
      operation_type_string = "mul";
      break;
    }
    case FixedPointOperationType::kDiv_circuit: {
      operation_type_string = "div";
      break;
    }
    case FixedPointOperationType::kDiv_Goldschmidt_circuit: {
      operation_type_string = "div_Goldschmidt";
      break;
    }
    case FixedPointOperationType::kLt_circuit: {
      operation_type_string = "lt";
      break;
    }
    case FixedPointOperationType::kGt_circuit: {
      operation_type_string = "gt";
      break;
    }
    case FixedPointOperationType::kEq_circuit: {
      operation_type_string = "eq";
      break;
    }
    case FixedPointOperationType::kIsZero_circuit: {
      operation_type_string = "is_zero";
      break;
    }
    // case FixedPointOperationType::kLTZ_circuit: {
    //   operation_type_string = "ltz";
    //   break;
    // }
    case FixedPointOperationType::kSqrt_circuit: {
      operation_type_string = "sqrt";
      break;
    }
    case FixedPointOperationType::kSqrt_P0132_circuit: {
      operation_type_string = "sqrt_P0132";
      break;
    }
    case FixedPointOperationType::kExp2_P1045_circuit: {
      operation_type_string = "exp2_P1045";
      break;
    }
    case FixedPointOperationType::kExp2_P1045_Neg_0_1_circuit: {
      operation_type_string = "exp2_P1045_neg_0_1";
      // operation_type_string = "exp2_P1045_neg_0_1_overflow"; // ! this circuit may not be accurate 
      break;
    }
    case FixedPointOperationType::kLog2_P2508_circuit: {
      operation_type_string = "log2_P2508"; // ! this circuit is very slow, needs to be improved
      // operation_type_string = "log2_P2508_overflow"; // ! this circuit is not correct
      break;
    }
    case FixedPointOperationType::kSin_P3307_0_1_circuit: {
      operation_type_string = "sin_P3307";
      break;
    }
    case FixedPointOperationType::kCos_P3508_circuit: {
      operation_type_string = "cos_P3508";
      break;
    }
    // case FixedPointOperationType::kExp_circuit: {
    //   operation_type_string = "exp";
    //   break;
    // }
    // case FixedPointOperationType::kLn_circuit: {
    //   operation_type_string = "ln";
    //   break;
    // }
    case FixedPointOperationType::kCeil_circuit: {
      operation_type_string = "ceil";
      break;
    }
    case FixedPointOperationType::kFx2Int_circuit: {
      operation_type_string = "to_int" + std::to_string(integer_bit_length);
      break;
    }
    case FixedPointOperationType::kFx2FL_circuit: {
      operation_type_string = "to_float" + std::to_string(floating_point_bit_length);
      break;
    }

    default:
      throw std::runtime_error(
          fmt::format("Invalid fixed-point operation required: {}", to_string(type)));
  }
  return fmt::format("{}/circuits/fixed_point_CBMC_k{}_f{}/fix{}_{}{}.bristol", kRootDir, k_, f_,
                     bitlength, operation_type_string, suffix);
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Simdify(
    std::span<SecureFixedPointCircuitCBMC> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureFixedPointCircuitCBMC& i) -> SharePointer { return i.Get().Get(); });
  return SecureFixedPointCircuitCBMC(ShareWrapper::Simdify(input_as_shares));
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Simdify(
    std::vector<SecureFixedPointCircuitCBMC>&& input) {
  return Simdify(input);
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Subset(std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureFixedPointCircuitCBMC(unwrap.Subset(positions));
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Subset(std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

std::vector<SecureFixedPointCircuitCBMC> SecureFixedPointCircuitCBMC::Unsimdify() const {
  auto unsimdify_gate = share_->Get()->GetRegister()->EmplaceGate<UnsimdifyGate>(share_->Get());
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<SecureFixedPointCircuitCBMC> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return SecureFixedPointCircuitCBMC(share); });
  return result;
  return result;
}

SecureFixedPointCircuitCBMC SecureFixedPointCircuitCBMC::Out(std::size_t output_owner) const {
  return SecureFixedPointCircuitCBMC(share_->Out(output_owner));
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template <typename T>
T SecureFixedPointCircuitCBMC::As() const {
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
                      typeid(T).name(), to_string(share_->Get()->GetProtocol())));
    }
  } else {
    throw std::invalid_argument("Unsupported protocol for SecureUnsignedInteger::As()");
  }
}

template std::uint8_t SecureFixedPointCircuitCBMC::As() const;
template std::uint16_t SecureFixedPointCircuitCBMC::As() const;
template std::uint32_t SecureFixedPointCircuitCBMC::As() const;
template std::uint64_t SecureFixedPointCircuitCBMC::As() const;
template __uint128_t SecureFixedPointCircuitCBMC::As() const;

template <typename T, typename A>
std::vector<T, A> SecureFixedPointCircuitCBMC::AsVector() const {
  auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
  std::vector<T> as_unsigned_output_vector = encrypto::motion::ToVectorOutput<T>(share_out);

  return as_unsigned_output_vector;
}

template std::vector<std::uint8_t> SecureFixedPointCircuitCBMC::AsVector() const;
template std::vector<std::uint16_t> SecureFixedPointCircuitCBMC::AsVector() const;
template std::vector<std::uint32_t> SecureFixedPointCircuitCBMC::AsVector() const;
template std::vector<std::uint64_t> SecureFixedPointCircuitCBMC::AsVector() const;
template std::vector<__uint128_t> SecureFixedPointCircuitCBMC::AsVector() const;

template <typename FxType, typename FxType_int>
double SecureFixedPointCircuitCBMC::AsFixedPoint(
    std::size_t fixed_point_bit_length, std::size_t fixed_point_fraction_part_bit_length) const {
  FxType as_unsigned_output = As<FxType>();

  // std::cout << "as_unsigned_output: " << as_unsigned_output << std::endl;

  double as_double_output;
  as_double_output = FixedPointToDouble<FxType, FxType_int>(as_unsigned_output, k_, f_);

  return as_double_output;
}

template double SecureFixedPointCircuitCBMC::AsFixedPoint<std::uint64_t, std::int64_t>(
    std::size_t fixed_point_bit_length, std::size_t fixed_point_fraction_part_bit_length) const;

template <typename FxType, typename FxType_int>
std::vector<double> SecureFixedPointCircuitCBMC::AsFixedPointVector(
    std::size_t fixed_point_bit_length, std::size_t fixed_point_fraction_part_bit_length) const {
  const auto bitlength = share_->Get()->GetBitLength();
  if (bitlength == 32) {
    throw std::runtime_error("Only supported 64 bits fixed-point numbers");
    // auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    // std::vector<std::uint32_t> as_unsigned_output_vector =
    //     encrypto::motion::ToVectorOutput<std::uint32_t>(share_out);

    // std::vector<double> as_fixed_output_vector;
    // for (std::size_t i = 0; i < as_unsigned_output_vector.size(); i++) {
    //   as_fixed_output_vector.emplace_back(FixedPointToDouble<FxType, FxType_int>(
    //       as_unsigned_output_vector[i], k_, f_));
    // }
    // return as_fixed_output_vector;

  } else if (bitlength == 64) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    std::vector<std::uint64_t> as_unsigned_output_vector =
        encrypto::motion::ToVectorOutput<std::uint64_t>(share_out);

    std::vector<double> as_fixed_output_vector;
    for (std::size_t i = 0; i < as_unsigned_output_vector.size(); i++) {
      as_fixed_output_vector.emplace_back(
          FixedPointToDouble<FxType, FxType_int>(as_unsigned_output_vector[i], k_, f_));
      // std::cout << "as_unsigned_output_vector: " << as_unsigned_output_vector[i] << std::endl;
      // std::cout << "as_fixed_output_vector: " << as_fixed_output_vector[i] << std::endl;
      // std::cout << std::endl;
    }
    return as_fixed_output_vector;

  }

  else {
    // TODO: fix later
    // throw std::invalid_argument(fmt::format(
    //     "Unsupported output type in SecureFixedPointCircuitCBMC::As<{}>() for {} Protocol",
    //     typeid(FxType).name(), share_->Get()->GetProtocol()));
    throw std::runtime_error("Only supported 64 bits fixed-point numbers");
  }

  return std::vector<double>();
}

// template std::uint32_t SecureFixedPointCircuitCBMC::As() const;
// template std::uint64_t SecureFixedPointCircuitCBMC::As() const;
// template std::vector<std::uint32_t> SecureFixedPointCircuitCBMC::As() const;
// template std::vector<std::uint64_t> SecureFixedPointCircuitCBMC::As() const;

template std::vector<double>
SecureFixedPointCircuitCBMC::AsFixedPointVector<std::uint64_t, std::int64_t>(
    std::size_t fixed_point_bit_length, std::size_t fixed_point_fraction_part_bit_length) const;

}  // namespace encrypto::motion
