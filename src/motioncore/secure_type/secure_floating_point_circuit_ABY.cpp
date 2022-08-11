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

#include "secure_floating_point_circuit_ABY.h"

#include <fmt/format.h>
#include <iterator>

#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "utility/constants.h"
#include "utility/logger.h"

namespace encrypto::motion {

SecureFloatingPointCircuitABY::SecureFloatingPointCircuitABY(const SharePointer& other)
    : share_(std::make_unique<ShareWrapper>(other)),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFloatingPointCircuitABY::SecureFloatingPointCircuitABY(SharePointer&& other)
    : share_(std::make_unique<ShareWrapper>(std::move(other))),
      logger_(share_.get()->Get()->GetRegister()->GetLogger()) {}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator+(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> addition_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kAdd_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kAdd_circuit, bitlength, "_depth");

    if ((addition_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point addition circuit with file path {}", path));
      }
    } else {
      addition_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(addition_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point addition circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFloatingPointCircuitABY(share_input.Evaluate(addition_algorithm));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator-(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    std::shared_ptr<AlgorithmDescription> subtraction_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSub_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSub_circuit, bitlength, "_depth");

    if ((subtraction_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point subtraction circuit with file path {}", path));
      }
    } else {
      subtraction_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(subtraction_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point subtraction circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFloatingPointCircuitABY(share_input.Evaluate(subtraction_algorithm));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator*(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> multiplication_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kMul_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kMul_circuit, bitlength, "_depth");

    if ((multiplication_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point multiplication circuit with file path {}",
            path));
      }
    } else {
      multiplication_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(multiplication_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point multiplication circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFloatingPointCircuitABY(share_input.Evaluate(multiplication_algorithm));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator/(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> division_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kDiv_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kDiv_circuit, bitlength, "_depth");

    if ((division_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point division circuit with file path {}", path));
      }
    } else {
      division_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(division_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point division circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return SecureFloatingPointCircuitABY(share_input.Evaluate(division_algorithm));
  }
}

ShareWrapper SecureFloatingPointCircuitABY::operator<(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kGt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kGt_circuit, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point less than circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point less than circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*other.share_, *share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureFloatingPointCircuitABY::operator>(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> is_greater_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kGt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kGt_circuit, bitlength, "_depth");

    if ((is_greater_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point greater than circuit with file path {}", path));
      }
    } else {
      is_greater_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(is_greater_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point greater than circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *other.share_})};
    return share_input.Evaluate(is_greater_algorithm).Split().at(0);
  }
}

ShareWrapper SecureFloatingPointCircuitABY::operator==(
    const SecureFloatingPointCircuitABY& other) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    if constexpr (kDebug) {
      if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean floating-point equality circuit in BMR");
      } else {
        logger_->LogDebug("Creating a Boolean floating-point equality circuit in GMW");
      }
    }
    // ! we assume -0 and +0 not equal to each other
    return this->Get() == other.Get();
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Neg() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    if constexpr (kDebug) {
      if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean floating-point negation circuit in BMR");
      } else {
        logger_->LogDebug("Creating a Boolean floating-point negation circuit in GMW");
      }
    }

    // invert the sign bit of the floating-point number
    std::vector<ShareWrapper> share_split_vector = share_->Split();
    ShareWrapper share_sign = share_split_vector.back();
    share_split_vector.back() = ~share_sign;
    return ShareWrapper::Concatenate(share_split_vector);
  }
}

// TODO: simd should work now
// for floating-point, zero has two representations:
// +0 (with sign bit s = 0),
// -0 (with sign bit s = 1)
ShareWrapper SecureFloatingPointCircuitABY::EQZ() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {
    const auto bitlength = share_->Get()->GetBitLength();
    std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();

    if constexpr (kDebug) {
      if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean floating-point equal to zero circuit in BMR");
      } else {
        logger_->LogDebug("Creating a Boolean floating-point equal to zero circuit in GMW");
      }
    }

    // exclude the sign bit for comparison
    std::vector<ShareWrapper> boolean_gmw_or_bmr_share_floating_point_bit_vector = share_->Split();
    std::vector<ShareWrapper> boolean_gmw_or_bmr_share_floating_point_bit_vector_exclude_sign_bit(
        boolean_gmw_or_bmr_share_floating_point_bit_vector.begin(),
        boolean_gmw_or_bmr_share_floating_point_bit_vector.end() - 1);

    ShareWrapper boolean_gmw_or_bmr_share_floating_point_bits = ShareWrapper::Concatenate(
        boolean_gmw_or_bmr_share_floating_point_bit_vector_exclude_sign_bit);

    ShareWrapper constant_boolean_gmw_or_bmr_share_zero_bit =
        boolean_gmw_or_bmr_share_floating_point_bit_vector[0] ^
        boolean_gmw_or_bmr_share_floating_point_bit_vector[0];

    std::vector<ShareWrapper> constant_boolean_gmw_or_bmr_share_zero_vector(
        bitlength - 1, constant_boolean_gmw_or_bmr_share_zero_bit);

    ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
        ShareWrapper::Concatenate(constant_boolean_gmw_or_bmr_share_zero_vector);

    return boolean_gmw_or_bmr_share_floating_point_bits == constant_boolean_gmw_or_bmr_share_zero;
  }
}

ShareWrapper SecureFloatingPointCircuitABY::LTZ() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    if constexpr (kDebug) {
      if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
        throw std::runtime_error(
            "Floating-point operations are not supported for Arithmetic GMW shares");
      } else {
        if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
          logger_->LogDebug("Creating a Boolean floating-point less than to zero circuit in BMR");
        } else {
          logger_->LogDebug("Creating a Boolean floating-point less than to zero circuit in GMW");
        }
      }
    }

    const auto bitlength = share_->Get()->GetBitLength();
    if (bitlength == 32) {
      ShareWrapper sign_bit = share_->Split()[bitlength - 1];
      return sign_bit;
    }
    if (bitlength == 64) {
      ShareWrapper sign_bit = share_->Split()[bitlength - 1];
      return sign_bit;
    }
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Abs() const {
  if (share_->Get()->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    if constexpr (kDebug) {
      if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
        throw std::runtime_error(
            "Floating-point operations are not supported for Arithmetic GMW shares");
      } else {
        if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
          logger_->LogDebug("Creating a Boolean floating-point absolute value circuit in BMR");
        } else {
          logger_->LogDebug("Creating a Boolean floating-point sabsolute value circuit in GMW");
        }
      }
    }

    // ShareWrapper boolean_gmw_or_bmr_share_floating_point_less_than_zero = (*this).LTZ();
    std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_vector = share_->Split();

    const auto bitlength = share_->Get()->GetBitLength();
    if (bitlength == 32) {
      ShareWrapper sign_bit = floating_point_boolean_gmw_or_bmr_share_vector[bitlength - 1];
      ShareWrapper constant_boolean_gmw_or_bmr_share_zero = sign_bit ^ sign_bit;
      floating_point_boolean_gmw_or_bmr_share_vector[bitlength - 1] =
          constant_boolean_gmw_or_bmr_share_zero;

      return ShareWrapper::Concatenate(floating_point_boolean_gmw_or_bmr_share_vector);
    }
    if (bitlength == 64) {
      ShareWrapper sign_bit = floating_point_boolean_gmw_or_bmr_share_vector[bitlength - 1];
      ShareWrapper constant_boolean_gmw_or_bmr_share_zero = sign_bit ^ sign_bit;
      floating_point_boolean_gmw_or_bmr_share_vector[bitlength - 1] =
          constant_boolean_gmw_or_bmr_share_zero;

      return ShareWrapper::Concatenate(floating_point_boolean_gmw_or_bmr_share_vector);
    }
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Ceil() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ceil_algorithm;
    std::string path;
    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kCeil_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kCeil_circuit, bitlength, "_depth");
    if ((ceil_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point ceil circuit with file path {}", path));
      }
    } else {
      ceil_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ceil_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point ceil circuit from file {}", path));
      }
    }

    // create constant share of zero
    // the second input of the circuit must be zero bits (because of CBMC-GC generation rules)
    ShareWrapper constant_boolean_gmw_or_bmr_share_zero = (*share_) ^ (*share_);

    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, constant_boolean_gmw_or_bmr_share_zero})};
    const auto evaluation_result = share_input.Evaluate(ceil_algorithm);
    return SecureFloatingPointCircuitABY(evaluation_result);
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Floor() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> floor_algorithm;
    std::string path;
    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kFloor_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit

      path = ConstructPath(FloatingPointOperationType::kFloor_circuit, bitlength, "_depth");
    if ((floor_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point floor circuit with file path {}", path));
      }
    } else {
      floor_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(floor_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point floor circuit from file {}", path));
      }
    }

    // create constant share of zero
    // the second input of the circuit must be zero bits (because of CBMC-GC generation rules)
    ShareWrapper constant_boolean_gmw_or_bmr_share_zero = (*share_) ^ (*share_);

    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, constant_boolean_gmw_or_bmr_share_zero})};
    const auto evaluation_result = share_input.Evaluate(floor_algorithm);
    return SecureFloatingPointCircuitABY(evaluation_result);
  }
}

SecureSignedInteger SecureFloatingPointCircuitABY::FL2Int(std::size_t integer_bit_length) const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> floating_point_to_integer_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kFL2Int_circuit, bitlength, "_size",
                           integer_bit_length);
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kFL2Int_circuit, bitlength, "_depth",
                           integer_bit_length);
    if ((floating_point_to_integer_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point to integer conversion circuit with file path {}",
            path));
      }
    } else {
      floating_point_to_integer_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(floating_point_to_integer_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean floating-point to integer conversion circuit from file {}", path));
      }
    }

    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_, *share_})};
    const auto evaluation_result = share_input.Evaluate(floating_point_to_integer_algorithm);
    return SecureSignedInteger(evaluation_result);
  }
}

// TODO: fixed after MulPow2m
SecureFixedPointCircuitCBMC SecureFloatingPointCircuitABY::FL2Fx(
    std::size_t fixed_point_fraction_bit_size, size_t fixed_point_bit_length) const {
  // SecureFloatingPointCircuitABY floating_point_multiple_pow2_fixed_point_fraction_bit_size =
  //     (*this) * double(std::exp2(fixed_point_fraction_bit_size));

  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    if constexpr (kDebug) {
      if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug(
            "Creating a Boolean floating-point to fixed-point conversion circuit in BMR");
      } else {
        logger_->LogDebug(
            "Creating a Boolean floating-point to fixed-point conversion circuit in GMW");
      }
    }

    SecureFloatingPointCircuitABY floating_point_multiple_pow2_fixed_point_fraction_bit_size =
        (*this).MulPow2m(std::int64_t(fixed_point_fraction_bit_size));

    // std::cout << "FL2Int()" << std::endl;
    // std::size_t fixed_point_bit_length = 64;

    return floating_point_multiple_pow2_fixed_point_fraction_bit_size.FL2Int(fixed_point_bit_length)
        .Get();
  }
}

// circuit only supports 32-bit floating-point as input,
// we use the 64-bit log2 and 64-bit exp2 circuits for 64-bit inputs
SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Exp() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();

    // 32-bit floating point input
    if (bitlength == 32) {
      // std::cout << "bitlength: " << bitlength << std::endl;
      std::shared_ptr<AlgorithmDescription> exp_algorithm;
      std::string path;

      if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kExp_circuit, bitlength, "_size");
      else  // GMW, use depth-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kExp_circuit, bitlength, "_depth");
      if ((exp_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
        if constexpr (kDebug) {
          logger_->LogDebug(
              fmt::format("Found in cache Boolean 32-bit floating-point exponentiation circuit "
                          "with file path {}",
                          path));
        }
      } else {
        exp_algorithm =
            std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
        assert(exp_algorithm);
        if constexpr (kDebug) {
          logger_->LogDebug(fmt::format(
              "Read Boolean 32-bit floating-point exponentiation circuit from file {}", path));
        }
      }
      const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
      const auto evaluation_result_wires = share_input.Evaluate(exp_algorithm).Split();

      // ignore the wire for other information (e.g., errors, ...)
      std::vector<ShareWrapper>::const_iterator first = evaluation_result_wires.begin();
      std::vector<ShareWrapper>::const_iterator last = evaluation_result_wires.begin() + bitlength;
      const std::vector<ShareWrapper> truncated_wires(first, last);
      return SecureFloatingPointCircuitABY(ShareWrapper::Concatenate(truncated_wires));
    }

    // (bitlength == 64)
    // for 64-bit floating-point input, use following conversion
    // e^x = 2^(x*log2(e))
    else {
      // std::cout << "bitlength: " << bitlength << std::endl;
      if constexpr (kDebug) {
        if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
          logger_->LogDebug("Creating a Boolean 64-bit exponentiation circuit in BMR");
        } else {
          logger_->LogDebug("Creating a Boolean 64-bit exponentiation circuit in GMW");
        }
      }

      std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
      std::vector<double> vector_of_constant_log2_e(num_of_simd, log2(std::numbers::e));

      SecureFloatingPointCircuitABY boolean_gmw_or_bmr_share_floating_point_constant_log2_e;

      // TODO: test if bmr or bgmw works
      if ((*share_)->GetProtocol() == MpcProtocol::kBooleanGmw) {
        boolean_gmw_or_bmr_share_floating_point_constant_log2_e =
            share_.get()->Get()->GetBackend().ConstantAsBooleanGmwInput(
                encrypto::motion::ToInput<double, std::true_type>(vector_of_constant_log2_e));
      } else {
        boolean_gmw_or_bmr_share_floating_point_constant_log2_e =
            share_.get()->Get()->GetBackend().ConstantAsBmrInput(
                encrypto::motion::ToInput<double, std::true_type>(vector_of_constant_log2_e));
      }

      SecureFloatingPointCircuitABY boolean_gmw_or_bmr_share_floating_point_x_mul_constant_log2_e =
          (*this) * boolean_gmw_or_bmr_share_floating_point_constant_log2_e;

      SecureFloatingPointCircuitABY exp_result =
          boolean_gmw_or_bmr_share_floating_point_x_mul_constant_log2_e.Exp2();
      return exp_result;
    }
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Exp2() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> exp2_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kExp2_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kExp2_circuit, bitlength, "_depth");
    if ((exp2_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point exp2 circuit with file path {}", path));
      }
    } else {
      exp2_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(exp2_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point exp2 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
    const auto evaluation_result_wires = share_input.Evaluate(exp2_algorithm).Split();

    // ignore the wire for other information (e.g., errors, ...)
    std::vector<ShareWrapper>::const_iterator first = evaluation_result_wires.begin();
    std::vector<ShareWrapper>::const_iterator last = evaluation_result_wires.begin() + bitlength;
    const std::vector<ShareWrapper> truncated_wires(first, last);
    return SecureFloatingPointCircuitABY(ShareWrapper::Concatenate(truncated_wires));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Log2() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> log2_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kLog2_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kLog2_circuit, bitlength, "_depth");
    if ((log2_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point log2 circuit with file path {}", path));
      }
    } else {
      log2_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(log2_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point log2 circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
    const auto evaluation_result_wires = share_input.Evaluate(log2_algorithm).Split();
    // ignore the wire for other information (e.g., errors, ...)
    std::vector<ShareWrapper>::const_iterator first = evaluation_result_wires.begin();
    std::vector<ShareWrapper>::const_iterator last = evaluation_result_wires.begin() + bitlength;
    const std::vector<ShareWrapper> truncated_wires(first, last);
    return SecureFloatingPointCircuitABY(ShareWrapper::Concatenate(truncated_wires));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Ln() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> ln_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kLn_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kLn_circuit, bitlength, "_depth");
    if ((ln_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point natural logarithm circuit with file path {}",
            path));
      }
    } else {
      ln_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(ln_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean floating-point natural logarithm circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
    const auto evaluation_result_wires = share_input.Evaluate(ln_algorithm).Split();
    std::vector<ShareWrapper>::const_iterator first = evaluation_result_wires.begin();
    std::vector<ShareWrapper>::const_iterator last = evaluation_result_wires.begin() + bitlength;
    const std::vector<ShareWrapper> truncated_wires(first, last);
    return SecureFloatingPointCircuitABY(ShareWrapper::Concatenate(truncated_wires));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Sqr() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> sqr_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSqr_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSqr_circuit, bitlength, "_depth");
    if ((sqr_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point square circuit with file path {}", path));
      }
    } else {
      sqr_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(sqr_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point square circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
    const auto evaluation_result = share_input.Evaluate(sqr_algorithm);
    return SecureFloatingPointCircuitABY(evaluation_result);
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Sqrt() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    std::shared_ptr<AlgorithmDescription> sqrt_algorithm;
    std::string path;
    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSqrt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kSqrt_circuit, bitlength, "_depth");
    if ((sqrt_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Found in cache Boolean floating-point square root circuit with file path {}", path));
      }
    } else {
      sqrt_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(sqrt_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Read Boolean floating-point square root circuit from file {}", path));
      }
    }
    const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
    const auto evaluation_result = share_input.Evaluate(sqrt_algorithm);
    return SecureFloatingPointCircuitABY(evaluation_result);
  }
}

// circuit only supports 32-bit floating-point as input,
// for 64-bit floating-point input, we first convert input to 32-bit floating point, then, use
// 32-bit circuit to compute the result, and convert the result to 64-bit floating point
SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Sin() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    if (bitlength == 32) {
      std::shared_ptr<AlgorithmDescription> sin_algorithm;
      std::string path;
      if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kSin_circuit, bitlength, "_size");
      else  // GMW, use depth-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kSin_circuit, bitlength, "_depth");
      if ((sin_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
        if constexpr (kDebug) {
          logger_->LogDebug(fmt::format(
              "Found in cache Boolean 32-bit floating-point sin circuit with file path {}", path));
        }
      } else {
        sin_algorithm =
            std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
        assert(sin_algorithm);
        if constexpr (kDebug) {
          logger_->LogDebug(
              fmt::format("Read Boolean 32-bit floating-point sin circuit from file {}", path));
        }
      }
      // std::cout << "before evaluation" << std::endl;
      const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
      const auto evaluation_result = share_input.Evaluate(sin_algorithm);
      // std::cout << "after evaluation" << std::endl;
      std::vector<ShareWrapper> evaluation_result_split = evaluation_result.Split();

      std::vector<ShareWrapper> single_precision_floating_point_result_vector(
          evaluation_result_split.begin(), evaluation_result_split.begin() + bitlength);

      return SecureFloatingPointCircuitABY(
          ShareWrapper::Concatenate(single_precision_floating_point_result_vector));
    }

    // TODO: test
    // bitlength==64
    else {
      if constexpr (kDebug) {
        if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
          logger_->LogDebug("Creating a 64-bit Boolean floating-point sin circuit in BMR");
        } else {
          logger_->LogDebug("Creating a 64-bit Boolean floating-point sin circuit in GMW");
        }
      }

      // convert 64-bit input to 32-bit input, use 32-bit circuit to compute sin(x)
      SecureFloatingPointCircuitABY single_precision_floating_point =
          (*this).ConvertDoublePrecisionToSinglePrecision();

      SecureFloatingPointCircuitABY single_precision_floating_point_sin =
          single_precision_floating_point.Sin();

      // convert 32-bit result to 64-bit result
      return single_precision_floating_point_sin.ConvertSinglePrecisionToDoublePrecision();
    }
  }
}

// circuit only supports 32-bit floating-point as input,
// for 64-bit floating-point input, we first convert input to 32-bit floating point, then, use
// 32-bit circuit to compute the result, and convert the result to 64-bit floating point
SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Cos() const {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    const auto bitlength = share_->Get()->GetBitLength();
    if (bitlength == 32) {
      std::shared_ptr<AlgorithmDescription> cos_algorithm;
      std::string path;
      if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kCos_circuit, bitlength, "_size");
      else  // GMW, use depth-optimized circuit
        path = ConstructPath(FloatingPointOperationType::kCos_circuit, bitlength, "_depth");
      if ((cos_algorithm = share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
        if constexpr (kDebug) {
          logger_->LogDebug(fmt::format(
              "Found in cache Boolean floating-point cos circuit with file path {}", path));
        }
      } else {
        cos_algorithm =
            std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
        assert(cos_algorithm);
        if constexpr (kDebug) {
          logger_->LogDebug(
              fmt::format("Read Boolean floating-point cos circuit from file {}", path));
        }
      }
      // std::cout << "before evaluation" << std::endl;
      const auto share_input{ShareWrapper::Concatenate(std::vector{*share_})};
      const auto evaluation_result = share_input.Evaluate(cos_algorithm);
      // std::cout << "after evaluation" << std::endl;
      std::vector<ShareWrapper> evaluation_result_split = evaluation_result.Split();

      std::vector<ShareWrapper> single_precision_floating_point_result_vector(
          evaluation_result_split.begin(), evaluation_result_split.begin() + bitlength);

      return SecureFloatingPointCircuitABY(
          ShareWrapper::Concatenate(single_precision_floating_point_result_vector));
    }

    // bitlength==64
    else {
      if constexpr (kDebug) {
        if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
          logger_->LogDebug("Creating a 64-bit Boolean floating-point cos circuit in BMR");
        } else {
          logger_->LogDebug("Creating a 64-bit Boolean floating-point cos circuit in GMW");
        }
      }

      // convert 64-bit input to 32-bit input, use 32-bit circuit to compute cos(x)
      SecureFloatingPointCircuitABY single_precision_floating_point =
          (*this).ConvertDoublePrecisionToSinglePrecision();

      SecureFloatingPointCircuitABY single_precision_floating_point_cos =
          single_precision_floating_point.Cos();

      return single_precision_floating_point_cos.ConvertSinglePrecisionToDoublePrecision();
    }
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::MulPow2m(std::int64_t m) const {
  // std::cout << "MulPow2m: " << std::endl;

  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType
    if (m == 0) {
      return *this;
    } else {
      // std::cout << "000" << std::endl;
      std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_x_vector = share_->Split();
      const auto bitlength = share_->Get()->GetBitLength();
      // std::cout << "111" << std::endl;

      if (bitlength == 32) {
        // std::cout << "222" << std::endl;
        using T = std::uint16_t;
        std::size_t T_size = sizeof(T) * 8;

        // std::cout << "333" << std::endl;
        ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
            floating_point_boolean_gmw_or_bmr_share_x_vector[0] ^
            floating_point_boolean_gmw_or_bmr_share_x_vector[0];

        // std::cout << "constant_boolean_gmw_or_bmr_share_zero.GetProtocol()"
        //           << (constant_boolean_gmw_or_bmr_share_zero->GetProtocol() == MpcProtocol::kBmr)
        //           << std::endl;

        ShareWrapper boolean_gmw_or_bmr_share_x_equal_zero = this->EQZ();
        // std::cout << "444" << std::endl;
        std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_x_exponent_vector(
            floating_point_boolean_gmw_or_bmr_share_x_vector.begin() +
                FLOATINGPOINT32_MANTISSA_BITS,
            floating_point_boolean_gmw_or_bmr_share_x_vector.begin() +
                FLOATINGPOINT32_MANTISSA_BITS + FLOATINGPOINT32_EXPONENT_BITS);
        // std::cout << "555" << std::endl;

        // compensate exponent of x with zero bits and convert it to a secure unsigned integer
        std::vector<ShareWrapper>
            floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector(T_size);

        for (std::size_t i = 0; i < T_size; i++) {
          floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector[i] =
              constant_boolean_gmw_or_bmr_share_zero;
        }
        for (std::size_t i = 0; i < FLOATINGPOINT32_EXPONENT_BITS; i++) {
          floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector[i] =
              floating_point_boolean_gmw_or_bmr_share_x_exponent_vector[i];
        }
        // std::cout << "666" << std::endl;
        SecureUnsignedInteger secure_unsigned_integer_x_exponent =
            SecureUnsignedInteger(ShareWrapper::Concatenate(
                floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector));
        // std::cout << "777" << std::endl;
        std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
        std::vector<T> vector_of_m(num_of_simd, T(m));

        SecureUnsignedInteger secure_unsigned_integer_m;
        if (share_->Get()->GetProtocol() == MpcProtocol::kBmr) {
          secure_unsigned_integer_m = SecureUnsignedInteger(
              share_->Get()->GetBackend().ConstantAsBmrInput(ToInput<T>(vector_of_m)));
        } else {
          secure_unsigned_integer_m = SecureUnsignedInteger(
              share_->Get()->GetBackend().ConstantBooleanGmwInput(ToInput<T>(vector_of_m)));
        }

        SecureUnsignedInteger secure_unsigned_integer_x_exponent_plus_m =
            secure_unsigned_integer_x_exponent + secure_unsigned_integer_m;

        std::vector<ShareWrapper> boolean_gmw_or_bmr_share_x_exponent_plus_m_vector =
            secure_unsigned_integer_x_exponent_plus_m.Get().Split();

        std::vector<ShareWrapper> boolean_gmw_or_bmr_share_x_mul_pow2_m_vector;
        boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.reserve(FLOATINGPOINT32_BITS);

        for (std::size_t i = 0; i < FLOATINGPOINT32_MANTISSA_BITS; i++) {
          boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
              floating_point_boolean_gmw_or_bmr_share_x_vector[i]);
        }

        for (std::size_t i = 0; i < FLOATINGPOINT32_EXPONENT_BITS; i++) {
          boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
              boolean_gmw_or_bmr_share_x_exponent_plus_m_vector[i]);
        }

        boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
            floating_point_boolean_gmw_or_bmr_share_x_vector.back());

        ShareWrapper boolean_gmw_or_bmr_share_x_mul_pow2_m =
            ShareWrapper::Concatenate(boolean_gmw_or_bmr_share_x_mul_pow2_m_vector);

        ShareWrapper result = boolean_gmw_or_bmr_share_x_equal_zero.Mux(
            this->Get(), boolean_gmw_or_bmr_share_x_mul_pow2_m);

        if constexpr (kDebug) {
          if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
            logger_->LogDebug(
                "Creating a Boolean multiplication with 2^m circuit for 32-bit flaoting-point in "
                "BMR");
          } else {
            logger_->LogDebug(
                "Creating a Boolean multiplication with 2^m circuit for 32-bit flaoting-point in "
                "GMW");
          }
        }

        return SecureFloatingPointCircuitABY(result);
      }

      // (bitlength == 64)
      else if (bitlength == 64) {
        using T = std::uint16_t;
        std::size_t T_size = sizeof(T) * 8;

        ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
            floating_point_boolean_gmw_or_bmr_share_x_vector[0] ^
            floating_point_boolean_gmw_or_bmr_share_x_vector[0];
        ShareWrapper boolean_gmw_or_bmr_share_x_equal_zero = this->EQZ();
        std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_x_exponent_vector(
            floating_point_boolean_gmw_or_bmr_share_x_vector.begin() + FLOATINGPOINT_MANTISSA_BITS,
            floating_point_boolean_gmw_or_bmr_share_x_vector.begin() + FLOATINGPOINT_MANTISSA_BITS +
                FLOATINGPOINT_EXPONENT_BITS);
        //   std::cout << "000" << std::endl;

        // compensate exponent of x with zero bits and convert it to a secure unsigned integer
        std::vector<ShareWrapper>
            floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector(T_size);

        for (std::size_t i = 0; i < T_size; i++) {
          floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector[i] =
              constant_boolean_gmw_or_bmr_share_zero;
        }
        for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; i++) {
          floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector[i] =
              floating_point_boolean_gmw_or_bmr_share_x_exponent_vector[i];
        }

        SecureUnsignedInteger secure_unsigned_integer_x_exponent =
            SecureUnsignedInteger(ShareWrapper::Concatenate(
                floating_point_boolean_gmw_or_bmr_share_x_exponent_compensation_vector));

        std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
        std::vector<T> vector_of_m(num_of_simd, T(m));

        SecureUnsignedInteger secure_unsigned_integer_m;
        if (share_->Get()->GetProtocol() == MpcProtocol::kBmr) {
          secure_unsigned_integer_m = SecureUnsignedInteger(
              share_->Get()->GetBackend().ConstantAsBmrInput(ToInput<T>(vector_of_m)));
        } else {
          secure_unsigned_integer_m = SecureUnsignedInteger(
              share_->Get()->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(vector_of_m)));
        }

        // SecureUnsignedInteger secure_unsigned_integer_m = SecureUnsignedInteger(
        //     share_->Get()->GetBackend().ConstantBooleanGmwInput(ToInput<T>(vector_of_m)));
        SecureUnsignedInteger secure_unsigned_integer_x_exponent_plus_m =
            secure_unsigned_integer_x_exponent + secure_unsigned_integer_m;

        //   std::cout << "111" << std::endl;
        std::vector<ShareWrapper> boolean_gmw_or_bmr_share_x_exponent_plus_m_vector =
            secure_unsigned_integer_x_exponent_plus_m.Get().Split();

        std::vector<ShareWrapper> boolean_gmw_or_bmr_share_x_mul_pow2_m_vector;
        boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.reserve(FLOATINGPOINT_BITS);

        for (std::size_t i = 0; i < FLOATINGPOINT_MANTISSA_BITS; i++) {
          boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
              floating_point_boolean_gmw_or_bmr_share_x_vector[i]);
        }

        for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; i++) {
          boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
              boolean_gmw_or_bmr_share_x_exponent_plus_m_vector[i]);
        }

        //   std::cout << "222" << std::endl;
        boolean_gmw_or_bmr_share_x_mul_pow2_m_vector.emplace_back(
            floating_point_boolean_gmw_or_bmr_share_x_vector.back());

        ShareWrapper boolean_gmw_or_bmr_share_x_mul_pow2_m =
            ShareWrapper::Concatenate(boolean_gmw_or_bmr_share_x_mul_pow2_m_vector);
        //   std::cout << "333" << std::endl;

        // TODO: test
        ShareWrapper result = boolean_gmw_or_bmr_share_x_equal_zero.Mux(
            this->Get(), boolean_gmw_or_bmr_share_x_mul_pow2_m);

        if constexpr (kDebug) {
          if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
            logger_->LogDebug(
                "Creating a Boolean multiplication with 2^m circuit for 64-bit flaoting-point in "
                "BMR");
          } else {
            logger_->LogDebug(
                "Creating a Boolean multiplication with 2^m circuit for 64-bit flaoting-point in "
                "GMW");
          }
        }

        return SecureFloatingPointCircuitABY(result);
      }

      else {
        throw std::runtime_error(fmt::format("Invalid floating-point format for MulPow2m()."));
      }
    }
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::DivPow2m(std::int64_t m) const {
  return MulPow2m(-m);
}

// TODO: test
SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::ClampB(double B) {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {
    const auto bitlength = share_->Get()->GetBitLength();
    if (bitlength != 64) {
      throw std::runtime_error(fmt::format("ClampB only supports 64-bit floating-point."));
    }

    if constexpr (kDebug) {
      if ((*share_)->GetProtocol() == MpcProtocol::kBmr) {
        logger_->LogDebug("Creating a Boolean clampB circuit for 64-bit floating-point in BMR");
      } else {
        logger_->LogDebug("Creating a Boolean clampB circuit for 64-bit floating-point in GMW");
      }
    }

    std::size_t num_of_simd = share_->Get()->GetNumberOfSimdValues();
    std::vector<double> B_vector(num_of_simd, B);

    ShareWrapper floating_point_constant_boolean_gmw_or_bmr_share_B;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr) {
      floating_point_constant_boolean_gmw_or_bmr_share_B =
          share_->Get()->GetBackend().ConstantAsBmrInput(ToInput<double, std::true_type>(B_vector));
    } else {
      floating_point_constant_boolean_gmw_or_bmr_share_B =
          share_->Get()->GetBackend().ConstantAsBooleanGmwInput(
              ToInput<double, std::true_type>(B_vector));
    }

    SecureFloatingPointCircuitABY floating_point_constant_B =
        SecureFloatingPointCircuitABY(floating_point_constant_boolean_gmw_or_bmr_share_B);

    ShareWrapper floating_point_boolean_gmw_or_bmr_share_x = this->Get();

    std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_x_vector =
        floating_point_boolean_gmw_or_bmr_share_x.Split();

    std::size_t floating_point_boolean_gmw_or_bmr_share_x_vector_size =
        floating_point_boolean_gmw_or_bmr_share_x_vector.size();

    ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
        floating_point_boolean_gmw_or_bmr_share_x_vector[0] ^
        floating_point_boolean_gmw_or_bmr_share_x_vector[0];

    std::vector<ShareWrapper> floating_point_boolean_gmw_or_bmr_share_x_abs_vector(
        floating_point_boolean_gmw_or_bmr_share_x_vector_size);

    for (std::size_t i = 0; i < floating_point_boolean_gmw_or_bmr_share_x_vector_size - 1; i++) {
      floating_point_boolean_gmw_or_bmr_share_x_abs_vector[i] =
          floating_point_boolean_gmw_or_bmr_share_x_vector[i];
    }

    // set the sign to 0 (positive)
    floating_point_boolean_gmw_or_bmr_share_x_abs_vector
        [floating_point_boolean_gmw_or_bmr_share_x_vector_size - 1] =
            constant_boolean_gmw_or_bmr_share_zero;

    ShareWrapper floating_point_boolean_gmw_or_bmr_share_x_abs =
        ShareWrapper::Concatenate(floating_point_boolean_gmw_or_bmr_share_x_abs_vector);

    SecureFloatingPointCircuitABY floating_point_x_abs =
        SecureFloatingPointCircuitABY(floating_point_boolean_gmw_or_bmr_share_x_abs);

    //   SecureFloatingPointCircuitABY floating_point_constant_B =
    //       SecureFloatingPointCircuitABY(floating_point_constant_boolean_gmw_or_bmr_share_B);

    ShareWrapper boolean_gmw_or_bmr_share_abs_x_greater_than_B =
        floating_point_x_abs > floating_point_constant_B;

    ShareWrapper floating_point_abs_result = boolean_gmw_or_bmr_share_abs_x_greater_than_B.Mux(
        floating_point_constant_boolean_gmw_or_bmr_share_B,
        floating_point_boolean_gmw_or_bmr_share_x);

    std::vector<ShareWrapper> floating_point_result_abs_vector = floating_point_abs_result.Split();

    std::vector<ShareWrapper> floating_point_result_vector(
        floating_point_boolean_gmw_or_bmr_share_x_vector_size);
    for (std::size_t i = 0; i < floating_point_boolean_gmw_or_bmr_share_x_vector_size - 1; i++) {
      floating_point_result_vector[i] = floating_point_result_abs_vector[i];
    }
    // set the result sign same as x
    floating_point_result_vector[floating_point_boolean_gmw_or_bmr_share_x_vector_size - 1] =
        floating_point_boolean_gmw_or_bmr_share_x_vector
            [floating_point_boolean_gmw_or_bmr_share_x_vector_size - 1];

    return ShareWrapper::Concatenate(floating_point_result_vector);
  }
}

// TODO: maybe generate circuit for 32-bit floating point
SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::RoundToNearestInteger() {
  if (share_->Get()->GetCircuitType() != CircuitType::kBoolean) {
    throw std::runtime_error(
        "Floating-point operations are not supported for Arithmetic GMW shares");
  } else {  // BooleanCircuitType

    const auto bitlength = share_->Get()->GetBitLength();
    assert(bitlength == 32);

    std::shared_ptr<AlgorithmDescription> round_to_nearest_integer_algorithm;
    std::string path;

    if (share_->Get()->GetProtocol() == MpcProtocol::kBmr)  // BMR, use size-optimized circuit
      path =
          ConstructPath(FloatingPointOperationType::kRoundToNearestInt_circuit, bitlength, "_size");
    else  // GMW, use depth-optimized circuit
      path = ConstructPath(FloatingPointOperationType::kRoundToNearestInt_circuit, bitlength,
                           "_depth");
    if ((round_to_nearest_integer_algorithm =
             share_->Get()->GetRegister()->GetCachedAlgorithmDescription(path))) {
      if constexpr (kDebug) {
        logger_->LogDebug(
            fmt::format("Found in cache Boolean floating-point round to nearest integer circuit "
                        "with file path {}",
                        path));
      }
    } else {
      round_to_nearest_integer_algorithm =
          std::make_shared<AlgorithmDescription>(AlgorithmDescription::FromBristol(path));
      assert(round_to_nearest_integer_algorithm);
      if constexpr (kDebug) {
        logger_->LogDebug(fmt::format(
            "Read Boolean floating-point round to nearest integer circuit from file {}", path));
      }
    }

    ShareWrapper constant_boolean_gmw_or_bmr_share_zero = (*share_) ^ (*share_);

    // the circuit mask the result with the second input as Bristol can't directly connect input
    // with output, we mask the result with 0
    const auto share_input{
        ShareWrapper::Concatenate(std::vector{*share_, constant_boolean_gmw_or_bmr_share_zero})};
    return SecureFloatingPointCircuitABY(share_input.Evaluate(round_to_nearest_integer_algorithm));
  }
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator+(
    const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant;
  floating_point_constant = share_->CreateConstantBooleanGmwOrBmrInput(constant_value);
  return *this + floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator-(
    const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this - floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator*(
    const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this * floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator/(
    const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this / floating_point_constant;
}

ShareWrapper SecureFloatingPointCircuitABY::operator<(const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this < floating_point_constant;
}

ShareWrapper SecureFloatingPointCircuitABY::operator>(const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this > floating_point_constant;
}
ShareWrapper SecureFloatingPointCircuitABY::operator==(const float& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this == floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator+(
    const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant;
  floating_point_constant = share_->CreateConstantBooleanGmwOrBmrInput(constant_value);
  return *this + floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator-(
    const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this - floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator*(
    const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this * floating_point_constant;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::operator/(
    const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this / floating_point_constant;
}

ShareWrapper SecureFloatingPointCircuitABY::operator<(const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this < floating_point_constant;
}

ShareWrapper SecureFloatingPointCircuitABY::operator>(const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this > floating_point_constant;
}
ShareWrapper SecureFloatingPointCircuitABY::operator==(const double& constant_value) const {
  SecureFloatingPointCircuitABY floating_point_constant =
      share_->CreateConstantBooleanGmwOrBmrInput(constant_value);

  return *this == floating_point_constant;
}

SecureFloatingPointCircuitABY
SecureFloatingPointCircuitABY::ConvertSinglePrecisionToDoublePrecision() const {
  using T = std::uint16_t;
  std::size_t T_size = sizeof(T) * 8;

  std::vector<ShareWrapper> single_precision_floating_point_bits_vector = share_->Split();

  std::vector<ShareWrapper> single_precision_floating_point_mantissa_bit_vector(
      single_precision_floating_point_bits_vector.begin(),
      single_precision_floating_point_bits_vector.begin() + FLOATINGPOINT32_MANTISSA_BITS);

  std::vector<ShareWrapper> single_precision_floating_point_exponent_bit_vector(
      single_precision_floating_point_bits_vector.begin() + FLOATINGPOINT32_MANTISSA_BITS,
      single_precision_floating_point_bits_vector.begin() + FLOATINGPOINT32_MANTISSA_BITS +
          FLOATINGPOINT32_EXPONENT_BITS);

  ShareWrapper single_precision_floating_point_sign_bit =
      single_precision_floating_point_bits_vector.back();

  ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
      single_precision_floating_point_sign_bit ^ single_precision_floating_point_sign_bit;

  // std::cout << "111" << std::endl;

  // extend the single-precision floating point to the double-precision floating point
  std::vector<ShareWrapper> double_precision_floating_point_bits_vector(FLOATINGPOINT_BITS);

  // fill the mantissa bits of 64-bit floating point
  for (std::size_t i = 0; i < FLOATINGPOINT_MANTISSA_BITS - FLOATINGPOINT32_MANTISSA_BITS; ++i) {
    double_precision_floating_point_bits_vector[i] = constant_boolean_gmw_or_bmr_share_zero;
  }
  for (std::size_t i = FLOATINGPOINT_MANTISSA_BITS - FLOATINGPOINT32_MANTISSA_BITS;
       i < FLOATINGPOINT_MANTISSA_BITS; ++i) {
    double_precision_floating_point_bits_vector[i] =
        single_precision_floating_point_bits_vector[i - (FLOATINGPOINT_MANTISSA_BITS -
                                                         FLOATINGPOINT32_MANTISSA_BITS)];
  }

  // std::cout << "222" << std::endl;

  // extend the exponent bits to 64-bit floating point
  std::vector<ShareWrapper> double_precision_floating_point_exponent_bit_vector(T_size);
  for (std::size_t i = 0; i < T_size; ++i) {
    double_precision_floating_point_exponent_bit_vector[i] = constant_boolean_gmw_or_bmr_share_zero;
  }
  for (std::size_t i = 0; i < FLOATINGPOINT32_EXPONENT_BITS; ++i) {
    double_precision_floating_point_exponent_bit_vector[i] =
        single_precision_floating_point_exponent_bit_vector[i];
  }
  // std::cout << "333" << std::endl;
  SecureUnsignedInteger unsigned_integer_double_precision_floating_point_exponent(
      ShareWrapper::Concatenate(double_precision_floating_point_exponent_bit_vector));
  // std::cout << "444" << std::endl;

  // compute the biased exponent of the double precision floating point
  SecureUnsignedInteger unsigned_integer_double_precision_floating_point_biased_exponent =
      unsigned_integer_double_precision_floating_point_exponent +
      T(T(FLOATINGPOINT_EXPONENT_BIAS) - T(FLOATINGPOINT32_EXPONENT_BIAS));

  // std::cout << "555" << std::endl;

  std::vector<ShareWrapper>
      unsigned_integer_double_precision_floating_point_biased_exponent_vector =
          unsigned_integer_double_precision_floating_point_biased_exponent.Get().Split();
  std::vector<ShareWrapper> double_precision_floating_point_biased_exponent_bit_vector(
      unsigned_integer_double_precision_floating_point_biased_exponent_vector.begin(),
      unsigned_integer_double_precision_floating_point_biased_exponent_vector.begin() +
          FLOATINGPOINT_EXPONENT_BITS);
  for (std::size_t i = FLOATINGPOINT_MANTISSA_BITS;
       i < FLOATINGPOINT_MANTISSA_BITS + FLOATINGPOINT_EXPONENT_BITS; ++i) {
    double_precision_floating_point_bits_vector[i] =
        double_precision_floating_point_biased_exponent_bit_vector[i - FLOATINGPOINT_MANTISSA_BITS];
  }
  double_precision_floating_point_bits_vector.back() = single_precision_floating_point_sign_bit;
  // std::cout << "666" << std::endl;
  return ShareWrapper::Concatenate(double_precision_floating_point_bits_vector);
}

SecureFloatingPointCircuitABY
SecureFloatingPointCircuitABY::ConvertDoublePrecisionToSinglePrecision() const {
  using T = std::uint16_t;
  std::size_t T_size = sizeof(T) * 8;

  std::vector<ShareWrapper> double_precision_floating_point_bits_vector = share_->Split();

  std::vector<ShareWrapper> double_precision_floating_point_mantissa_bit_vector(
      double_precision_floating_point_bits_vector.begin(),
      double_precision_floating_point_bits_vector.begin() + FLOATINGPOINT_MANTISSA_BITS);

  std::vector<ShareWrapper> double_precision_floating_point_exponent_bit_vector(
      double_precision_floating_point_bits_vector.begin() + FLOATINGPOINT_MANTISSA_BITS,
      double_precision_floating_point_bits_vector.begin() + FLOATINGPOINT_MANTISSA_BITS +
          FLOATINGPOINT_EXPONENT_BITS);

  ShareWrapper double_precision_floating_point_sign_bit =
      double_precision_floating_point_bits_vector.back();

  // std::cout << "000" << std::endl;
  ShareWrapper constant_boolean_gmw_or_bmr_share_zero =
      double_precision_floating_point_sign_bit ^ double_precision_floating_point_sign_bit;

  // std::cout << "111" << std::endl;

  // truncate the double-precision floating point to the single-precision floating point
  std::vector<ShareWrapper> single_precision_floating_point_bits_vector(FLOATINGPOINT32_BITS);

  // fill the mantissa bits of 32-bit floating point
  for (std::size_t i = 0; i < FLOATINGPOINT32_MANTISSA_BITS; ++i) {
    single_precision_floating_point_bits_vector[i] =
        double_precision_floating_point_bits_vector[i + (FLOATINGPOINT_MANTISSA_BITS -
                                                         FLOATINGPOINT32_MANTISSA_BITS)];
  }

  // std::cout << "222" << std::endl;

  // truncate the exponent bits to 32-bit floating point
  std::vector<ShareWrapper> single_precision_floating_point_exponent_bit_vector(T_size);
  for (std::size_t i = 0; i < T_size; ++i) {
    single_precision_floating_point_exponent_bit_vector[i] = constant_boolean_gmw_or_bmr_share_zero;
  }
  for (std::size_t i = 0; i < FLOATINGPOINT_EXPONENT_BITS; ++i) {
    single_precision_floating_point_exponent_bit_vector[i] =
        double_precision_floating_point_exponent_bit_vector[i];
  }
  // std::cout << "333" << std::endl;
  SecureUnsignedInteger unsigned_integer_single_precision_floating_point_exponent(
      ShareWrapper::Concatenate(single_precision_floating_point_exponent_bit_vector));
  // std::cout << "444" << std::endl;

  // TODO: operation with constant supoprt bmr protocol
  // compute the biased exponent of the double precision floating point
  SecureUnsignedInteger unsigned_integer_single_precision_floating_point_biased_exponent =
      unsigned_integer_single_precision_floating_point_exponent +
      T(T(FLOATINGPOINT32_EXPONENT_BIAS) - T(FLOATINGPOINT_EXPONENT_BIAS));

  // std::cout << "555" << std::endl;

  std::vector<ShareWrapper>
      unsigned_integer_single_precision_floating_point_biased_exponent_vector =
          unsigned_integer_single_precision_floating_point_biased_exponent.Get().Split();
  std::vector<ShareWrapper> single_precision_floating_point_biased_exponent_bit_vector(
      unsigned_integer_single_precision_floating_point_biased_exponent_vector.begin(),
      unsigned_integer_single_precision_floating_point_biased_exponent_vector.begin() +
          FLOATINGPOINT32_EXPONENT_BITS);

  for (std::size_t i = FLOATINGPOINT32_MANTISSA_BITS;
       i < FLOATINGPOINT32_MANTISSA_BITS + FLOATINGPOINT32_EXPONENT_BITS; ++i) {
    single_precision_floating_point_bits_vector[i] =
        single_precision_floating_point_biased_exponent_bit_vector[i -
                                                                   FLOATINGPOINT32_MANTISSA_BITS];
  }
  single_precision_floating_point_bits_vector.back() = double_precision_floating_point_sign_bit;
  // std::cout << "666" << std::endl;
  return ShareWrapper::Concatenate(single_precision_floating_point_bits_vector);
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::MulBooleanGmwBit(
    const ShareWrapper& boolean_gmw_share_other) const {
  assert(boolean_gmw_share_other->GetProtocol() == MpcProtocol::kBooleanGmw);
  assert(boolean_gmw_share_other->GetWires().size() == 1);

  SecureFloatingPointCircuitABY result = boolean_gmw_share_other.XCOTMul(*share_);
  return result;
}

// suffix is ignored, BMR and GMW are using the same circuit
std::string SecureFloatingPointCircuitABY::ConstructPath(
    const FloatingPointOperationType type, const std::size_t bitlength, std::string suffix,
    const std::size_t integer_bit_length) const {
  std::string operation_type_string;
  std::string circuit_source = "ABY";
  std::string suffix_tmp = "";

  switch (type) {
    case FloatingPointOperationType::kAdd_circuit: {
      operation_type_string = "add";
      break;
    }
    case FloatingPointOperationType::kSub_circuit: {
      operation_type_string = "sub";
      break;
    }
    case FloatingPointOperationType::kMul_circuit: {
      operation_type_string = "mult";
      break;
    }
    case FloatingPointOperationType::kDiv_circuit: {
      operation_type_string = "div";
      break;
    }
    case FloatingPointOperationType::kLt_circuit: {
      operation_type_string = "cmp";
      break;
    }
    case FloatingPointOperationType::kGt_circuit: {
      operation_type_string = "cmp";
      break;
    }
    // case FloatingPointOperationType::kEq_circuit: {
    //   operation_type_string = "eq";
    //   break;
    // }
    case FloatingPointOperationType::kExp2_circuit: {
      operation_type_string = "exp2";
      break;
    }
    case FloatingPointOperationType::kLog2_circuit: {
      operation_type_string = "log2";
      break;
    }
    case FloatingPointOperationType::kExp_circuit: {
      operation_type_string = "exp";
      break;
    }
    case FloatingPointOperationType::kLn_circuit: {
      operation_type_string = "ln";
      break;
    }
    case FloatingPointOperationType::kSqr_circuit: {
      operation_type_string = "sqr";
      break;
    }
    case FloatingPointOperationType::kSqrt_circuit: {
      operation_type_string = "sqrt";
      break;
    }
    case FloatingPointOperationType::kSin_circuit: {
      operation_type_string = "sin";
      break;
    }
    case FloatingPointOperationType::kCos_circuit: {
      operation_type_string = "cos";
      break;
    }
    case FloatingPointOperationType::kCeil_circuit: {
      operation_type_string = "ceil";
      circuit_source = "CBMC";
      suffix_tmp = suffix;
      break;
    }

    case FloatingPointOperationType::kFloor_circuit: {
      operation_type_string = "floor";
      circuit_source = "CBMC";
      suffix_tmp = suffix;
      break;
    }
    case FloatingPointOperationType::kFL2Int_circuit: {
      operation_type_string = "to_int" + std::to_string(integer_bit_length);
      circuit_source = "CBMC";
      suffix_tmp = suffix;
      break;
    }

    case FloatingPointOperationType::kRoundToNearestInt_circuit: {
      operation_type_string = "round_to_nearest_integer";
      circuit_source = "CBMC";
      suffix_tmp = suffix;
      break;
    }
      //  case FloatingPointOperationType::kFL2Fx_circuit: {
      //      operation_type_string = "FL2Fx";
      //      break;
      //  }

    default:
      throw std::runtime_error(fmt::format("Invalid floating-point operation required: {}", type));
  }

  return fmt::format("{}/circuits/floating_point_ABY/float{}_{}{}_{}.bristol", kRootDir, bitlength,
                     operation_type_string, suffix_tmp, circuit_source);
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Simdify(
    std::span<SecureFloatingPointCircuitABY> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureFloatingPointCircuitABY& i) -> SharePointer { return i.Get().Get(); });
  return SecureFloatingPointCircuitABY(ShareWrapper::Simdify(input_as_shares));
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Simdify(
    std::vector<SecureFloatingPointCircuitABY>&& input) {
  return Simdify(input);
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Subset(
    std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureFloatingPointCircuitABY(unwrap.Subset(positions));
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Subset(
    std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

std::vector<SecureFloatingPointCircuitABY> SecureFloatingPointCircuitABY::Unsimdify() const {
  auto unsimdify_gate = std::make_shared<UnsimdifyGate>(share_->Get());
  auto unsimdify_gate_cast = std::static_pointer_cast<Gate>(unsimdify_gate);
  share_->Get()->GetRegister()->RegisterNextGate(unsimdify_gate_cast);
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<SecureFloatingPointCircuitABY> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return SecureFloatingPointCircuitABY(share); });
  return result;
}

SecureFloatingPointCircuitABY SecureFloatingPointCircuitABY::Out(std::size_t output_owner) const {
  return SecureFloatingPointCircuitABY(share_->Out(output_owner));
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template <typename T>
T SecureFloatingPointCircuitABY::As() const {
  if (share_->Get()->GetProtocol() == MpcProtocol::kArithmeticGmw)
    return share_->As<T>();
  else if (share_->Get()->GetProtocol() == MpcProtocol::kBooleanGmw ||
           share_->Get()->GetProtocol() == MpcProtocol::kBooleanConstant ||
           share_->Get()->GetProtocol() == MpcProtocol::kBooleanMix ||
           share_->Get()->GetProtocol() == MpcProtocol::kBmr) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    if constexpr (std::is_unsigned<T>()) {
      return encrypto::motion::ToOutput<T>(share_out);
    } else {
      throw std::invalid_argument(fmt::format(
          "Unsupported output type in SecureFloatingPointCircuitABY::As<{}>() for {} Protocol",
          typeid(T).name(), share_->Get()->GetProtocol()));
    }
  }

  // TODO:: add kBooleanConstant

  else {
    throw std::invalid_argument("Unsupported protocol for SecureFloatingPointCircuitABY::As()");
  }
}

template <typename FLType>
FLType SecureFloatingPointCircuitABY::AsFloatingPoint() const {
  if constexpr (std::is_same<FLType, float>()) {
    std::uint32_t as_unsigned_output = As<std::uint32_t>();

    FLType as_float_output;
    as_float_output = reinterpret_cast<float&>(as_unsigned_output);

    return as_float_output;
  } else if constexpr (std::is_same<FLType, double>()) {
    std::uint64_t as_unsigned_output = As<std::uint64_t>();

    // std::cout << "as_unsigned_output: " << as_unsigned_output << std::endl;

    FLType as_double_output;
    as_double_output = reinterpret_cast<double&>(as_unsigned_output);
    // std::cout << "as_double_output: " << as_double_output << std::endl;
    return as_double_output;
  } else {
    throw std::invalid_argument(
        fmt::format("Unsupported output type in "
                    "SecureFloatingPointCircuitABY::AsFloatingPoint<{}>() for {} Protocol",
                    typeid(FLType).name(), share_->Get()->GetProtocol()));
  }
}

template <typename FLType, typename A>
vector<FLType, A> SecureFloatingPointCircuitABY::AsFloatingPointVector() const {
  if constexpr (std::is_same<FLType, float>()) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    std::vector<std::uint32_t> as_unsigned_output_vector =
        encrypto::motion::ToVectorOutput<std::uint32_t>(share_out);

    vector<FLType, A> as_float_output_vector;
    for (std::size_t i = 0; i < as_unsigned_output_vector.size(); i++) {
      as_float_output_vector.emplace_back(reinterpret_cast<float&>(as_unsigned_output_vector[i]));
    }
    return as_float_output_vector;
  } else if constexpr (std::is_same<FLType, double>()) {
    auto share_out = share_->As<std::vector<encrypto::motion::BitVector<>>>();
    std::vector<std::uint64_t> as_unsigned_output_vector =
        encrypto::motion::ToVectorOutput<std::uint64_t>(share_out);

    vector<FLType, A> as_double_output_vector;
    for (std::size_t i = 0; i < as_unsigned_output_vector.size(); i++) {
      as_double_output_vector.emplace_back(reinterpret_cast<double&>(as_unsigned_output_vector[i]));
    }
    return as_double_output_vector;
    ;
  } else {
    throw std::invalid_argument(fmt::format(
        "Unsupported output type in SecureFloatingPointCircuitABY::As<{}>() for {} Protocol",
        typeid(FLType).name(), share_->Get()->GetProtocol()));
  }
  return vector<FLType, A>();
}

template std::uint32_t SecureFloatingPointCircuitABY::As() const;

template std::uint64_t SecureFloatingPointCircuitABY::As() const;

template std::vector<std::uint32_t> SecureFloatingPointCircuitABY::As() const;

template std::vector<std::uint64_t> SecureFloatingPointCircuitABY::As() const;

template float SecureFloatingPointCircuitABY::AsFloatingPoint() const;

template double SecureFloatingPointCircuitABY::AsFloatingPoint() const;

template std::vector<float> SecureFloatingPointCircuitABY::AsFloatingPointVector() const;

template std::vector<double> SecureFloatingPointCircuitABY::AsFloatingPointVector() const;

}  // namespace encrypto::motion
