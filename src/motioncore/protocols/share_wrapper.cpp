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

#include "share_wrapper.h"

#include <cassert>
#include <stdexcept>
#include <typeinfo>

#include "algorithm/algorithm_description.h"
#include "algorithm/boolean_algorithms.h"
#include "algorithm/low_depth_reduce.h"
#include "base/backend.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_gate.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/astra/astra_gate.h"
#include "protocols/astra/astra_share.h"
#include "protocols/astra/astra_wire.h"
#include "protocols/bmr/bmr_gate.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/constant/constant_gate.h"
#include "protocols/constant/constant_share.h"
#include "protocols/constant/constant_wire.h"
#include "protocols/conversion/b2a_gate.h"
#include "protocols/conversion/conversion_gate.h"
#include "protocols/data_management/simdify_gate.h"
#include "protocols/data_management/subset_gate.h"
#include "protocols/data_management/unsimdify_gate.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "secure_type/secure_fixed_point_circuit_CBMC.h"
#include "secure_type/secure_floating_point_circuit_ABY.h"
#include "secure_type/secure_signed_integer.h"
#include "secure_type/secure_unsigned_integer.h"
#include "share.h"
#include "utility/bit_vector.h"

namespace encrypto::motion {

using SharePointer = std::shared_ptr<Share>;

ShareWrapper ShareWrapper::operator~() const {
  assert(share_);
  if (share_->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for arithmetic circuits");
  }

  switch (share_->GetProtocol()) {
    case MpcProtocol::kBmr: {
      auto bmr_share = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
      assert(bmr_share);
      auto inv_gate =
          share_->GetBackend().GetRegister()->EmplaceGate<proto::bmr::InvGate>(bmr_share);
      return ShareWrapper(inv_gate->GetOutputAsShare());
    }
    case MpcProtocol::kBooleanGmw: {
      auto gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
      assert(gmw_share);
      auto inv_gate =
          share_->GetBackend().GetRegister()->EmplaceGate<proto::boolean_gmw::InvGate>(gmw_share);
      return ShareWrapper(inv_gate->GetOutputAsShare());
    }
    case MpcProtocol::kGarbledCircuit: {
      auto inv_gate = share_->GetBackend().GetGarbledCircuitProvider().MakeInvGate(share_);
      return ShareWrapper(inv_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(
          fmt::format("Unknown protocol for constructing an INV gate with id {}",
                      static_cast<std::size_t>(share_->GetProtocol())));
  }
}

ShareWrapper ShareWrapper::operator^(const ShareWrapper& other) const {
  assert(share_);
  assert(*other);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for arithmetic circuits");
  }

  switch (share_->GetProtocol()) {
    case MpcProtocol::kBmr: {
      auto this_b = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
      auto other_b = std::dynamic_pointer_cast<proto::bmr::Share>(*other);

      auto xor_gate =
          share_->GetBackend().GetRegister()->EmplaceGate<proto::bmr::XorGate>(this_b, other_b);
      return ShareWrapper(xor_gate->GetOutputAsShare());
    }
    case MpcProtocol::kBooleanGmw: {
      auto this_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
      auto other_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

      assert(this_b);
      assert(other_b);

      auto xor_gate = share_->GetBackend().GetRegister()->EmplaceGate<proto::boolean_gmw::XorGate>(
          this_b, other_b);
      return ShareWrapper(xor_gate->GetOutputAsShare());
    }
    case MpcProtocol::kGarbledCircuit: {
      auto xor_gate = share_->GetBackend().GetGarbledCircuitProvider().MakeXorGate(share_, *other);
      return ShareWrapper(xor_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(
          fmt::format("Unknown protocol for constructing an XOR gate with id {}",
                      static_cast<std::size_t>(share_->GetProtocol())));
  }
}

ShareWrapper ShareWrapper::operator&(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for arithmetic circuits");
  }

  switch (share_->GetProtocol()) {
    case MpcProtocol::kBmr: {
      auto this_b = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
      auto other_b = std::dynamic_pointer_cast<proto::bmr::Share>(*other);

      auto and_gate =
          share_->GetBackend().GetRegister()->EmplaceGate<proto::bmr::AndGate>(this_b, other_b);
      return ShareWrapper(and_gate->GetOutputAsShare());
    }
    case MpcProtocol::kBooleanGmw: {
      auto this_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
      auto other_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

      auto and_gate = share_->GetBackend().GetRegister()->EmplaceGate<proto::boolean_gmw::AndGate>(
          this_b, other_b);
      return ShareWrapper(and_gate->GetOutputAsShare());
    }
    case MpcProtocol::kGarbledCircuit: {
      auto and_gate = share_->GetBackend().GetGarbledCircuitProvider().MakeAndGate(share_, *other);
      return ShareWrapper(and_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(
          fmt::format("Unknown protocol for constructing an AND gate with id {}",
                      static_cast<std::size_t>(share_->GetProtocol())));
  }
}

ShareWrapper ShareWrapper::operator|(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetCircuitType() == CircuitType::kArithmetic) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for arithmetic circuits");
  }

  // OR operatinos is equal to NOT ( ( NOT a ) AND ( NOT b ) )
  return ~((~*this) & ~other);
}

ShareWrapper ShareWrapper::operator+(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());

  // std::cout << "ShareWrapper::operator+" << std::endl;

  // std::cout << "share_->GetProtocol() == MpcProtocol::kArithmeticConstant: "
  //           << (share_->GetProtocol() == MpcProtocol::kArithmeticConstant) << std::endl;
  // std::cout << "other->GetProtocol() == MpcProtocol::kArithmeticConstant: "
  //           << (other->GetProtocol() == MpcProtocol::kArithmeticConstant) << std::endl;

  // modified by Liang Zhao
  if ((share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra)

      // added by Liang Zhao
      && (share_->GetProtocol() != MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() != MpcProtocol::kArithmeticConstant)) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW and Astra shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Add<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Add<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Add<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Add<std::uint64_t>(share_, *other);
  }

  // added by Liang Zhao
  else if (share_->GetBitLength() == 128u) {
    return Add<__uint128_t>(share_, *other);
  }

  else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator-(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if ((share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra)

      // added by Liang Zhao
      && (share_->GetProtocol() != MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() != MpcProtocol::kArithmeticConstant)) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW and Astra shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Sub<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Sub<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Sub<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Sub<std::uint64_t>(share_, *other);
  }

  // added by Liang Zhao
  else if (share_->GetBitLength() == 128u) {
    // std::cout << "share_->GetBitLength(): " << share_->GetBitLength() << std::endl;
    return Sub<__uint128_t>(share_, *other);
  }

  else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator*(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetNumberOfSimdValues() == other->GetNumberOfSimdValues());

  bool lhs_is_arith = share_->GetCircuitType() == CircuitType::kArithmetic;
  bool rhs_is_arith = other->GetCircuitType() == CircuitType::kArithmetic;
  bool lhs_is_bool = share_->GetCircuitType() == CircuitType::kBoolean;
  bool rhs_is_bool = other->GetCircuitType() == CircuitType::kBoolean;

  if (!lhs_is_arith || !rhs_is_arith) {
    if (lhs_is_bool && rhs_is_arith) {
      if (other->GetBitLength() == 8u) {
        return HybridMul<std::uint8_t>(share_, *other);
      } else if (other->GetBitLength() == 16u) {
        return HybridMul<std::uint16_t>(share_, *other);
      } else if (other->GetBitLength() == 32u) {
        return HybridMul<std::uint32_t>(share_, *other);
      } else if (other->GetBitLength() == 64u) {
        return HybridMul<std::uint64_t>(share_, *other);
      }

      // added by Liang Zhao
      else if (other->GetBitLength() == 128u) {
        return HybridMul<__uint128_t>(share_, *other);
      }

      else {
        throw std::bad_cast();
      }
    } else if (lhs_is_arith && rhs_is_bool) {
      return other * *this;
    } else {
      throw std::runtime_error(
          "Arithmetic primitive operations are only supported for arithmetic shares");
    }
  }

  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());

  assert(share_->GetNumberOfSimdValues() == other->GetNumberOfSimdValues());
  if ((share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
       share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra)

      // added by Liang Zhao
      && (other->GetProtocol() != MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() != MpcProtocol::kArithmeticConstant)

  ) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW and Astra shares");
  }

  if (share_ == other.share_) {  // squaring
    if (share_->GetBitLength() == 8u) {
      return Square<std::uint8_t>(share_);
    } else if (share_->GetBitLength() == 16u) {
      return Square<std::uint16_t>(share_);
    } else if (share_->GetBitLength() == 32u) {
      return Square<std::uint32_t>(share_);
    } else if (share_->GetBitLength() == 64u) {
      return Square<std::uint64_t>(share_);
    }

    // added by Liang Zhao
    else if (share_->GetBitLength() == 128u) {
      return Square<__uint128_t>(share_);
    } else {
      throw std::bad_cast();
    }
  } else {
    if (share_->GetBitLength() == 8u) {
      return Mul<std::uint8_t>(share_, *other);
    } else if (share_->GetBitLength() == 16u) {
      return Mul<std::uint16_t>(share_, *other);
    } else if (share_->GetBitLength() == 32u) {
      return Mul<std::uint32_t>(share_, *other);
    } else if (share_->GetBitLength() == 64u) {
      return Mul<std::uint64_t>(share_, *other);
    }

    // added by Liang Zhao
    else if (share_->GetBitLength() == 128u) {
      return Mul<__uint128_t>(share_, *other);
    } else {
      throw std::bad_cast();
    }
  }
}

ShareWrapper ShareWrapper::operator==(const ShareWrapper& other) const {
  if (other->GetBitLength() != share_->GetBitLength()) {
    share_->GetBackend().GetLogger()->LogError(
        fmt::format("Comparing shared bit strings of different bit lengths: this {} bits vs other "
                    "share's {} bits",
                    share_->GetBitLength(), other->GetBitLength()));
  } else if (other->GetBitLength() == 0) {
    share_->GetBackend().GetLogger()->LogError(
        "Comparing shared bit strings of bit length 0 is not allowed");
  }

  auto result = ~(*this ^ other);  // XNOR
  const auto bitlength = result->GetBitLength();

  if (bitlength == 1) {
    return result;
  } else if (IsPowerOfTwo(bitlength)) {
    return LowDepthReduce(result.Split(), std::bit_and<>());
  } else {  // bitlength is not a power of 2
    while (result->GetBitLength() != 1) {
      std::queue<ShareWrapper> q;
      std::vector<ShareWrapper> output;
      std::size_t offset{0};
      const auto inner_bitlength{result->GetBitLength()};
      output.reserve(std::ceil(std::log2(inner_bitlength)));
      const auto split = result.Split();
      for (auto i = 1ull; i <= inner_bitlength; i *= 2) {
        if ((inner_bitlength & i) == i) {
          const auto _begin = split.begin() + offset;
          const auto _end = split.begin() + offset + i;
          q.push(ShareWrapper::Concatenate(_begin, _end));
          offset += i;
        }
      }
      while (!q.empty()) {
        output.emplace_back(LowDepthReduce(q.front().Split(), std::bit_and<>()));
        q.pop();
      }
      result = ShareWrapper::Concatenate(output);
    }
    return result;
  }
}

ShareWrapper ShareWrapper::operator>(const ShareWrapper& other) const {
  if (other->GetBitLength() != share_->GetBitLength()) {
    share_->GetBackend().GetLogger()->LogError(
        fmt::format("Comparing shares of different bit lengths: this {} bits vs other "
                    "share's {} bits",
                    share_->GetBitLength(), other->GetBitLength()));
  } else if (other->GetBitLength() == 0) {
    share_->GetBackend().GetLogger()->LogError("Comparing shares of bit length 0 is not allowed");
  }

  assert(*other);
  assert(share_);
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw ||
      other->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error("GreaterThan operation is only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    return GreaterThan<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return GreaterThan<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return GreaterThan<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return GreaterThan<std::uint64_t>(share_, *other);
  }

  // added by Liang Zhao
  else if (share_->GetBitLength() == 128u) {
    return GreaterThan<__uint128_t>(share_, *other);
  }

  else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::Mux(const ShareWrapper& a, const ShareWrapper& b) const {
  assert(*a);
  assert(*b);
  assert(share_);
  assert(share_->GetProtocol() == a->GetProtocol());
  assert(share_->GetProtocol() == b->GetProtocol());
  assert(a->GetBitLength() == b->GetBitLength());
  assert(share_->GetBitLength() == 1);

  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    // TODO implement
    throw std::runtime_error("C-OT-based Mux for Arithmetic GMW shares is not implemented yet");
  }

  else if (share_->GetProtocol() == MpcProtocol::kBooleanGmw &&
           a->GetProtocol() == MpcProtocol::kBooleanGmw &&
           b->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto this_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    auto a_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*a);
    auto b_gmw = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*b);

    assert(this_gmw);
    assert(a_gmw);
    assert(b_gmw);

    auto mux_gate =
        share_->GetRegister()->EmplaceGate<proto::boolean_gmw::MuxGate>(a_gmw, b_gmw, this_gmw);
    return ShareWrapper(mux_gate->GetOutputAsShare());
  } else {
    // s ? a : b
    // result <- b ^ (s * (a ^ b))

    auto a_xor_b = a ^ b;

    auto mask =
        ShareWrapper::Concatenate(std::vector<ShareWrapper>(a_xor_b->GetBitLength(), *this));
    mask &= a_xor_b;
    return b ^ mask;
  }
}

// added by Liang Zhao
// a (share_): bit
// b: vector of bits
ShareWrapper ShareWrapper::XCOTMul(const ShareWrapper& b) const {
  assert(share_);
  assert(*b);
  assert(share_->GetProtocol() == b->GetProtocol());
  assert(share_->GetBitLength() == 1);
  assert(b->GetBitLength() > 0);

  // use COT if both shares are Boolean GMW
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw &&
      b->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto a_boolean_gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
    auto b_boolean_gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*b);

    assert(a_boolean_gmw_share);
    assert(b_boolean_gmw_share);

    auto XCOTMul_gate = share_->GetRegister()->EmplaceGate<proto::boolean_gmw::XCOTMulGate>(
        a_boolean_gmw_share, b_boolean_gmw_share);
    return ShareWrapper(XCOTMul_gate->GetOutputAsShare());
  }

  // Garbled Circuit And Operation
  else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit &&
           b->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    // replicate the bit of a to construct a new bit-string that has the same length as b
    auto mask = ShareWrapper::Concatenate(std::vector<ShareWrapper>(b->GetBitLength(), *this));
    return mask & b;
  }

  // otherwise, use BMR AND operation
  else if (share_->GetProtocol() == MpcProtocol::kBmr && b->GetProtocol() == MpcProtocol::kBmr) {
    // replicate the bit of a to construct a new bit-string that has the same length as b
    auto mask = ShareWrapper::Concatenate(std::vector<ShareWrapper>(b->GetBitLength(), *this));
    return mask & b;
  }

  else if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    // TODO implement
    throw std::runtime_error(
        "C-OT-based Multiplication for Arithmetic GMW shares is not implemented yet");
  } else {
    throw std::runtime_error("C-OT-based Multiplication are not supported");
  }
}

ShareWrapper DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b) {
  assert(a.size() == b.size());
  assert(a.size() > 0);
  assert(*a[0]);
  assert(*b[0]);
  assert(a[0]->GetCircuitType() == b[0]->GetCircuitType());
  assert(a[0]->GetBitLength() == b[0]->GetBitLength());
  for (auto i = 1u; i != a.size(); ++i) {
    assert(*a[i]);
    assert(*b[i]);
    assert(a[i]->GetCircuitType() == b[i]->GetCircuitType());
    assert(a[i]->GetBitLength() == b[i]->GetBitLength());
    assert(a[i - 1]->GetCircuitType() == a[i]->GetCircuitType());
    assert(b[i - 1]->GetCircuitType() == b[i]->GetCircuitType());
    assert(a[i - 1]->GetBitLength() == a[i]->GetBitLength());
    assert(b[i - 1]->GetBitLength() == b[i]->GetBitLength());
  }

  auto bit_length = a[0]->GetBitLength();
  if (bit_length == 8u) {
    return a[0].DotProduct<std::uint8_t>(a, b);
  } else if (bit_length == 16u) {
    return a[0].DotProduct<std::uint16_t>(a, b);
  } else if (bit_length == 32u) {
    return a[0].DotProduct<std::uint32_t>(a, b);
  } else if (bit_length == 64u) {
    return a[0].DotProduct<std::uint64_t>(a, b);
  }

  else if (bit_length == 128u) {
    return a[0].DotProduct<__uint128_t>(a, b);
  }

  else {
    throw std::bad_cast();
  }
}

template <MpcProtocol P>
ShareWrapper ShareWrapper::Convert() const {
  constexpr auto kArithmeticGmw = MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = MpcProtocol::kBmr;
  constexpr auto kGarbledCircuit = MpcProtocol::kGarbledCircuit;
  if (share_->GetProtocol() == P) {
    throw std::runtime_error("Trying to convert share to MpcProtocol it is already in");
  }

  assert(share_->GetProtocol() < MpcProtocol::kInvalid);

  if constexpr (P == kArithmeticGmw) {
    if (share_->GetProtocol() == kBooleanGmw) {  // kBooleanGmw -> kArithmeticGmw
      return BooleanGmwToArithmeticGmw();
    } else {  // kBmr --(over kBooleanGmw)--> kArithmeticGmw
      return this->Convert<kBooleanGmw>().Convert<kArithmeticGmw>();
    }
  } else if constexpr (P == kBooleanGmw) {
    if (share_->GetProtocol() == kArithmeticGmw) {  // kArithmeticGmw --(over kBmr)--> kBooleanGmw
      return this->Convert<kBmr>().Convert<kBooleanGmw>();
    }

    // added by Liang Zhao
    else if (share_->GetProtocol() == kGarbledCircuit) {  // kGarbledCircuit -> kBooleanGmw
      return GCToBooleanGmw();
    }

    else if (share_->GetProtocol() == kBmr) {  // kBmr -> kBooleanGmw
      return BmrToBooleanGmw();
    }
  } else if constexpr (P == kBmr) {
    if (share_->GetProtocol() == kArithmeticGmw) {  // kArithmeticGmw -> kBmr
      return ArithmeticGmwToBmr();
    } else {  // kBooleanGmw -> kBmr
      return BooleanGmwToBmr();
    }
  }

  // added by Liang Zhao
  else if constexpr (P == kGarbledCircuit) {
    if (share_->GetProtocol() == kBooleanGmw) {  // kBooleanGmw -> kGarbledCircuit
      return BooleanGmwToGC();
    } else {  // kArithmeticGmw -> kGarbledCircuit
      return ArithmeticGmwToGC();
    }
  }

  else {
    throw std::runtime_error("Unknown MpcProtocol");
  }
}

// explicit specialization of function templates
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kArithmeticGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBooleanGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBmr>() const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kGarbledCircuit>() const;

ShareWrapper ShareWrapper::ArithmeticGmwToBmr() const {
  auto arithmetic_gmw_to_bmr_gate{
      share_->GetRegister()->EmplaceGate<ArithmeticGmwToBmrGate>(share_)};
  return ShareWrapper(arithmetic_gmw_to_bmr_gate->GetOutputAsShare());
}

ShareWrapper ShareWrapper::BooleanGmwToArithmeticGmw() const {
  const auto bitlength = share_->GetBitLength();
  switch (bitlength) {
    case 8u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          share_->GetRegister()->EmplaceGate<GmwToArithmeticGate<std::uint8_t>>(share_)};
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 16u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          share_->GetRegister()->EmplaceGate<GmwToArithmeticGate<std::uint16_t>>(share_)};
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 32u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          share_->GetRegister()->EmplaceGate<GmwToArithmeticGate<std::uint32_t>>(share_)};
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    case 64u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          share_->GetRegister()->EmplaceGate<GmwToArithmeticGate<std::uint64_t>>(share_)};
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }

    case 128u: {
      auto boolean_gmw_to_arithmetic_gmw_gate{
          share_->GetRegister()->EmplaceGate<GmwToArithmeticGate<__uint128_t>>(share_)};
      return ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(fmt::format("Invalid bitlength {}", bitlength));
  }
}

ShareWrapper ShareWrapper::BooleanGmwToBmr() const {
  auto boolean_gmw_share = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
  assert(boolean_gmw_share);
  auto boolean_gmw_to_bmr_gate{
      share_->GetRegister()->EmplaceGate<BooleanGmwToBmrGate>(boolean_gmw_share)};
  return ShareWrapper(boolean_gmw_to_bmr_gate->GetOutputAsShare());
}

ShareWrapper ShareWrapper::BmrToBooleanGmw() const {
  auto bmr_share = std::dynamic_pointer_cast<proto::bmr::Share>(share_);
  assert(bmr_share);
  auto bmr_to_boolean_gmw_gate{share_->GetRegister()->EmplaceGate<BmrToBooleanGmwGate>(bmr_share)};
  return ShareWrapper(bmr_to_boolean_gmw_gate->GetOutputAsShare());
}

// added by Liang Zhao
// TODO: improve according to ABY paper using OT, which is more efficient
// current approach:
// 1. both the garbler and evaluator secret share their Boolean GMW share and get GC share.
// 2. they both XOR the GC share.
ShareWrapper ShareWrapper::BooleanGmwToGC() const {
  std::size_t party_id = share_->GetBackend().GetCommunicationLayer().GetMyId();

  std::vector<WirePointer> parent = share_->GetWires();

  std::size_t number_of_wires = parent.size();

  std::vector<BitVector<>> boolean_gmw_value_vector;
  boolean_gmw_value_vector.reserve(parent.size());

  // wait for parent wire to obtain a value
  for (std::size_t i = 0; i < number_of_wires; ++i) {
    auto boolean_gmw_wire = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(parent.at(i));
    assert(boolean_gmw_wire);
    boolean_gmw_wire->GetIsReadyCondition().Wait();
    assert(!boolean_gmw_wire->GetValues().GetData().empty());
    boolean_gmw_value_vector.emplace_back(boolean_gmw_wire->GetValues());
  }

  // both the garbler and evaluator secret share their Boolean GMW share and get GC share.
  // 1. the garbler first share his Boolean Gmw share value
  ShareWrapper gc_share_garbler = share_->GetBackend().GarbledCircuitInput(
      static_cast<std::size_t>(GarbledCircuitRole::kGarbler), boolean_gmw_value_vector);

  ShareWrapper gc_share_evaluator = share_->GetBackend().GarbledCircuitInput(
      static_cast<std::size_t>(GarbledCircuitRole::kEvaluator), boolean_gmw_value_vector);

  return gc_share_garbler ^ gc_share_evaluator;
}

// added by Liang Zhao
ShareWrapper ShareWrapper::GCToBooleanGmw() const {}

// added by Liang Zhao
// TODO: implement
ShareWrapper ShareWrapper::ArithmeticGmwToGC() const {}

ShareWrapper ShareWrapper::Out(std::size_t output_owner) const {
  assert(share_);
  auto& backend = share_->GetBackend();
  SharePointer result{nullptr};
  switch (share_->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      switch (share_->GetBitLength()) {
        case 8u: {
          result = backend.ArithmeticGmwOutput<std::uint8_t>(share_, output_owner);
          break;
        }
        case 16u: {
          result = backend.ArithmeticGmwOutput<std::uint16_t>(share_, output_owner);
          break;
        }
        case 32u: {
          result = backend.ArithmeticGmwOutput<std::uint32_t>(share_, output_owner);
          break;
        }
        case 64u: {
          result = backend.ArithmeticGmwOutput<std::uint64_t>(share_, output_owner);
          break;
        }

        // added by Liang Zhao
        case 128u: {
          result = backend.ArithmeticGmwOutput<__uint128_t>(share_, output_owner);
          break;
        }

        default: {
          throw std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength()));
        }
      }
    } break;
    case MpcProtocol::kAstra: {
      switch (share_->GetBitLength()) {
        case 8u: {
          result = backend.AstraOutput<std::uint8_t>(share_, output_owner);
          break;
        }
        case 16u: {
          result = backend.AstraOutput<std::uint16_t>(share_, output_owner);
          break;
        }
        case 32u: {
          result = backend.AstraOutput<std::uint32_t>(share_, output_owner);
          break;
        }
        case 64u: {
          result = backend.AstraOutput<std::uint64_t>(share_, output_owner);
          break;
        }

          // added by Liang Zhao
        case 128u: {
          result = backend.AstraOutput<__uint128_t>(share_, output_owner);
          break;
        }

        default: {
          throw std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength()));
        }
      }
    } break;
    case MpcProtocol::kBooleanGmw: {
      result = backend.BooleanGmwOutput(share_, output_owner);
      break;
    }
    case MpcProtocol::kBmr: {
      result = backend.BmrOutput(share_, output_owner);
      break;
    }
    case MpcProtocol::kGarbledCircuit: {
      result = backend.GarbledCircuitOutput(share_, output_owner);
      break;
    }
    default: {
      throw std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<unsigned int>(share_->GetProtocol())));
    }
  }
  return ShareWrapper(result);
}

std::vector<ShareWrapper> ShareWrapper::Split() const {
  std::vector<ShareWrapper> result;
  if (!share_) return result;

  result.reserve(share_->GetWires().size());
  const auto split = share_->Split();
  for (const auto& s : split) result.emplace_back(s);
  return result;
}

ShareWrapper ShareWrapper::GetWire(std::size_t i) const { return ShareWrapper(share_->GetWire(i)); }

ShareWrapper ShareWrapper::Concatenate(std::span<const ShareWrapper> input) {
  if (input.empty()) throw std::runtime_error("ShareWrapper cannot be empty");
  {
    const auto protocol = input[0]->GetProtocol();
    for (auto i = 1ull; i < input.size(); ++i) {
      if (input[i]->GetProtocol() != protocol) {
        throw std::runtime_error("Trying to join shares of different types");
      }
    }
  }
  std::vector<SharePointer> unwrapped_shares;
  unwrapped_shares.reserve(input.size());
  for (const auto& s : input) unwrapped_shares.emplace_back(*s);

  std::size_t bit_size_wires{0};
  for (const auto& s : input) bit_size_wires += s->GetBitLength();

  std::vector<WirePointer> wires;
  wires.reserve(bit_size_wires);
  for (const auto& s : input)
    for (const auto& w : s->GetWires()) wires.emplace_back(w);
  switch (input[0]->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      switch (wires.at(0)->GetBitLength()) {
        case 8: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint8_t>>(wires));
        }
        case 16: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint16_t>>(wires));
        }
        case 32: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint32_t>>(wires));
        }
        case 64: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<std::uint64_t>>(wires));
        }

          // added by Liang Zhao
        case 128: {
          return ShareWrapper(std::make_shared<proto::arithmetic_gmw::Share<__uint128_t>>(wires));
        }

        default:
          throw std::runtime_error(fmt::format(
              "Incorrect bit length of arithmetic shares: {}, allowed are 8, 16, 32, 64",
              wires.at(0)->GetBitLength()));
      }
    }
    case MpcProtocol::kAstra: {
      switch (wires.at(0)->GetBitLength()) {
        case 8: {
          return ShareWrapper(std::make_shared<proto::astra::Share<std::uint8_t>>(wires.at(0)));
        }
        case 16: {
          return ShareWrapper(std::make_shared<proto::astra::Share<std::uint16_t>>(wires.at(0)));
        }
        case 32: {
          return ShareWrapper(std::make_shared<proto::astra::Share<std::uint32_t>>(wires.at(0)));
        }
        case 64: {
          return ShareWrapper(std::make_shared<proto::astra::Share<std::uint64_t>>(wires.at(0)));
        }

          // added by Liang Zhao
        case 128: {
          return ShareWrapper(std::make_shared<proto::astra::Share<__uint128_t>>(wires.at(0)));
        }

        default:
          throw std::runtime_error(fmt::format(
              "Incorrect bit length of arithmetic shares: {}, allowed are 8, 16, 32, 64",
              wires.at(0)->GetBitLength()));
      }
    }
    case MpcProtocol::kBooleanGmw: {
      return ShareWrapper(std::make_shared<proto::boolean_gmw::Share>(wires));
    }
    case MpcProtocol::kBmr: {
      return ShareWrapper(std::make_shared<proto::bmr::Share>(wires));
    }
    case MpcProtocol::kGarbledCircuit: {
      return ShareWrapper(std::make_shared<proto::garbled_circuit::Share>(wires));
    }
    default: {
      throw std::runtime_error("Unknown MPC protocol");
    }
  }
}

ShareWrapper ShareWrapper::Evaluate(const AlgorithmDescription& algorithm) const {
  std::size_t number_of_input_wires = algorithm.number_of_input_wires_parent_a;
  if (algorithm.number_of_input_wires_parent_b)
    number_of_input_wires += *algorithm.number_of_input_wires_parent_b;

  if (number_of_input_wires != share_->GetBitLength()) {
    share_->GetRegister()->GetLogger()->LogError(fmt::format(
        "ShareWrapper::Evaluate: expected a share of bit length {}, got a share of bit length {}",
        number_of_input_wires, share_->GetBitLength()));
  }

  auto share_split_in_wires{Split()};
  std::vector<std::shared_ptr<ShareWrapper>> pointers_to_wires_of_split_share;
  pointers_to_wires_of_split_share.reserve(share_split_in_wires.size());
  for (const auto& w : share_split_in_wires)
    pointers_to_wires_of_split_share.emplace_back(std::make_shared<ShareWrapper>(w.Get()));

  pointers_to_wires_of_split_share.resize(algorithm.number_of_wires, nullptr);

  assert((algorithm.number_of_gates + number_of_input_wires) ==
         pointers_to_wires_of_split_share.size());

  for (std::size_t wire_i = number_of_input_wires, gate_i = 0; wire_i < algorithm.number_of_wires;
       ++wire_i, ++gate_i) {
    const auto& gate = algorithm.gates.at(gate_i);
    const auto type = gate.type;
    switch (type) {
      case PrimitiveOperationType::kXor: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) ^
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kAnd: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) &
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kOr: {
        assert(gate.parent_b);
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(*pointers_to_wires_of_split_share.at(gate.parent_a) |
                                           *pointers_to_wires_of_split_share.at(*gate.parent_b));
        break;
      }
      case PrimitiveOperationType::kInv: {
        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(~*pointers_to_wires_of_split_share.at(gate.parent_a));
        break;
      }

        // added by Liang Zhao
      case PrimitiveOperationType::kMux: {
        assert(gate.parent_b);
        assert(gate.output_wire);
        // auto mux_result = pointers_to_wires_of_split_share.at(*gate.selection_bit)
        //                       ->Mux(*pointers_to_wires_of_split_share.at(gate.parent_a),
        //                             *pointers_to_wires_of_split_share.at(*gate.parent_b));
        auto mux_result = (*pointers_to_wires_of_split_share.at(*gate.selection_bit))
                              .Mux(*pointers_to_wires_of_split_share.at(gate.parent_a),
                                   *pointers_to_wires_of_split_share.at(*gate.parent_b));

        pointers_to_wires_of_split_share.at(gate.output_wire) =
            std::make_shared<ShareWrapper>(mux_result);
        break;
      }
      default:
        throw std::runtime_error("Invalid PrimitiveOperationType");
    }
  }

  std::vector<ShareWrapper> output;
  output.reserve(pointers_to_wires_of_split_share.size() - algorithm.number_of_output_wires);
  for (auto i = pointers_to_wires_of_split_share.size() - algorithm.number_of_output_wires;
       i < pointers_to_wires_of_split_share.size(); i++) {
    output.emplace_back(*pointers_to_wires_of_split_share.at(i));
  }

  return ShareWrapper::Concatenate(output);
}

void ShareWrapper::ShareConsistencyCheck() const {
  if (share_->GetWires().size() == 0) {
    throw std::invalid_argument("ShareWrapper::share_ has 0 wires");
  }
  if constexpr (kDebug) {
    std::size_t number_of_simd{share_->GetWires()[0]->GetNumberOfSimdValues()};
    for (std::size_t i = 0; i < share_->GetWires().size(); ++i) {
      if (share_->GetWires()[i]->GetNumberOfSimdValues() != number_of_simd) {
        throw std::invalid_argument(
            fmt::format("ShareWrapper::share_ has inconsistent numbers of SIMD values"));
      }
    }
    if (number_of_simd == 0) {
      throw std::invalid_argument(fmt::format("Wires in ShareWrapper::share_ have 0 SIMD values"));
    }
  }
}

template <typename Test, template <typename...> class Ref>
struct is_specialization : std::false_type {};

template <template <typename...> class Ref, typename... Args>
struct is_specialization<Ref<Args...>, Ref> : std::true_type {};

template <typename T>
T ShareWrapper::As() const {
  ShareConsistencyCheck();
  if constexpr (std::is_unsigned<T>()) {
    if (share_->GetCircuitType() != CircuitType::kArithmetic) {
      throw std::invalid_argument(
          "Trying to ShareWrapper::As() to a arithmetic output with non-arithmetic input");
    }
    if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      auto arithmetic_gmw_wire =
          std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(share_->GetWires()[0]);
      assert(arithmetic_gmw_wire);
      return arithmetic_gmw_wire->GetValues()[0];
    } else if (share_->GetProtocol() == MpcProtocol::kArithmeticConstant) {
      auto constant_arithmetic_wire =
          std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share_->GetWires()[0]);
      assert(constant_arithmetic_wire);
      return constant_arithmetic_wire->GetValues()[0];
    } else if (share_->GetProtocol() == MpcProtocol::kAstra) {
      auto astra_wire = std::dynamic_pointer_cast<proto::astra::Wire<T>>(share_->GetWires()[0]);
      assert(astra_wire);
      return astra_wire->GetValues()[0].value;
    } else {
      throw std::invalid_argument("Unsupported arithmetic protocol in ShareWrapper::As()");
    }
  } else if constexpr (std::is_signed<T>()) {
    std::make_unsigned_t<T> unsigned_value{As<std::make_unsigned_t<T>>()};
    bool msb{(unsigned_value >> sizeof(T) * 8 - 1) == 1};
    T signed_value{msb ? -static_cast<T>(-unsigned_value) : static_cast<T>(unsigned_value)};
    return signed_value;
  } else if constexpr (is_specialization<T, std::vector>::value &&
                       std::is_unsigned<typename T::value_type>()) {
    // std::vector of unsigned integers
    if (share_->GetCircuitType() != CircuitType::kArithmetic) {
      throw std::invalid_argument(
          "Trying to ShareWrapper::As() to a arithmetic output with non-arithmetic input");
    }
    if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
      auto arithmetic_gmw_wire =
          std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<typename T::value_type>>(
              share_->GetWires()[0]);
      assert(arithmetic_gmw_wire);
      return arithmetic_gmw_wire->GetValues();
    } else if (share_->GetProtocol() == MpcProtocol::kArithmeticConstant) {
      auto constant_arithmetic_wire =
          std::dynamic_pointer_cast<proto::ConstantArithmeticWire<typename T::value_type>>(
              share_->GetWires()[0]);
      assert(constant_arithmetic_wire);
      return constant_arithmetic_wire->GetValues();
    } else if (share_->GetProtocol() == MpcProtocol::kAstra) {
      auto astra_wire = std::dynamic_pointer_cast<proto::astra::Wire<typename T::value_type>>(
          share_->GetWires()[0]);
      assert(astra_wire);
      auto const& values = astra_wire->GetValues();
      T result(values.size());
      for (auto i = 0u; i != result.size(); ++i) {
        result[i] = values[i].value;
      }
      return result;
    } else {
      throw std::invalid_argument("Unsupported arithmetic protocol in ShareWrapper::As()");
    }
  } else if constexpr (is_specialization<T, std::vector>::value &&
                       std::is_signed<typename T::value_type>()) {
    auto unsigned_values{As<std::vector<std::make_unsigned_t<typename T::value_type>>>()};
    T signed_values;
    signed_values.reserve(unsigned_values.size());
    for (auto& v : unsigned_values) {
      bool msb{(v >> sizeof(T) * 8 - 1) == 1};
      T signed_value{msb ? -static_cast<T>(-v) : static_cast<T>(v)};
      signed_values.emplace_back(signed_value);
    }
    return unsigned_values;
  } else {
    throw std::invalid_argument(
        fmt::format("Unsupported output type in ShareWrapper::As<{}>()", typeid(T).name()));
  }
}

template <>
bool ShareWrapper::As<bool>() const {
  ShareConsistencyCheck();
  if (share_->GetCircuitType() != CircuitType::kBoolean) {
    throw std::invalid_argument(
        "Trying to ShareWrapper::As() to a Boolean output with non-Boolean input");
  }
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto boolean_gmw_wire =
        std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(share_->GetWires()[0]);
    assert(boolean_gmw_wire);
    return boolean_gmw_wire->GetValues()[0];
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    auto bmr_wire = std::dynamic_pointer_cast<proto::bmr::Wire>(share_->GetWires()[0]);
    assert(bmr_wire);
    return bmr_wire->GetPublicValues()[0];
  } else if (share_->GetProtocol() == MpcProtocol::kBooleanConstant) {
    auto constant_boolean_wire =
        std::dynamic_pointer_cast<proto::ConstantBooleanWire>(share_->GetWires()[0]);
    assert(constant_boolean_wire);
    return constant_boolean_wire->GetValues()[0];
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    auto gc_wire = std::dynamic_pointer_cast<proto::garbled_circuit::Wire>(share_->GetWires()[0]);
    assert(gc_wire);
    return gc_wire->CopyPermutationBits()[0];
  } else {
    throw std::invalid_argument("Unsupported Boolean protocol in ShareWrapper::As()");
  }
}

template <>
BitVector<> ShareWrapper::As() const {
  ShareConsistencyCheck();
  if (share_->GetCircuitType() != CircuitType::kBoolean) {
    throw std::invalid_argument(
        "Trying to ShareWrapper::As() to a Boolean output with non-Boolean input");
  }
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    auto boolean_gmw_wire =
        std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(share_->GetWires()[0]);
    assert(boolean_gmw_wire);
    return boolean_gmw_wire->GetValues();
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    auto bmr_wire = std::dynamic_pointer_cast<proto::bmr::Wire>(share_->GetWires()[0]);
    assert(bmr_wire);
    return bmr_wire->GetPublicValues();
  } else if (share_->GetProtocol() == MpcProtocol::kBooleanConstant) {
    auto constant_boolean_wire =
        std::dynamic_pointer_cast<proto::ConstantBooleanWire>(share_->GetWires()[0]);
    assert(constant_boolean_wire);
    return constant_boolean_wire->GetValues();
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    auto gc_wire = std::dynamic_pointer_cast<proto::garbled_circuit::Wire>(share_->GetWires()[0]);
    assert(gc_wire);
    return gc_wire->CopyPermutationBits();
  } else {
    throw std::invalid_argument("Unsupported Boolean protocol in ShareWrapper::As()");
  }
}

template <>
std::vector<BitVector<>> ShareWrapper::As() const {
  std::vector<BitVector<>> result;
  result.reserve(share_->GetWires().size());
  for (std::size_t i = 0; i < share_->GetWires().size(); ++i) {
    result.emplace_back(this->GetWire(i).As<BitVector<>>());
  }
  return result;
}

template std::uint8_t ShareWrapper::As() const;
template std::uint16_t ShareWrapper::As() const;
template std::uint32_t ShareWrapper::As() const;
template std::uint64_t ShareWrapper::As() const;

// added by Liang Zhao
template __uint128_t ShareWrapper::As() const;

template std::vector<std::uint8_t> ShareWrapper::As() const;
template std::vector<std::uint16_t> ShareWrapper::As() const;
template std::vector<std::uint32_t> ShareWrapper::As() const;
template std::vector<std::uint64_t> ShareWrapper::As() const;

// added by Liang Zhao
template std::vector<__uint128_t> ShareWrapper::As() const;

template <typename T>
ShareWrapper ShareWrapper::Add(SharePointer share, SharePointer other) const {
  // std::cout << "ShareWrapper::Add" << std::endl;

  assert(share->GetProtocol() == other->GetProtocol() ||
         (share->GetCircuitType() == other->GetCircuitType() &&
          share->IsConstant() != other->IsConstant()));

  switch (share->GetProtocol()) {
      // added by Liang Zhao
    case MpcProtocol::kArithmeticConstant: {
      // std::cout<<"a + b"<<std::endl;
      // a + b
      if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() == MpcProtocol::kArithmeticConstant) {
        auto constant_wire_a =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share->GetWires()[0]);
        auto constant_wire_b =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(other->GetWires()[0]);

        auto addition_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticAdditionGate<T>>(
                constant_wire_a, constant_wire_b);
        // std::cout << "002" << std::endl;
        auto result =
            std::static_pointer_cast<Share>(addition_gate->GetOutputAsConstantArithmeticShare());

        // std::cout << "003" << std::endl;
        return ShareWrapper(result);
      }

      // a + <b>
      else if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
               other->GetProtocol() == MpcProtocol::kArithmeticGmw) {
        // std::cout<<"a + <b>"<<std::endl;

        auto constant_wire_original = share;
        auto non_constant_wire_original = other;
        // if (non_constant_wire_original->IsConstant())
        //   std::swap(constant_wire_original, non_constant_wire_original);
        assert(constant_wire_original->IsConstant() && !non_constant_wire_original->IsConstant());

        auto constant_wire = std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(
            constant_wire_original->GetWires()[0]);
        assert(constant_wire);
        auto non_constant_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
            non_constant_wire_original->GetWires()[0]);
        assert(non_constant_wire);

        auto addition_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticAdditionGate<T>>(
                non_constant_wire, constant_wire);
        auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Add");
      }
    }
    case MpcProtocol::kArithmeticGmw: {
      // <a> + <b>
      if (!share->IsConstant() && !other->IsConstant()) {
        auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
        assert(this_a);
        auto this_wire_a = this_a->GetArithmeticWire();

        auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
        assert(other_a);
        auto other_wire_a = other_a->GetArithmeticWire();

        auto addition_gate =
            share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::AdditionGate<T>>(
                this_wire_a, other_wire_a);
        auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      // <a> + b
      else if (!(share->IsConstant() && other->IsConstant())) {
        // assert(!(share->IsConstant() && other->IsConstant()));
        auto constant_wire_original = share;
        auto non_constant_wire_original = other;
        if (non_constant_wire_original->IsConstant())
          std::swap(constant_wire_original, non_constant_wire_original);
        assert(constant_wire_original->IsConstant() && !non_constant_wire_original->IsConstant());

        auto constant_wire = std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(
            constant_wire_original->GetWires()[0]);
        assert(constant_wire);
        auto non_constant_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
            non_constant_wire_original->GetWires()[0]);
        assert(non_constant_wire);

        auto addition_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticAdditionGate<T>>(
                non_constant_wire, constant_wire);
        auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Add");
      }
    }
    case MpcProtocol::kAstra: {
      auto this_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(share);
      assert(this_a);
      auto this_wire_a = this_a->GetAstraWire();

      auto other_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(other);
      assert(other_a);
      auto other_wire_a = other_a->GetAstraWire();

      auto addition_gate = share_->GetRegister()->EmplaceGate<proto::astra::AdditionGate<T>>(
          this_wire_a, other_wire_a);
      auto result = std::static_pointer_cast<Share>(addition_gate->GetOutputAsAstraShare());

      return ShareWrapper(result);
    }
    default:
      throw std::invalid_argument("Unsupported Arithmetic protocol in ShareWrapper::Add");
  }
}

template ShareWrapper ShareWrapper::Add<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Add<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::Add<__uint128_t>(SharePointer share, SharePointer other) const;

template <typename T>
ShareWrapper ShareWrapper::Sub(SharePointer share, SharePointer other) const {
  // commented out by Liang Zhao
  // assert(share->GetProtocol() == other->GetProtocol());

  switch (share->GetProtocol()) {
    // added by Liang Zhao
    case MpcProtocol::kArithmeticConstant: {
      // a - b
      if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() == MpcProtocol::kArithmeticConstant) {
        auto constant_wire_a =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share->GetWires()[0]);
        auto constant_wire_b =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(other->GetWires()[0]);

        auto subtraction_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticSubtractionGate<T>>(
                constant_wire_a, constant_wire_b);
        auto result =
            std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsConstantArithmeticShare());

        return ShareWrapper(result);
      }

      // a - <b>
      else if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
               other->GetProtocol() == MpcProtocol::kArithmeticGmw) {
        auto constant_wire_a =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share->GetWires()[0]);
        auto non_constant_wire_b =
            std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(other->GetWires()[0]);

        auto subtraction_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticSubtractionGate<T>>(
                constant_wire_a, non_constant_wire_b);
        auto result =
            std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Sub");
      }
    }

    case MpcProtocol::kArithmeticGmw: {
      // <a> - <b>
      if (!share->IsConstant() && !other->IsConstant()) {
        auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
        assert(this_a);
        auto this_wire_a = this_a->GetArithmeticWire();

        auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
        assert(other_a);
        auto other_wire_a = other_a->GetArithmeticWire();

        auto subtraction_gate =
            share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::SubtractionGate<T>>(
                this_wire_a, other_wire_a);
        auto result =
            std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      // <a> - b
      else if (share->GetProtocol() == MpcProtocol::kArithmeticGmw &&
               other->GetProtocol() == MpcProtocol::kArithmeticConstant) {
        // std::cout << "else if  " << std::endl;
        auto non_constant_wire_a =
            std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(share->GetWires()[0]);
        auto constant_wire_b =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(other->GetWires()[0]);

        // std::cout << "subtraction_gate  " << std::endl;
        auto subtraction_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticSubtractionGate<T>>(
                non_constant_wire_a, constant_wire_b);
        auto result =
            std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Sub");
      }
    }
    case MpcProtocol::kAstra: {
      auto this_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(share);
      assert(this_a);
      auto this_wire_a = this_a->GetAstraWire();

      auto other_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(other);
      assert(other_a);
      auto other_wire_a = other_a->GetAstraWire();

      auto subtraction_gate = share_->GetRegister()->EmplaceGate<proto::astra::SubtractionGate<T>>(
          this_wire_a, other_wire_a);
      auto result = std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsAstraShare());
      return result;
    }
    default:
      throw std::invalid_argument("Unsupported Arithmetic protocol in ShareWrapper::Sub");
  }
}

template ShareWrapper ShareWrapper::Sub<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Sub<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::Sub<__uint128_t>(SharePointer share, SharePointer other) const;

template <typename T>
ShareWrapper ShareWrapper::Mul(SharePointer share, SharePointer other) const {
  assert(share->GetProtocol() == other->GetProtocol() ||
         (share->GetCircuitType() == other->GetCircuitType() &&
          share->IsConstant() != other->IsConstant()));
  switch (share->GetProtocol()) {
    // added by Liang Zhao
    case MpcProtocol::kArithmeticConstant: {
      // a * b
      if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
          other->GetProtocol() == MpcProtocol::kArithmeticConstant) {
        auto constant_wire_a =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share->GetWires()[0]);
        auto constant_wire_b =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(other->GetWires()[0]);

        auto multiplication_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticMultiplicationGate<T>>(
                constant_wire_a, constant_wire_b);
        auto result = std::static_pointer_cast<Share>(
            multiplication_gate->GetOutputAsConstantArithmeticShare());

        return ShareWrapper(result);
      }

      // a * <b>
      else if (share->GetProtocol() == MpcProtocol::kArithmeticConstant &&
               other->GetProtocol() == MpcProtocol::kArithmeticGmw) {
        auto constant_wire_a =
            std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(share->GetWires()[0]);
        auto non_constant_wire_b =
            std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(other->GetWires()[0]);

        auto multiplication_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticMultiplicationGate<T>>(
                constant_wire_a, non_constant_wire_b);
        auto result =
            std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Mul");
      }
    }

    case MpcProtocol::kArithmeticGmw: {
      // <a> * <b>
      if (!share->IsConstant() && !other->IsConstant()) {
        auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
        assert(this_a);
        auto this_wire_a = this_a->GetArithmeticWire();

        auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
        assert(other_a);
        auto other_wire_a = other_a->GetArithmeticWire();

        auto multiplication_gate =
            share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::MultiplicationGate<T>>(
                this_wire_a, other_wire_a);
        auto result =
            std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      // <a> * b
      else if (!(share->IsConstant() && other->IsConstant())) {
        // assert(!(share->IsConstant() && other->IsConstant()));
        auto constant_wire_original = share;
        auto non_constant_wire_original = other;
        if (non_constant_wire_original->IsConstant())
          std::swap(constant_wire_original, non_constant_wire_original);
        assert(constant_wire_original->IsConstant() && !non_constant_wire_original->IsConstant());

        auto constant_wire = std::dynamic_pointer_cast<proto::ConstantArithmeticWire<T>>(
            constant_wire_original->GetWires()[0]);
        assert(constant_wire);
        auto non_constant_wire = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(
            non_constant_wire_original->GetWires()[0]);
        assert(non_constant_wire);

        auto multiplication_gate =
            share_->GetRegister()->EmplaceGate<proto::ConstantArithmeticMultiplicationGate<T>>(
                non_constant_wire, constant_wire);
        auto result =
            std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());

        return ShareWrapper(result);
      }

      else {
        throw std::invalid_argument("Unsupported Arithmetic GMW protocol in ShareWrapper::Mul");
      }
    }
    case MpcProtocol::kAstra: {
      auto this_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(share);
      assert(this_a);
      auto this_wire_a = this_a->GetAstraWire();

      auto other_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(other);
      assert(other_a);
      auto other_wire_a = other_a->GetAstraWire();

      auto multiplication_gate =
          share_->GetRegister()->EmplaceGate<proto::astra::MultiplicationGate<T>>(this_wire_a,
                                                                                  other_wire_a);
      auto result = std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsAstraShare());
      return ShareWrapper(result);
    }
    default:
      throw std::invalid_argument("Unsupported Arithmetic protocol in ShareWrapper::Mul");
  }
}

template <typename T>
ShareWrapper ShareWrapper::GreaterThan(SharePointer share, SharePointer other) const {
  if (share_->GetCircuitType() != CircuitType::kArithmetic) {
    throw std::invalid_argument("Trying to ShareWrapper::GreaterThan() with non-Arithmetic inputs");
  } else if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw) {
    throw std::invalid_argument(
        "ShareWrapper::GreaterThan() is implemented only for the arithmetic GMW protocol");
  }

  auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
  assert(other_a);
  auto other_wire_a = other_a->GetArithmeticWire();

  std::size_t l_s = 7;

  auto greater_than_gate =
      share_->GetRegister()->template EmplaceGate<proto::arithmetic_gmw::GreaterThanGate<T>>(
          this_wire_a, other_wire_a, l_s);
  auto result = std::static_pointer_cast<Share>(greater_than_gate->GetOutputAsGmwShare());

  return ShareWrapper(result);
}

template ShareWrapper ShareWrapper::GreaterThan<std::uint8_t>(SharePointer share,
                                                              SharePointer other) const;
template ShareWrapper ShareWrapper::GreaterThan<std::uint16_t>(SharePointer share,
                                                               SharePointer other) const;
template ShareWrapper ShareWrapper::GreaterThan<std::uint32_t>(SharePointer share,
                                                               SharePointer other) const;
template ShareWrapper ShareWrapper::GreaterThan<std::uint64_t>(SharePointer share,
                                                               SharePointer other) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::GreaterThan<__uint128_t>(SharePointer share,
                                                             SharePointer other) const;

template <typename T>
ShareWrapper ShareWrapper::HybridMul(SharePointer share_bit, SharePointer share_integer) const {
  if (!share_bit->IsConstant() && !share_integer->IsConstant()) {
    auto bgmw_share{std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_bit)};
    assert(bgmw_share);
    auto wire_bit{bgmw_share->GetWires()[0]};
    auto bgmw_wire_bit{std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(wire_bit)};

    auto agmw_share = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share_integer);
    assert(agmw_share);
    auto agmw_wire_integer{agmw_share->GetArithmeticWire()};

    auto multiplication_gate =
        share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::HybridMultiplicationGate<T>>(
            bgmw_wire_bit, agmw_wire_integer);
    auto result =
        std::static_pointer_cast<Share>(multiplication_gate->GetOutputAsArithmeticShare());
    return ShareWrapper(result);
  } else {
    throw(std::runtime_error("Hybrid Multiplication is not implemented for constants, yet."));
  }
}

template <typename T>
ShareWrapper ShareWrapper::Square(SharePointer share) const {
  auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto square_gate =
      share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::SquareGate<T>>(this_wire_a);
  auto result = std::static_pointer_cast<Share>(square_gate->GetOutputAsArithmeticShare());
  return ShareWrapper(result);
}

template ShareWrapper ShareWrapper::Mul<std::uint8_t>(SharePointer share, SharePointer other) const;
template ShareWrapper ShareWrapper::Mul<std::uint16_t>(SharePointer share,
                                                       SharePointer other) const;
template ShareWrapper ShareWrapper::Mul<std::uint32_t>(SharePointer share,
                                                       SharePointer other) const;

template ShareWrapper ShareWrapper::Mul<std::uint64_t>(SharePointer share,
                                                       SharePointer other) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::Mul<__uint128_t>(SharePointer share, SharePointer other) const;

template ShareWrapper ShareWrapper::HybridMul<std::uint8_t>(SharePointer share,
                                                            SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint16_t>(SharePointer share,
                                                             SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint32_t>(SharePointer share,
                                                             SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint64_t>(SharePointer share,
                                                             SharePointer other) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::HybridMul<__uint128_t>(SharePointer share,
                                                           SharePointer other) const;
template <typename T>
ShareWrapper ShareWrapper::DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b) const {
  switch (a[0]->GetProtocol()) {
    case MpcProtocol::kAstra: {
      std::vector<WirePointer> a_input;
      std::vector<WirePointer> b_input;
      a_input.reserve(a.size());
      b_input.reserve(b.size());

      for (auto i = 0u; i != a.size(); ++i) {
        auto share_a = std::dynamic_pointer_cast<proto::astra::Share<T>>(a[i].share_);
        assert(share_a);
        a_input.emplace_back(share_a->GetAstraWire());

        auto share_b = std::dynamic_pointer_cast<proto::astra::Share<T>>(b[i].share_);
        assert(share_b);
        b_input.emplace_back(share_b->GetAstraWire());
      }
      auto dot_product_gate = share_->GetRegister()->EmplaceGate<proto::astra::DotProductGate<T>>(
          std::move(a_input), std::move(b_input));
      auto result = std::static_pointer_cast<Share>(dot_product_gate->GetOutputAsAstraShare());
      return ShareWrapper(result);
    }
    default:
      throw std::invalid_argument("Unsupported Arithmetic protocol in ShareWrapper::DotProduct");
  }
}

template ShareWrapper ShareWrapper::DotProduct<std::uint8_t>(std::span<ShareWrapper> a,
                                                             std::span<ShareWrapper> b) const;
template ShareWrapper ShareWrapper::DotProduct<std::uint16_t>(std::span<ShareWrapper> a,
                                                              std::span<ShareWrapper> b) const;
template ShareWrapper ShareWrapper::DotProduct<std::uint32_t>(std::span<ShareWrapper> a,
                                                              std::span<ShareWrapper> b) const;
template ShareWrapper ShareWrapper::DotProduct<std::uint64_t>(std::span<ShareWrapper> a,
                                                              std::span<ShareWrapper> b) const;

// added by Liang Zhao
template ShareWrapper ShareWrapper::DotProduct<__uint128_t>(std::span<ShareWrapper> a,
                                                            std::span<ShareWrapper> b) const;

ShareWrapper ShareWrapper::Subset(std::vector<std::size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

ShareWrapper ShareWrapper::Subset(std::span<const std::size_t> positions) {
  auto subset_gate = share_->GetRegister()->EmplaceGate<SubsetGate>(share_, positions);
  return ShareWrapper(subset_gate->GetOutputAsShare());
}

std::vector<ShareWrapper> ShareWrapper::Unsimdify() {
  auto unsimdify_gate = share_->GetRegister()->EmplaceGate<UnsimdifyGate>(share_);
  std::vector<SharePointer> shares{unsimdify_gate->GetOutputAsVectorOfShares()};
  std::vector<ShareWrapper> result(shares.size());
  std::transform(shares.begin(), shares.end(), result.begin(),
                 [](SharePointer share) { return ShareWrapper(share); });
  return result;
}

ShareWrapper ShareWrapper::Simdify(std::span<const ShareWrapper> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  for (auto& share_wrapper : input) input_as_shares.emplace_back(share_wrapper.Get());
  return Simdify(input_as_shares);
}

ShareWrapper ShareWrapper::Simdify(std::span<SharePointer> input) {
  if (input.empty()) throw std::invalid_argument("Empty inputs in ShareWrapper::Simdify");
  auto simdify_gate = input[0]->GetRegister()->EmplaceGate<SimdifyGate>(input);
  return simdify_gate->GetOutputAsShare();
}

ShareWrapper ShareWrapper::Simdify(std::vector<ShareWrapper>&& input) { return Simdify(input); }

// added by Liang Zhao
std::vector<ShareWrapper> ShareWrapper::SimdifyReshapeHorizontal(std::vector<ShareWrapper> input,
                                                                 std::size_t num_of_wires,
                                                                 std::size_t num_of_simd) {
  assert(input.size() == num_of_simd * num_of_wires);

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> share_wire_tmp;
    share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      share_wire_tmp.emplace_back(input[i + j * num_of_wires]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(share_wire_tmp));
  }
  return result_vector;
}

// added by Liang Zhao
std::vector<ShareWrapper> ShareWrapper::SimdifyReshapeVertical(std::vector<ShareWrapper> input,
                                                               std::size_t num_of_wires,
                                                               std::size_t num_of_simd) {
  assert(input.size() == num_of_simd * num_of_wires);

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> share_wire_tmp;
    share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      share_wire_tmp.emplace_back(input[i * num_of_simd + j]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(share_wire_tmp));
  }

  return result_vector;
}

// added by Liang Zhao
std::vector<ShareWrapper> ShareWrapper::SimdifyDuplicateHorizontal(std::vector<ShareWrapper> input,
                                                                   std::size_t num_of_wires) {
  //   assert(input.size() == num_of_simd);
  std::size_t num_of_simd = input.size();

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> share_wire_tmp;
    share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      share_wire_tmp.emplace_back(input[j]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(share_wire_tmp));
  }

  return result_vector;
}

// added by Liang Zhao
std::vector<ShareWrapper> ShareWrapper::SimdifyDuplicateVertical(std::vector<ShareWrapper> input,
                                                                 std::size_t num_of_simd) {
  //   assert(input.size() == num_of_wires);
  std::size_t num_of_wires = input.size();

  std::vector<ShareWrapper> result_vector;
  result_vector.reserve(num_of_wires);

  for (std::size_t i = 0; i < num_of_wires; i++) {
    std::vector<ShareWrapper> share_wire_tmp;
    share_wire_tmp.reserve(num_of_simd);
    for (std::size_t j = 0; j < num_of_simd; j++) {
      share_wire_tmp.emplace_back(input[i]);
    }
    result_vector.emplace_back(ShareWrapper::Simdify(share_wire_tmp));
  }

  return result_vector;
}

// added by Liang Zhao
ShareWrapper ShareWrapper::KOrL() const {
  std::vector<ShareWrapper> share_split = ShareWrapper(share_).Split();

  // std::cout << "share_split.size(): " << share_split.size() << std::endl;
  // return KOrL(share_split, 0, share_->GetBitLength() - 1);
  return KOrL(share_split, 0, share_split.size() - 1);
}

// added by Liang Zhao
ShareWrapper ShareWrapper::KOrL(const std::vector<ShareWrapper>& input, std::size_t head,
                                std::size_t tail) const {
  assert(share_);
  assert(share_->GetCircuitType() == CircuitType::kBoolean);
  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error("Boolean KOrL operations are not supported for Arithmetic GMW shares");
  }

  if (tail - head == 0) {
    return input.at(head);
  } else {
    ShareWrapper t1 = KOrL(input, head, head + (tail - head) / 2);
    ShareWrapper t2 = KOrL(input, head + (tail - head) / 2 + 1, tail);
    // std::cout << "t1 | t2: " << std::endl;
    return t1 | t2;
  }
}

// added by Liang Zhao
ShareWrapper ShareWrapper::KAndL() const {
  std::vector<ShareWrapper> share_split = ShareWrapper(share_).Split();

  // std::cout << "share_split.size(): " << share_split.size() << std::endl;
  // return KOrL(share_split, 0, share_->GetBitLength() - 1);
  return KAndL(share_split, 0, share_split.size() - 1);
}

// added by Liang Zhao
ShareWrapper ShareWrapper::KAndL(const std::vector<ShareWrapper>& input, std::size_t head,
                                 std::size_t tail) const {
  assert(share_);
  assert(share_->GetCircuitType() == CircuitType::kBoolean);
  if (share_->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean KAndL operations are not supported for Arithmetic GMW shares");
  }

  if (tail - head == 0) {
    return input.at(head);
  } else {
    ShareWrapper t1 = KAndL(input, head, head + (tail - head) / 2);
    ShareWrapper t2 = KAndL(input, head + (tail - head) / 2 + 1, tail);
    return t1 & t2;
  }
}

// added by Liang Zhao
// we use binary tree structure to optimize the depth of Boolean GMW,
// a better way to optimize is using SIMD to speed up the computation, that guarantee the
// parallelization, for example: a0 * a1 * a2 * a3: first arithmetic wire w1: a0, a1 secone
// arithmetic wire w2: a2, a3 first compute w3 = w1 * w2, then, multiply the two values in w3.
ShareWrapper ShareWrapper::KMulL(const std::vector<ShareWrapper>& input, std::size_t head,
                                 std::size_t tail) const {
  // assert(share_);
  assert(input[0]->GetCircuitType() == CircuitType::kArithmetic);
  // if (input[0]->GetProtocol() == MpcProtocol::kBooleanGmw) {
  //   throw std::runtime_error(
  //       "Arithmetic KMulL operations are not supported for Boolean GMW shares");
  // }

  if (tail - head == 0) {
    return input.at(head);
  } else {
    ShareWrapper t1 = KMulL(input, head, head + (tail - head) / 2);
    ShareWrapper t2 = KMulL(input, head + (tail - head) / 2 + 1, tail);
    return t1 * t2;
  }
}

// added by Liang Zhao
ShareWrapper ShareWrapper::PreOr() const {
  ShareWrapper share_x = share_;
  return PreOr(share_x);
}

// added by Liang Zhao
ShareWrapper ShareWrapper::PreOr(const ShareWrapper& x) const {
  auto share_x = *x;
  assert(share_x);
  assert(share_x->GetCircuitType() == CircuitType::kBoolean);

  if (share_x->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean PreOr operations are not supported for Arithmetic GMW shares");
  } else {
    std::size_t k = share_x->GetBitLength();
    std::vector<ShareWrapper> share_split = ShareWrapper(share_x).Split();
    std::vector<ShareWrapper> preOr_list(k);

    preOr_list[0] = share_split.at(0);
    for (std::uint32_t j = 1; j < k; ++j) {
      preOr_list[j] = preOr_list[j - 1] | share_split.at(j);
    }
    return Concatenate(preOr_list);
  }
}

// added by Liang Zhao
ShareWrapper ShareWrapper::PreOrL() const {
  ShareWrapper share_x = share_;
  return PreOrL(share_x);
}

// added by Liang Zhao
ShareWrapper ShareWrapper::PreOrL(const ShareWrapper& x) const {
  auto share_x = *x;
  assert(share_x);
  assert(share_x->GetCircuitType() == CircuitType::kBoolean);

  if (share_x->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    throw std::runtime_error(
        "Boolean PreOr operations are not supported for Arithmetic GMW shares");
  } else {
    std::size_t k = share_x->GetBitLength();
    std::vector<ShareWrapper> preOr_list = ShareWrapper(share_x).Split();

    std::size_t log_k = std::size_t(ceil(log2(k)));
    std::size_t kmax = static_cast<std::uint32_t>(pow(2, log_k));

    // std::cout << "log_k: " << log_k << std::endl;
    // std::cout << "kmax: " << kmax << std::endl;

    for (std::uint32_t i = 0; i < log_k; i++) {
      for (std::uint32_t j = 0; j < kmax / static_cast<std::uint32_t>(pow(2, i + 1)); j++) {
        std::size_t y = static_cast<std::uint32_t>(pow(2, i)) +
                        j * static_cast<std::uint32_t>(pow(2, i + 1)) - 1;
        for (std::uint32_t z = 1; z < static_cast<std::uint32_t>(pow(2, i)) + 1; z++) {
          if (y + z < k) {
            preOr_list[y + z] = preOr_list[y] | preOr_list[y + z];
          }
        }
      }
    }
    return Concatenate(preOr_list);
  }
}

// added by Liang Zhao
// TODO: use bit_length_l
template <typename T>
ShareWrapper ShareWrapper::EQ(const ShareWrapper& arithmetic_gmw_share_a,
                              const ShareWrapper& arithmetic_gmw_share_b,
                              std::size_t bit_length_l) const {
  std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

  // <a> - <b>
  ShareWrapper arithmetic_gmw_share_a_minus_b = arithmetic_gmw_share_a - arithmetic_gmw_share_b;

  // a - b
  if (arithmetic_gmw_share_a_minus_b->GetProtocol() == MpcProtocol::kArithmeticConstant) {
    // std::cout << "EQ constant" << std::endl;
    auto constant_arithmetic_gmw_share_a_minus_b =
        std::dynamic_pointer_cast<proto::ConstantArithmeticShare<T>>(
            arithmetic_gmw_share_a_minus_b.share_);

    auto constant_arithmetic_gmw_wire_a_minus_b =
        constant_arithmetic_gmw_share_a_minus_b->GetConstantArithmeticWire();

    std::vector<T> constant_arithmetic_gmw_wire_value_a_minus_b =
        constant_arithmetic_gmw_wire_a_minus_b->GetValues();

    BitVector constant_arithmetic_gmw_wire_value_a_minus_b_equal_zero =
        BitVector<>(num_of_simd, false);
    for (std::size_t i = 0; i < num_of_simd; i++) {
      if (constant_arithmetic_gmw_wire_value_a_minus_b[i] == 0) {
        constant_arithmetic_gmw_wire_value_a_minus_b_equal_zero.Set(true, i);
      } else {
        constant_arithmetic_gmw_wire_value_a_minus_b_equal_zero.Set(false, i);
      }
    }

    return share_->GetBackend().ConstantAsBooleanGmwInput(
        constant_arithmetic_gmw_wire_value_a_minus_b_equal_zero);

    // if (constant_arithmetic_gmw_wire_value_a_minus_b == 0) {
    //   return share_->GetBackend().ConstantBooleanGmwInput(true);
    // } else {
    //   return share_->GetBackend().ConstantBooleanGmwInput(false);
    // }

  }

  // <a> - <b>
  else {
    return EQZ<T>(arithmetic_gmw_share_a_minus_b, bit_length_l);

    //   share_->GetRegister()->SetAsPrecomputationMode();

    //   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
    //   // auto edaBit_Gate =
    //   // std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
    //   // share_->GetRegister()->RegisterNextGate(edaBit_Gate);
    //   // ShareWrapper boolean_gmw_share_r =
    //   //     std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
    //   // ShareWrapper arithmetic_gmw_share_r =
    //   //     std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
    //   // std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
    //   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(bit_length_l, num_of_simd);
    //   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
    //   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

    //   share_->GetRegister()->UnsetPrecomputationMode();

    //   // c = a - b + r
    //   ShareWrapper arithmetic_share_c = arithmetic_gmw_share_a_minus_b +
    // arithmetic_gmw_share_r;

    //   auto arithmetic_gmw_share_c =
    //       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_share_c);
    //   // create reconstruct and bit-decomposition gate for c
    //   auto rec_and_bit_decompose_gate = std::make_shared<
    //       proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
    //       arithmetic_gmw_share_c);
    //   share_->GetRegister()->RegisterNextGate(rec_and_bit_decompose_gate);
    //   ShareWrapper boolean_value_c =
    // std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsBooleanGmwValue());
    //   ShareWrapper arithmetic_value_c =
    //
    //
    // std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsArithmeticGmwValue());
    //   boolean_value_c->SetAsPubliclyKnownShare();
    //   arithmetic_value_c->SetAsPubliclyKnownShare();

    //   // auto boolean_gmw_value_c =
    //   //     std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_value_c);
    //   auto boolean_gmw_share_r_invert = ~boolean_gmw_share_r;
    //   //    std::cout << "before BooleanValueSelection" << std::endl;
    //   ShareWrapper boolean_gmw_share_c_prime =
    //       BooleanValueSelection(boolean_value_c, boolean_gmw_share_r,
    //       boolean_gmw_share_r_invert);

    //   std::vector<ShareWrapper> boolean_gmw_share_c_prime_split =
    //   boolean_gmw_share_c_prime.Split(); std::vector<ShareWrapper>
    //   boolean_gmw_share_c_prime_of_length_l_vector(
    //       boolean_gmw_share_c_prime_split.begin(),
    //       boolean_gmw_share_c_prime_split.begin() + bit_length_l);
    //   ShareWrapper boolean_gmw_share_c_prime_of_length_l =
    //       Concatenate(boolean_gmw_share_c_prime_of_length_l_vector);

    //   ShareWrapper boolean_gmw_share_and_result =
    // boolean_gmw_share_c_prime_of_length_l.KAndL();
    //   return boolean_gmw_share_and_result;
  }
}

template ShareWrapper ShareWrapper::EQ<std::uint8_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                     const ShareWrapper& arithmetic_gmw_share_b,
                                                     std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQ<std::uint16_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                      const ShareWrapper& arithmetic_gmw_share_b,
                                                      std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQ<std::uint32_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                      const ShareWrapper& arithmetic_gmw_share_b,
                                                      std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQ<std::uint64_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                      const ShareWrapper& arithmetic_gmw_share_b,
                                                      std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQ<__uint128_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                    const ShareWrapper& arithmetic_gmw_share_b,
                                                    std::size_t bit_length_l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::EQC(const ShareWrapper& arithmetic_gmw_share_a,
//                                const ShareWrapper& arithmetic_value_b,
//                                std::size_t bit_length_l) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();
//   arithmetic_value_b->SetAsPubliclyKnownShare();

//   // <a> - <b>
//   ShareWrapper arithmetic_gmw_share_a_minus_b;

//   // a - b
//   if (arithmetic_value_b->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     arithmetic_gmw_share_a_minus_b = arithmetic_gmw_share_a - arithmetic_value_b;
//   }

//   // <a> - <b>
//   else if (arithmetic_value_b->GetProtocol() == MpcProtocol::kArithmeticGmw) {
//     arithmetic_gmw_share_a_minus_b =
//         ArithmeticValueSubtraction<T>(arithmetic_gmw_share_a, arithmetic_value_b);
//   } else {
//     throw std::runtime_error(
//         fmt::format("unsupport protocol for equality check", share_->GetBitLength()));
//   }

//   return EQZ<T>(arithmetic_gmw_share_a_minus_b, bit_length_l);

//   //   share_->GetRegister()->SetAsPrecomputationMode();

//   //   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//   //   //   auto edaBit_Gate =
//   //   //   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   //   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   //   //   ShareWrapper boolean_gmw_share_r =
//   //   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   //   //   ShareWrapper arithmetic_gmw_share_r =
//   //   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
//   //   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
//   //   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//   //   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

//   //   share_->GetRegister()->UnsetPrecomputationMode();

//   //   // c = a - b + r
//   //   ShareWrapper arithmetic_share_c = arithmetic_gmw_share_a_minus_b + arithmetic_gmw_share_r;

//   //   auto arithmetic_gmw_share_c =
//   //       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_share_c);
//   //   // create reconstruct and bit-decomposition gate for c
//   //   auto rec_and_bit_decompose_gate =
//   //
//   //
//   //
//   std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
//       //           arithmetic_gmw_share_c);
//       //   share_->GetRegister()->RegisterNextGate(rec_and_bit_decompose_gate);
//       //   ShareWrapper boolean_value_c =
//       //
//       std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsBooleanGmwValue());
//       //   ShareWrapper arithmetic_value_c =
//       //
//       //
//       //
//       std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsArithmeticGmwValue());
//       //   boolean_value_c->SetAsPubliclyKnownShare();
//       //   arithmetic_value_c->SetAsPubliclyKnownShare();

//       //   auto boolean_gmw_value_c =
//       //   std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_value_c); auto
//       //   boolean_gmw_share_r_invert = ~boolean_gmw_share_r;
//       //   //        std::cout << "before BooleanValueSelection" << std::endl;
//       //   ShareWrapper boolean_gmw_share_c_prime =
//       //       BooleanValueSelection(boolean_value_c, boolean_gmw_share_r,
//       boolean_gmw_share_r_invert);
//   //   ShareWrapper boolean_gmw_share_and_result = boolean_gmw_share_c_prime.KAndL();
//   //   return boolean_gmw_share_and_result;
// }

// template ShareWrapper ShareWrapper::EQC<std::uint8_t>(const ShareWrapper& arithmetic_gmw_share_a,
//                                                       const ShareWrapper& arithmetic_gmw_share_b,
//                                                       std::size_t bit_length_l) const;

// template ShareWrapper ShareWrapper::EQC<std::uint16_t>(const ShareWrapper&
// arithmetic_gmw_share_a,
//                                                        const ShareWrapper&
//                                                        arithmetic_gmw_share_b, std::size_t
//                                                        bit_length_l) const;

// template ShareWrapper ShareWrapper::EQC<std::uint32_t>(const ShareWrapper&
// arithmetic_gmw_share_a,
//                                                        const ShareWrapper&
//                                                        arithmetic_gmw_share_b, std::size_t
//                                                        bit_length_l) const;

// template ShareWrapper ShareWrapper::EQC<std::uint64_t>(const ShareWrapper&
// arithmetic_gmw_share_a,
//                                                        const ShareWrapper&
//                                                        arithmetic_gmw_share_b, std::size_t
//                                                        bit_length_l) const;

// template ShareWrapper ShareWrapper::EQC<__uint128_t>(const ShareWrapper& arithmetic_gmw_share_a,
//                                                      const ShareWrapper& arithmetic_gmw_share_b,
//                                                      std::size_t bit_length_l) const;

// added by Liang Zhao
// TODO:: use bit_length_l to compare partial arithmetic gmw share
template <typename T>
ShareWrapper ShareWrapper::EQZ(const ShareWrapper& arithmetic_gmw_share_a,

                               std::size_t bit_length_l) const {
  std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();
  //   share_->GetRegister()->SetAsPrecomputationMode();

  // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
  //   auto edaBit_Gate =
  //   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
  //   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
  //   ShareWrapper boolean_gmw_share_r =
  //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
  //   ShareWrapper arithmetic_gmw_share_r =
  //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
  //   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
  std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(bit_length_l, num_of_simd);
  ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
  ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

  //   share_->GetRegister()->UnsetPrecomputationMode();

  // <c> = <a> + <r>
  ShareWrapper arithmetic_share_c = arithmetic_gmw_share_a + arithmetic_gmw_share_r;

  auto arithmetic_gmw_share_c =
      std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_share_c);
  // create reconstruct and bit-decomposition gate for c
  // auto rec_and_bit_decompose_gate =
  //     std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
  //         arithmetic_gmw_share_c);
  // share_->GetRegister()->RegisterNextGate(rec_and_bit_decompose_gate);

  auto rec_and_bit_decompose_gate =
      share_->GetRegister()
          ->EmplaceGate<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
              arithmetic_gmw_share_c);

  ShareWrapper boolean_value_c =
      std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsBooleanGmwValue());
  ShareWrapper arithmetic_value_c =
      std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsArithmeticGmwValue());
  boolean_value_c->SetAsPubliclyKnownShare();
  arithmetic_value_c->SetAsPubliclyKnownShare();

  auto boolean_gmw_value_c = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_value_c);
  auto boolean_gmw_share_r_invert = ~boolean_gmw_share_r;
  //        std::cout << "before BooleanValueSelection" << std::endl;
  ShareWrapper boolean_gmw_share_c_prime =
      BooleanValueSelection(boolean_value_c, boolean_gmw_share_r, boolean_gmw_share_r_invert);

  std::vector<ShareWrapper> boolean_gmw_share_c_prime_split = boolean_gmw_share_c_prime.Split();
  std::vector<ShareWrapper> boolean_gmw_share_c_prime_of_length_l_vector(
      boolean_gmw_share_c_prime_split.begin(),
      boolean_gmw_share_c_prime_split.begin() + bit_length_l);
  ShareWrapper boolean_gmw_share_c_prime_of_length_l =
      Concatenate(boolean_gmw_share_c_prime_of_length_l_vector);
  ShareWrapper boolean_gmw_share_and_result = boolean_gmw_share_c_prime_of_length_l.KAndL();

  //   ShareWrapper boolean_gmw_share_and_result = boolean_gmw_share_c_prime.KAndL();
  return boolean_gmw_share_and_result;
}

template ShareWrapper ShareWrapper::EQZ<std::uint8_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                      std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQZ<std::uint16_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                       std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQZ<std::uint32_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                       std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQZ<std::uint64_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                       std::size_t bit_length_l) const;

template ShareWrapper ShareWrapper::EQZ<__uint128_t>(const ShareWrapper& arithmetic_gmw_share_a,
                                                     std::size_t bit_length_l) const;

// // added by Liang Zhao
// ShareWrapper ShareWrapper::LTBits(const ShareWrapper& R, const ShareWrapper& x) const {
//   // std::cout << "LTBits" << std::endl;

//   // R is either constant boolean share or publicly known boolean share after online evaluation
//   of
//   // previous gates
//   assert(R->GetProtocol() == MpcProtocol::kArithmeticConstant || R->IsPubliclyKnownShare());
//   assert(*R);
//   auto share_R = *R;

//   // x is a boolean gmw share
//   auto share_x = *x;
//   assert(share_x);
//   assert(share_x->GetCircuitType() == CircuitType::kBoolean);

//   size_t m = share_x->GetBitLength();

//   // if R is constant arithmetic share, convert it to boolean gmw share
//   ShareWrapper boolean_value_R;

//   // std::cout << "m: " << m << std::endl;
//   // std::cout << "before ConstantArithmeticGmwToBooleanValue" << std::endl;

//   if (R->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     if (m == 8U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint8_t>(R);
//     } else if (m == 16U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint16_t>(R);
//     } else if (m == 32U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint32_t>(R);
//     } else if (m == 64U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint64_t>(R);
//     } else if (m == 128U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<__uint128_t>(R);
//     }

//   } else {
//     boolean_value_R = R;
//   }

//   // std::cout << "after ConstantArithmeticGmwToBooleanValue" << std::endl;
//   // compute locally: <y>^B = <x>^B ^ <R>^B;
//   // auto boolean_value_xor_gate = std::make_shared<proto::BooleanGmwValueMixXorGate>(share_R,
//   // share_x); share_->GetRegister()->RegisterNextGate(boolean_value_xor_gate);
//   ShareWrapper y = BooleanValueXor(x, boolean_value_R);
//   // ShareWrapper y = BooleanValueXor(x, x);

//   // std::cout << "after BooleanValueXor" << std::endl;

//   // <z_i>^B = OR ^(m-1) _(j=i) <y_i>^B
//   // ShareWrapper y =
//   // std::static_pointer_cast<Share>(boolean_value_xor_gate->GetOutputAsGmwShare());
//   std::vector<ShareWrapper> y_split = y.Split();
//   std::reverse(y_split.begin(), y_split.end());
//   ShareWrapper y_split_reverse_concatenate = Concatenate(y_split);
//   ShareWrapper z = PreOrL(y_split_reverse_concatenate);
//   std::vector<ShareWrapper> z_split = z.Split();
//   std::reverse(z_split.begin(), z_split.end());

//   // <w_i>^B = <z_i>^B - <z_i+1>^B = <z_i>^B ^ <z_i+1>^B
//   std::vector<ShareWrapper> w_split(m);
//   for (std::size_t i = 0; i < m - 1; i++) {
//     w_split.at(i) = z_split.at(i) ^ z_split.at(i + 1);
//   }

//   // <w_(m-1)>^B = <z_(m-1)>^B
//   w_split.at(m - 1) = z_split.at(m - 1);
//   ShareWrapper w = Concatenate(w_split);

//   // compute locally: <x < R>^B = SUM ^(m-1) _(i=0) R & <w>^B;
//   // auto boolean_value_and_gate = std::make_shared<proto::BooleanGmwValueMixAndGate>(share_R,
//   *w);
//   // share_->GetRegister()->RegisterNextGate(boolean_value_and_gate);
//   // ShareWrapper R_and_w =
//   //     std::static_pointer_cast<Share>(boolean_value_and_gate->GetOutputAsGmwShare());
//   ShareWrapper R_and_w = BooleanValueAnd(w, boolean_value_R);
//   ShareWrapper x_less_than_R = R_and_w.KOrL();
//   ShareWrapper c = ~x_less_than_R;
//   return c;
// }

// // added by Liang Zhao
// ShareWrapper ShareWrapper::LTTBits(const ShareWrapper& R, const ShareWrapper& x) const {
//   // std::cout << "LTBits" << std::endl;

//   // R is either a constant boolean share or publicly known boolean share (after online
//   evaluation
//   // of previous gates)
//   assert(R->GetProtocol() == MpcProtocol::kArithmeticConstant || R->IsPubliclyKnownShare());
//   assert(*R);
//   auto share_R = *R;

//   // x is a boolean gmw share
//   auto share_x = *x;
//   assert(share_x);
//   assert(share_x->GetCircuitType() == CircuitType::kBoolean);

//   size_t m = share_x->GetBitLength();

//   // if R is constant arithmetic share, convert it to boolean gmw share
//   ShareWrapper boolean_value_R;

//   // std::cout << "m: " << m << std::endl;
//   // std::cout << "before ConstantArithmeticGmwToBooleanValue" << std::endl;

//   if (R->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     if (m == 8U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint8_t>(R);
//     } else if (m == 16U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint16_t>(R);
//     } else if (m == 32U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint32_t>(R);
//     } else if (m == 64U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<std::uint64_t>(R);
//     } else if (m == 128U) {
//       boolean_value_R = ConstantArithmeticGmwToBooleanValue<__uint128_t>(R);
//     }

//   } else {
//     boolean_value_R = R;
//   }

//   // std::cout << "after ConstantArithmeticGmwToBooleanValue" << std::endl;
//   // compute locally: <y>^B = <x>^B ^ <R>^B;
//   // auto boolean_value_xor_gate = std::make_shared<proto::BooleanGmwValueMixXorGate>(share_R,
//   // share_x); share_->GetRegister()->RegisterNextGate(boolean_value_xor_gate);
//   ShareWrapper y = BooleanValueXor(x, boolean_value_R);
//   // ShareWrapper y = BooleanValueXor(x, x);

//   // std::cout << "after BooleanValueXor" << std::endl;

//   // <z_i>^B = OR ^(m-1) _(j=i) <y_i>^B
//   // ShareWrapper y =
//   // std::static_pointer_cast<Share>(boolean_value_xor_gate->GetOutputAsGmwShare());
//   std::vector<ShareWrapper> y_split = y.Split();
//   std::reverse(y_split.begin(), y_split.end());
//   ShareWrapper y_split_reverse_concatenate = Concatenate(y_split);
//   ShareWrapper z = PreOrL(y_split_reverse_concatenate);
//   std::vector<ShareWrapper> z_split = z.Split();
//   std::reverse(z_split.begin(), z_split.end());

//   // <w_i>^B = <z_i>^B - <z_i+1>^B = <z_i>^B ^ <z_i+1>^B
//   std::vector<ShareWrapper> w_split(m);
//   for (std::uint32_t i = 0; i < m - 1; i++) {
//     w_split.at(i) = z_split.at(i) ^ z_split.at(i + 1);
//   }

//   // <w_(m-1)>^B = <z_(m-1)>^B
//   w_split.at(m - 1) = z_split.at(m - 1);
//   ShareWrapper w = Concatenate(w_split);

//   // compute locally: <x < R>^B = SUM ^(m-1) _(i=0) R & <w>^B;
//   // auto boolean_value_and_gate = std::make_shared<proto::BooleanGmwValueMixAndGate>(share_R,
//   *w);
//   // share_->GetRegister()->RegisterNextGate(boolean_value_and_gate);
//   // ShareWrapper R_and_w =
//   //     std::static_pointer_cast<Share>(boolean_value_and_gate->GetOutputAsGmwShare());
//   ShareWrapper R_and_w = BooleanValueAnd(w, boolean_value_R);
//   ShareWrapper x_less_than_R = R_and_w.KOrL();
//   // ShareWrapper c = ~x_less_than_R;

//   // modification by Liang Zhao
//   // <R> != <x>
//   ShareWrapper x_not_equal_R = y.KOrL();

//   // <d>^B = <R < x> = ~ (<R > x> | <R == x>) = ~ (<R > x> | ~(~<R == x>))
//   ShareWrapper d = ~(x_less_than_R | (~x_not_equal_R));
//   return d;
// }

//// added by Liang Zhao
//    template<typename T>
//    ShareWrapper ShareWrapper::LTC_MRVW(const ShareWrapper &x, const ShareWrapper &R) const {
//        // ShareWrapper ShareWrapper::LTC_MRVW() const {
//        // std::cout << "LTC_MRVW" << std::endl;
//        assert(R->GetProtocol() == MpcProtocol::kArithmeticConstant || R->IsPubliclyKnownShare());
//
//        ShareWrapper arithmetic_value_R = R;
//        if (R->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//            arithmetic_value_R = ConstantArithmeticGmwToArithmeticValue<T>(R);
//        } else {  // ??? need to deal with convert constant arithmetic wire
//            arithmetic_value_R =
//                    ShareWrapper(std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*R));
//        }
//
//        // auto share_R = *arithmetic_value_R;
//
//        // arithmetic_value_R->GetWires().at(0)->SetAsPubliclyKnownWire();
//
//        // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//        auto edaBit_Gate =
//        std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//        share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//        ShareWrapper boolean_gmw_share_r =
//                std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//        ShareWrapper arithmetic_gmw_share_r =
//                std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
//
//        // compute <a>^A = <x>^A + <r>^A
//        ShareWrapper share_a = x + arithmetic_gmw_share_r;
//
//        // reconstruct <a>^A and bit-decompose it to <a>^B
//        // <a>^A and <a>^B are publicly known values after online evaluation of previous gate
//        // i.e., <a>^A and <a>^B are revealed to all parties, and all parties hold the same
//        value of a
//        // (without being secret shared)
//        auto arithmetic_share_a =
//        std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share_a);
//        // create reconstruct and bit-decomposition gate for a
//        // ??? recover and convert the reconstructed arithmetic value to boolean bits
//        auto rec_and_bitDecompose_gate_a =
//                std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
//                        arithmetic_share_a);
//        share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate_a);
//        ShareWrapper boolean_value_a =
//                std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsBooleanGmwValue());
//        ShareWrapper arithmetic_value_a =
//                std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsArithmeticGmwValue());
//
//        // compute b^A = a^A + M^A - r^A = a^A - R^A
//        // std::cout << "compute <b>^A" << std::endl;
//        ShareWrapper value_b = ArithmeticValueSubtraction<T>(arithmetic_value_a,
//        arithmetic_value_R);
//
//        // reconstruct <b>^A, <b>^B
//        // locally reconstruct share_b
//        // share_b is only publicly known after the online evaluation of share_a
//        // all parties hold the same value of b
//        auto arithmetic_value_b =
//        std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*value_b);
//        // auto bitDecompose_gate_b =
//        // std::make_shared<proto::ArithmeticGmwValueBitDecompositionGate<T>>(arithmetic_value_b);
//        // share_->GetRegister()->RegisterNextGate(bitDecompose_gate_b);
//        // ShareWrapper boolean_value_b =
//        //     std::static_pointer_cast<Share>(bitDecompose_gate_b->GetOutputAsBooleanGmwValue());
//        ShareWrapper boolean_value_b = ArithmeticValueBitDecomposition<T>(value_b);
//
//        boolean_value_a->SetAsPubliclyKnownShare();
//        boolean_value_b->SetAsPubliclyKnownShare();
//
//        ShareWrapper w_1 = LTBits(boolean_value_a, boolean_gmw_share_r);
//        ShareWrapper w_2 = LTBits(boolean_value_b, boolean_gmw_share_r);
//        // std::cout << "w_1, w_2" << std::endl;
//
//        // compute -R
//        ShareWrapper arithmetic_value_minus_R = ArithmeticValueMinus<T>(arithmetic_value_R);
//        // std::cout << "arithmetic_value_minus_R" << std::endl;
//
//        ShareWrapper boolean_value_w3 =
//                ArithmeticValueLessThan<T>(ShareWrapper(arithmetic_value_b),
//                arithmetic_value_minus_R);
//        // std::cout << "boolean_value_w3" << std::endl;
//
//        ShareWrapper w_tmp = ~w_1 ^ w_2;
//        // std::cout << "w_tmp" << std::endl;
//        // auto constant_boolean_xor_gate =
//        //     std::make_shared<proto::BooleanGmwValueMixXorGate>(*boolean_value_w3, *w_tmp);
//        // share_->GetRegister()->RegisterNextGate(constant_boolean_xor_gate);
//        // ShareWrapper w =
//        // std::static_pointer_cast<Share>(constant_boolean_xor_gate->GetOutputAsGmwShare());
//        ShareWrapper w = BooleanValueXor(boolean_value_w3, w_tmp);
//
//        return w;
//    }

//    template ShareWrapper ShareWrapper::LTC_MRVW<std::uint8_t>(const ShareWrapper &x,
//                                                          const ShareWrapper &R) const;
//
//    template ShareWrapper ShareWrapper::LTC_MRVW<std::uint16_t>(const ShareWrapper &x,
//                                                           const ShareWrapper &R) const;
//
//    template ShareWrapper ShareWrapper::LTC_MRVW<std::uint32_t>(const ShareWrapper &x,
//                                                           const ShareWrapper &R) const;
//
//    template ShareWrapper ShareWrapper::LTC_MRVW<std::uint64_t>(const ShareWrapper &x,
//                                                           const ShareWrapper &R) const;
//
//// should support now
//    template ShareWrapper ShareWrapper::LTC_MRVW<__uint128_t>(const ShareWrapper &x,
//                                                         const ShareWrapper &R) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::LTC_MRVW(const ShareWrapper& x,
//                                                  const ShareWrapper& R) const {
//   // ShareWrapper ShareWrapper::LTC_MRVW() const {
//   // std::cout << "LTC_MRVW" << std::endl;
//   assert(R->GetProtocol() == MpcProtocol::kArithmeticConstant || R->IsPubliclyKnownShare());

//   std::size_t num_of_simd = x->GetNumberOfSimdValues();

//   ShareWrapper arithmetic_value_R = R;
//   if (R->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     arithmetic_value_R = ConstantArithmeticGmwToArithmeticValue<T>(R);
//   } else {  // ??? need to deal with convert constant arithmetic wire
//     arithmetic_value_R =
//         ShareWrapper(std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*R));
//   }

//   // auto share_R = *arithmetic_value_R;

//   // arithmetic_value_R->GetWires().at(0)->SetAsPubliclyKnownWire();

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//   //   auto edaBit_Gate =
//   //   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   //   ShareWrapper boolean_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   //   ShareWrapper arithmetic_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

//   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
//   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   //   std::cout<<"000"<<std::endl;
//   // compute <a>^A = <x>^A + <r>^A
//   ShareWrapper share_a = x + arithmetic_gmw_share_r;
//   //   std::cout<<"111"<<std::endl;

//   // reconstruct <a>^A and bit-decompose it to <a>^B
//   // <a>^A and <a>^B are publicly known values after online evaluation of previous gate
//   // i.e., <a>^A and <a>^B are revealed to all parties, and all parties hold the same value of a
//   // (without being secret shared)
//   auto arithmetic_share_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share_a);
//   // create reconstruct and bit-decomposition gate for a
//   // ??? recover and convert the reconstructed arithmetic value to boolean bits
//   auto rec_and_bitDecompose_gate_a =
//       std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
//           arithmetic_share_a);
//   share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate_a);
//   ShareWrapper boolean_value_a =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsBooleanGmwValue());
//   ShareWrapper arithmetic_value_a =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsArithmeticGmwValue());

//   // compute b^A = a^A + M^A - r^A = a^A - R^A
//   // std::cout << "compute <b>^A" << std::endl;
//   ShareWrapper value_b = ArithmeticValueSubtraction<T>(arithmetic_value_a, arithmetic_value_R);

//   // reconstruct <b>^A, <b>^B
//   // locally reconstruct share_b
//   // share_b is only publicly known after the online evaluation of share_a
//   // all parties hold the same value of b
//   auto arithmetic_value_b = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*value_b);
//   // auto bitDecompose_gate_b =
//   //     std::make_shared<proto::ArithmeticGmwValueBitDecompositionGate<T>>(arithmetic_value_b);
//   // share_->GetRegister()->RegisterNextGate(bitDecompose_gate_b);
//   // ShareWrapper boolean_value_b =
//   //     std::static_pointer_cast<Share>(bitDecompose_gate_b->GetOutputAsBooleanGmwValue());
//   ShareWrapper boolean_value_b = ArithmeticValueBitDecomposition<T>(value_b);

//   boolean_value_a->SetAsPubliclyKnownShare();
//   boolean_value_b->SetAsPubliclyKnownShare();

//   ShareWrapper w_1 = LTTBits(boolean_value_a, boolean_gmw_share_r);
//   ShareWrapper w_2 = LTTBits(boolean_value_b, boolean_gmw_share_r);
//   // std::cout << "w_1, w_2" << std::endl;

//   // compute -R
//   ShareWrapper arithmetic_value_minus_R = ArithmeticValueMinus<T>(arithmetic_value_R);
//   // std::cout << "arithmetic_value_minus_R" << std::endl;

//   // when
//   bool return_boolean_value = true;
//   bool set_zero_as_maximum = true;
//   ShareWrapper boolean_value_w3 =
//       ArithmeticValueLessThan<T>(ShareWrapper(arithmetic_value_b), arithmetic_value_minus_R,
//                                  return_boolean_value, set_zero_as_maximum);
//   // std::cout << "boolean_value_w3" << std::endl;

//   ShareWrapper w_tmp = w_1 ^ w_2;
//   // std::cout << "w_tmp" << std::endl;
//   // auto constant_boolean_xor_gate =
//   //     std::make_shared<proto::BooleanGmwValueMixXorGate>(*boolean_value_w3, *w_tmp);
//   // share_->GetRegister()->RegisterNextGate(constant_boolean_xor_gate);
//   // ShareWrapper w =
//   //     std::static_pointer_cast<Share>(constant_boolean_xor_gate->GetOutputAsGmwShare());
//   ShareWrapper w = ~BooleanValueXor(boolean_value_w3, w_tmp);

//   std::vector<ShareWrapper> result;
//   result.reserve(1);
//   result.emplace_back(w);

//   // only for debugging
//   result.emplace_back(arithmetic_gmw_share_r);
//   result.emplace_back(arithmetic_value_a);
//   result.emplace_back(value_b);
//   result.emplace_back(w_1);
//   result.emplace_back(w_2);
//   result.emplace_back(boolean_value_w3);

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::LTC_MRVW<std::uint8_t>(
//     const ShareWrapper& x, const ShareWrapper& R) const;

// template std::vector<ShareWrapper> ShareWrapper::LTC_MRVW<std::uint16_t>(
//     const ShareWrapper& x, const ShareWrapper& R) const;

// template std::vector<ShareWrapper> ShareWrapper::LTC_MRVW<std::uint32_t>(
//     const ShareWrapper& x, const ShareWrapper& R) const;

// template std::vector<ShareWrapper> ShareWrapper::LTC_MRVW<std::uint64_t>(
//     const ShareWrapper& x, const ShareWrapper& R) const;

// template std::vector<ShareWrapper> ShareWrapper::LTC_MRVW<__uint128_t>(const ShareWrapper& x,
//                                                                        const ShareWrapper& R)
//                                                                        const;

// // added by Liang Zhao
// template <typename M>
// std::vector<ShareWrapper> ShareWrapper::LTS_MRVW(const ShareWrapper& arithmetic_share_x,
//                                                  const ShareWrapper& arithmetic_share_y) const {
//   std::size_t num_of_simd = arithmetic_share_x->GetNumberOfSimdValues();

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <r>^A and <r>^B
//   //   auto edaBit_Gate_a =
//   //   std::make_shared<proto::arithmetic_gmw::edaBitGate<M>>(share_->GetBackend());
//   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate_a);
//   //   ShareWrapper boolean_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate_a->GetOutputAsBooleanShare());
//   //   ShareWrapper arithmetic_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate_a->GetOutputAsArithmeticShare());
//   std::vector<ShareWrapper> edaBit_vector_a = EdaBit<M>(sizeof(M) * 8, num_of_simd);
//   ShareWrapper boolean_gmw_share_r = edaBit_vector_a.at(0);
//   ShareWrapper arithmetic_gmw_share_r = edaBit_vector_a.at(1);

//   // generate edaBits: <r'>^A and <r'>^B
//   //   auto edaBit_Gate_b =
//   //   std::make_shared<proto::arithmetic_gmw::edaBitGate<M>>(share_->GetBackend());
//   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate_b);
//   //   ShareWrapper boolean_gmw_share_r_prime =
//   //       std::static_pointer_cast<Share>(edaBit_Gate_b->GetOutputAsBooleanShare());
//   //   ShareWrapper arithmetic_gmw_share_r_prime =
//   //       std::static_pointer_cast<Share>(edaBit_Gate_b->GetOutputAsArithmeticShare());
//   std::vector<ShareWrapper> edaBit_vector_b = EdaBit<M>(sizeof(M) * 8, num_of_simd);
//   ShareWrapper boolean_gmw_share_r_prime = edaBit_vector_b.at(0);
//   ShareWrapper arithmetic_gmw_share_r_prime = edaBit_vector_b.at(1);

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // <b>^A = <y>^A + <r>^A, <a>^A = <r'>^A - <x>^A
//   ShareWrapper share_b = arithmetic_share_y + arithmetic_gmw_share_r;
//   ShareWrapper share_a = arithmetic_gmw_share_r_prime - arithmetic_share_x;
//   auto arithmetic_share_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<M>>(*share_a);
//   auto arithmetic_share_b = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<M>>(*share_b);

//   // open <a> and <b>
//   auto rec_and_bitDecompose_gate_a =
//       std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<M>>(
//           arithmetic_share_a);
//   share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate_a);
//   ShareWrapper boolean_value_a =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsBooleanGmwValue());
//   ShareWrapper arithmetic_value_a =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_a->GetOutputAsArithmeticGmwValue());

//   auto rec_and_bitDecompose_gate_b =
//       std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<M>>(
//           arithmetic_share_b);
//   share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate_b);
//   ShareWrapper boolean_value_b =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_b->GetOutputAsBooleanGmwValue());
//   ShareWrapper arithmetic_value_b =
//       std::static_pointer_cast<Share>(rec_and_bitDecompose_gate_b->GetOutputAsArithmeticGmwValue());

//   // compute T = a + b locally
//   ShareWrapper arithmetic_value_T =
//       ArithmeticValueAddition<M>(arithmetic_value_a, arithmetic_value_b);
//   arithmetic_value_T->SetAsPubliclyKnownShare();

//   // <w1>^B = b < <r>^B, <w2>^B = a < <r'>^B,
//   ShareWrapper boolean_gmw_share_w1 = LTTBits(boolean_value_b, boolean_gmw_share_r);
//   ShareWrapper boolean_gmw_share_w2 = LTTBits(boolean_value_a, boolean_gmw_share_r_prime);

//   // w3 = (T < b)
//   ShareWrapper boolean_value_w3 =
//       ArithmeticValueLessThan<M>(arithmetic_value_T, arithmetic_value_b);
//   boolean_value_w3->SetAsPubliclyKnownShare();

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // (<s>_0^B, ..., <s>_(m-1)^B, <s>_m^B) = BitAdder(<r>^B,<r'>^B)
//   // expand <r>^B and <r'>^B to a larger field U by appending constant boolean values
//   //   ShareWrapper constant_boolean_value_r_complement =
//   //       share_->GetBackend().ConstantBooleanGmwInput(ToInput(M(0)));
//   ShareWrapper constant_boolean_value_r_complement =
//       CreateConstantBooleanGmwInput<M>(M(0), num_of_simd);
//   std::vector<ShareWrapper> constant_boolean_value_r_complement_vector =
//       constant_boolean_value_r_complement.Split();

//   //   ShareWrapper constant_boolean_value_r_prime_complement =
//   //       share_->GetBackend().ConstantBooleanGmwInput(ToInput(M(0)));
//   ShareWrapper constant_boolean_value_r_prime_complement =
//       CreateConstantBooleanGmwInput<M>(M(0), num_of_simd);
//   std::vector<ShareWrapper> constant_boolean_value_r_prime_complement_vector =
//       constant_boolean_value_r_prime_complement.Split();

//   std::vector<ShareWrapper> boolean_gmw_share_r_vector = boolean_gmw_share_r.Split();
//   boolean_gmw_share_r_vector.insert(boolean_gmw_share_r_vector.end(),
//                                     constant_boolean_value_r_complement_vector.begin(),
//                                     constant_boolean_value_r_complement_vector.end());

//   std::vector<ShareWrapper> boolean_gmw_share_r_prime_vector = boolean_gmw_share_r_prime.Split();
//   boolean_gmw_share_r_prime_vector.insert(boolean_gmw_share_r_prime_vector.end(),
//                                           constant_boolean_value_r_prime_complement_vector.begin(),
//                                           constant_boolean_value_r_prime_complement_vector.end());

//   ShareWrapper constant_boolean_value_r_with_complement =
//   Concatenate(boolean_gmw_share_r_vector); ShareWrapper
//   constant_boolean_value_r_prime_with_complement =
//       Concatenate(boolean_gmw_share_r_prime_vector);

//   SecureUnsignedInteger boolean_gmw_share_s =
//       SecureUnsignedInteger(constant_boolean_value_r_with_complement) +
//       SecureUnsignedInteger(constant_boolean_value_r_prime_with_complement);

//   std::vector<ShareWrapper> boolean_gmw_share_s_vector = boolean_gmw_share_s.Get().Split();

//   std::vector<ShareWrapper> boolean_gmw_share_s_0_to_s_m_minus_1_vector =
//   std::vector<ShareWrapper>(
//       boolean_gmw_share_s_vector.begin(), boolean_gmw_share_s_vector.begin() + sizeof(M) * 8);
//   ShareWrapper boolean_gmw_share_s_0_to_s_m_minus_1 =
//       Concatenate(boolean_gmw_share_s_0_to_s_m_minus_1_vector);

//   ShareWrapper boolean_gmw_share_s_m = boolean_gmw_share_s_vector[sizeof(M) * 8];

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   ShareWrapper boolean_gmw_share_w4 = boolean_gmw_share_s_m;

//   ShareWrapper boolean_value_T = ArithmeticValueBitDecomposition<M>(arithmetic_value_T);

//   ShareWrapper boolean_gmw_share_w5 =
//       LTTBits(boolean_value_T, boolean_gmw_share_s_0_to_s_m_minus_1);

//   ShareWrapper boolean_gmw_w_part1 =
//       boolean_gmw_share_w1 ^ boolean_gmw_share_w2 ^ boolean_gmw_share_w4 ^ boolean_gmw_share_w5;

//   ShareWrapper boolean_gmw_w = BooleanValueXor(boolean_gmw_w_part1, boolean_value_w3);

//   std::vector<ShareWrapper> result_vector;
//   result_vector.reserve(1);
//   result_vector.emplace_back(boolean_gmw_w);

//   // only for debugging
//   result_vector.emplace_back(arithmetic_value_a);
//   result_vector.emplace_back(arithmetic_value_b);
//   result_vector.emplace_back(arithmetic_value_T);
//   result_vector.emplace_back(boolean_gmw_share_w1);
//   result_vector.emplace_back(boolean_gmw_share_w2);
//   result_vector.emplace_back(boolean_value_w3);
//   result_vector.emplace_back(boolean_gmw_share_w4);
//   result_vector.emplace_back(boolean_gmw_share_w5);
//   result_vector.emplace_back(arithmetic_gmw_share_r);
//   result_vector.emplace_back(arithmetic_gmw_share_r_prime);

//   return result_vector;

//   //   return boolean_gmw_w;
// }

// template std::vector<ShareWrapper> ShareWrapper::LTS_MRVW<std::uint8_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_share_y) const;

// template std::vector<ShareWrapper> ShareWrapper::LTS_MRVW<std::uint16_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_share_y) const;

// template std::vector<ShareWrapper> ShareWrapper::LTS_MRVW<std::uint32_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_share_y) const;

// template std::vector<ShareWrapper> ShareWrapper::LTS_MRVW<std::uint64_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_share_y) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ModPow2m(const ShareWrapper& arithmetic_gmw_share_a,
//                                     std::size_t m) const {
//   std::size_t k = sizeof(T) * 8;

//   assert(k > m);
//   assert(m != 0);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   // generate edaBits: <r>^A and <r>^B of length m
//   // auto edaBit_Gate =
//   //         std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend(), m);
//   // share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   // ShareWrapper boolean_gmw_share_r =
//   //         std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   // ShareWrapper arithmetic_gmw_share_r =
//   //         std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
//   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(m, num_of_simd);
//   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

//   // 2^(k-m)
//   // std::cout << "2^(k-m)" << std::endl;
//   //   std::vector<T> power_of_2_k_minus_m{T(1) << (k - m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_k_minus_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (k - m), num_of_simd);

//   // convert constant arithmetic share 2^(k-m) to arithmetic gmw share (publicly known value)
//   // std::cout
//   //     << "convert constant arithmetic share 2^(k-m) to arithmetic gmw share (publicly known
//   //     value)"
//   //     << std::endl;
//   ShareWrapper arithmetic_value_power_of_2_k_minus_m =
//       ConstantArithmeticGmwToArithmeticValue<T>(constant_arithmetic_gmw_share_power_of_2_k_minus_m);
//   arithmetic_value_power_of_2_k_minus_m->SetAsPubliclyKnownShare();

//   // 2^(k-m) * (<a>^A + <r>^A)
//   // std::cout << "2^(k-m) * (<a>^A + <r>^A)" << std::endl;
//   ShareWrapper sharewrapper_arithmetic_gmw_share_to_recontruct =
//       constant_arithmetic_gmw_share_power_of_2_k_minus_m *
//       (arithmetic_gmw_share_a + arithmetic_gmw_share_r);

//   // reconstruct <c>^A to get c^A, and bit-decompose it to obtain c^B
//   // c = rec(2^(k-m) * (<a>^A + <r>^A))
//   // std::cout << "c = rec(2^(k-m) * (<a>^A + <r>^A))" << std::endl;
//   //   auto arithmetic_gmw_share_to_reconstruct =
//   //       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(
//   //           *sharewrapper_arithmetic_gmw_share_to_recontruct);
//   //   auto rec_and_bitDecompose_gate =
//   //
//   std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
//   //           arithmetic_gmw_share_to_reconstruct);
//   //   share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate);
//   //   ShareWrapper boolean_value_c =
//   // std::static_pointer_cast<Share>(rec_and_bitDecompose_gate->GetOutputAsBooleanGmwValue());
//   //   ShareWrapper arithmetic_value_c =
//   // std::static_pointer_cast<Share>(rec_and_bitDecompose_gate->GetOutputAsArithmeticGmwValue());
//   std::vector<ShareWrapper> reconstruct_and_bit_decompose_vector =
//       ReconstructArithmeticGmwShareAndBitDecompose<T>(
//           sharewrapper_arithmetic_gmw_share_to_recontruct);
//   ShareWrapper boolean_value_c = reconstruct_and_bit_decompose_vector[0];
//   ShareWrapper arithmetic_value_c = reconstruct_and_bit_decompose_vector[1];

//   // split c^B and <r>^B to get their subset for LT operation
//   std::vector<ShareWrapper> c_split = boolean_value_c.Split();
//   std::vector<ShareWrapper> c_subvector =
//       std::vector(c_split.cbegin() + k - m, c_split.cbegin() + k);
//   ShareWrapper sharewrapper_c_subvector = Concatenate(c_subvector);
//   std::vector<ShareWrapper> r_split = boolean_gmw_share_r.Split();
//   std::vector<ShareWrapper> r_subvector = std::vector(r_split.cbegin(), r_split.cbegin() + m);
//   ShareWrapper sharewrapper_r_subvector = Concatenate(r_subvector);

//   // compare the size between subset of c^B and <r>^B
//   sharewrapper_c_subvector->SetAsPubliclyKnownShare();
//   ShareWrapper boolean_gmw_share_v = LTTBits(sharewrapper_c_subvector, sharewrapper_r_subvector);
//   // TODO using circuit for the comparison, performance difference

//   // convert <v>^B to <v>^A using b2a_gate
//   // auto boolean_gmw_to_arithmetic_gmw_gate =
//   //     std::make_shared<BooleanGmwBitsToArithmeticGmwGate<T>>(*boolean_gmw_share_v);
//   // share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
//   // ShareWrapper arithmetic_gmw_share_v =
//   //     ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
//   ShareWrapper arithmetic_gmw_share_v = boolean_gmw_share_v.BooleanGmwBitsToArithmeticGmw<T>();

//   // 2^m
//   // std::cout << "2^m" << std::endl;
//   //   std::vector<T> power_of_2_m{T(1) << (m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (m), num_of_simd);

//   // 2^m * <v>^A - <r>^A
//   // std::cout << "2^m * <v>^A - <r>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_a_mod_part1 =
//       constant_arithmetic_gmw_share_power_of_2_m * arithmetic_gmw_share_v -
//       arithmetic_gmw_share_r;

//   // c/2^(k-m)
//   // std::cout << "c/2^(k-m)" << std::endl;
//   ShareWrapper arithmetic_value_c_div_power_of_2_k_minus_m =
//       ArithmeticValueDivision<T>(arithmetic_value_c, arithmetic_value_power_of_2_k_minus_m);

//   // <a mod 2^m>^A = 2^m * <v>^A - <r>^A + c/2^(k-m)
//   // std::cout << "<a mod 2^m>^A = 2^m * <v>^A - <r>^A + c/2^(k-m)" << std::endl;
//   // ??? shouldn't use constant arithmetic add, arithmetic_gmw_share_a_mod_part1 is a share
//   ShareWrapper arithmetic_gmw_share_a_mod_power_of_2_m = ArithmeticValueAddition<T>(
//       arithmetic_value_c_div_power_of_2_k_minus_m, arithmetic_gmw_share_a_mod_part1);

//   // return arithmetic_gmw_share_v;
//   return arithmetic_gmw_share_a_mod_power_of_2_m;
// }

// template ShareWrapper ShareWrapper::ModPow2m<std::uint8_t>(const ShareWrapper& a,
//                                                            std::size_t m) const;

// template ShareWrapper ShareWrapper::ModPow2m<std::uint16_t>(const ShareWrapper& a,
//                                                             std::size_t m) const;

// template ShareWrapper ShareWrapper::ModPow2m<std::uint32_t>(const ShareWrapper& a,
//                                                             std::size_t m) const;

// template ShareWrapper ShareWrapper::ModPow2m<std::uint64_t>(const ShareWrapper& a,
//                                                             std::size_t m) const;

// // should support now
// template ShareWrapper ShareWrapper::ModPow2m<__uint128_t>(const ShareWrapper& a,
//                                                           std::size_t m) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m) const
//     {
//   std::uint8_t l = sizeof(T) * 8;

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   // TODO: use B2U to generate boolean GMW share x? performance difference?
//   bool return_boolean_share_vector = false;
//   bool return_pow2_m = true;

//   std::vector<ShareWrapper> arithmetic_gmw_share_x_vector =
//       B2U<T>(arithmetic_gmw_share_m, l, return_boolean_share_vector, return_pow2_m);

//   // B2U already generate <2^m>^A
//   ShareWrapper arithemtic_gmw_share_pow2_m = arithmetic_gmw_share_x_vector.back();

//   // generate r
// //   share_->GetRegister()->SetAsPrecomputationMode();
//   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//   auto edaBit_Gate = std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(
//       share_->GetBackend(), sizeof(T) * 8, num_of_simd);
//   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   ShareWrapper boolean_gmw_share_r =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   ShareWrapper arithmetic_gmw_share_r =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

//   // arithmetic gmw share of each edaBit <ri>^A
//   std::vector<SharePointer> share_r_of_each_bit_vector =
//       edaBit_Gate->GetOutputAsArithmeticShareOfEachBit();
//   std::vector<ShareWrapper> arithmetic_gmw_share_r_of_each_bit_vector;
//   arithmetic_gmw_share_r_of_each_bit_vector.reserve(l);
//   for (std::size_t i = 0; i < l; i++) {
//     arithmetic_gmw_share_r_of_each_bit_vector.emplace_back(share_r_of_each_bit_vector[i]);
//   }
// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // ============================================================
//   // without SIMD

//   //   // r' = Sum_(i=1)^(k-1) 2^i * <xi>^A * <ri>^A
//   //   ShareWrapper arithmetic_gmw_share_r_prime =
//   //       arithmetic_gmw_share_x_vector[0] * arithmetic_gmw_share_r_of_each_bit_vector[0];
//   //   for (std::size_t i = 1; i < l; i++) {
//   //     //     std::vector<T> constant_power_of_2_i{T(1) << (i)};
//   //     //     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//   //     //         share_->GetBackend().ConstantArithmeticGmwInput(constant_power_of_2_i);
//   //     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//   //         CreateConstantArithmeticGmwInput<T>(T(1) << (i), num_of_simd);

//   //     arithmetic_gmw_share_r_prime =
//   //         arithmetic_gmw_share_r_prime + constant_arithmetic_gmw_share_power_of_2_i *
//   //                                            arithmetic_gmw_share_x_vector[i] *
//   //                                            arithmetic_gmw_share_r_of_each_bit_vector[i];
//   //   }

//   // ============================================================
//   // use SIMD to parallelize
//   // the benchmark result shows no noticable performance difference, l is not large enough for
//   SIMD

//   // r' = Sum_(i=1)^(k-1) 2^i * <xi>^A * <ri>^A
//   //   std::cout << "start simd" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_x_subvector(
//       arithmetic_gmw_share_x_vector.begin(), arithmetic_gmw_share_x_vector.begin() + l);
//   ShareWrapper arithmetic_gmw_share_x_vector_simdify = Simdify(arithmetic_gmw_share_x_subvector);
//   ShareWrapper arithmetic_gmw_share_r_of_each_bit_vector_simdify =
//       Simdify(arithmetic_gmw_share_r_of_each_bit_vector);
//   ShareWrapper arithmetic_gmw_share_x_mul_r_of_each_bit_vector_simdify =
//       arithmetic_gmw_share_x_vector_simdify * arithmetic_gmw_share_r_of_each_bit_vector_simdify;

//   // std::cout << "after simd" << std::endl;

//   std::vector<ShareWrapper> arithmetic_gmw_share_x_mul_r_of_each_bit_vector_unsimdify =
//       arithmetic_gmw_share_x_mul_r_of_each_bit_vector_simdify.Unsimdify();

//   std::vector<ShareWrapper> arithmetic_gmw_share_x_mul_r_of_each_bit_vector_simdify_reshape =
//       SimdifyReshapeVertical(arithmetic_gmw_share_x_mul_r_of_each_bit_vector_unsimdify, l,
//                              num_of_simd);
//   ShareWrapper arithmetic_gmw_share_r_prime =
//       arithmetic_gmw_share_x_mul_r_of_each_bit_vector_simdify_reshape[0];
//   for (std::size_t i = 1; i < l; i++) {
//     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//         CreateConstantArithmeticGmwInput<T>(T(1) << (i), num_of_simd);

//     arithmetic_gmw_share_r_prime =
//         arithmetic_gmw_share_r_prime +
//         constant_arithmetic_gmw_share_power_of_2_i *
//             arithmetic_gmw_share_x_mul_r_of_each_bit_vector_simdify_reshape[i];
//   }

//   // ============================================================

//   // <c>^A = <a>^A + <r>^A
//   ShareWrapper arithmetic_gmw_share_c = arithmetic_gmw_share_a + arithmetic_gmw_share_r;

//   // reconstruct c
//   std::vector<ShareWrapper> reconstruct_and_bit_decompose_vector =
//       ReconstructArithmeticGmwShareAndBitDecompose<T>(arithmetic_gmw_share_c);
//   ShareWrapper boolean_value_c = reconstruct_and_bit_decompose_vector[0];
//   ShareWrapper arithmetic_value_c = reconstruct_and_bit_decompose_vector[1];
//   std::vector<ShareWrapper> boolean_value_c_vector = boolean_value_c.Split();

//   std::vector<ShareWrapper> arithmetic_value_c_prime_vector;
//   arithmetic_value_c_prime_vector.reserve(l - 1);
//   for (std::size_t i = 1; i < l; i++) {
//     //     std::vector<T> constant_power_of_2_i{T(1) << (i)};
//     //     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//     //         share_->GetBackend().ConstantArithmeticGmwInput(constant_power_of_2_i);
//     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//         CreateConstantArithmeticGmwInput<T>(T(1) << (i), num_of_simd);

//     ShareWrapper arithmetic_value_pow2_i =
//         ConstantArithmeticGmwToArithmeticValue<T>(constant_arithmetic_gmw_share_power_of_2_i);

//     ShareWrapper arithmetic_value_c_prime =
//         ArithmeticValueModularReduction<T>(arithmetic_value_c, arithmetic_value_pow2_i);
//     arithmetic_value_c_prime_vector.emplace_back(arithmetic_value_c_prime);
//   }

//   // <c''>^A = Sum_(i=1)^(l-1) c_(i-1)' * (<x_(i-1)>^A - <x_i>^A)
//   ShareWrapper arithmetic_gmw_share_c_prime_prime = ArithmeticValueMultiplication<T>(
//       arithmetic_value_c_prime_vector[0],
//       (arithmetic_gmw_share_x_vector[0] - arithmetic_gmw_share_x_vector[1]));

//   for (std::size_t i = 2; i < l; i++) {
//     arithmetic_gmw_share_c_prime_prime =
//         arithmetic_gmw_share_c_prime_prime +
//         ArithmeticValueMultiplication<T>(
//             arithmetic_value_c_prime_vector[i - 1],
//             (arithmetic_gmw_share_x_vector[i - 1] - arithmetic_gmw_share_x_vector[i]));
//   }

//   ShareWrapper arithmetic_gmw_share_d =
//       LT<T>(arithmetic_gmw_share_c_prime_prime, arithmetic_gmw_share_r_prime);

//   ShareWrapper arithmetic_gmw_share_a_mod_pow2_m =
//       arithmetic_gmw_share_c_prime_prime - arithmetic_gmw_share_r_prime +
//       arithemtic_gmw_share_pow2_m * arithmetic_gmw_share_d;

//   std::vector<ShareWrapper> result;
//   result.reserve(2);
//   result.emplace_back(arithmetic_gmw_share_a_mod_pow2_m);  // 0
//   result.emplace_back(arithemtic_gmw_share_pow2_m);        // 1

//   // only for debugging
//   // result.emplace_back(arithmetic_gmw_share_r);              // 2
//   // result.emplace_back(arithmetic_gmw_share_c_prime_prime);  // 3
//   // result.emplace_back(arithmetic_gmw_share_c);              // 4
//   // result.emplace_back(arithmetic_gmw_share_a);              // 5
//   // result.emplace_back(arithmetic_value_c_prime_vector[0]);  // 6
//   // result.emplace_back(arithmetic_value_c_prime_vector[1]);  // 7
//   // result.emplace_back(arithmetic_value_c_prime_vector[2]);  // 8
//   // result.emplace_back(arithmetic_value_c_prime_vector[3]);  // 9
//   // result.emplace_back(arithmetic_value_c_prime_vector[4]);  // 10
//   // result.emplace_back(arithmetic_value_c_prime_vector[5]);  // 11

//   // result.emplace_back(arithmetic_gmw_share_x_vector[0] - arithmetic_gmw_share_x_vector[1]); //
//   // 12 result.emplace_back(arithmetic_gmw_share_x_vector[1] - arithmetic_gmw_share_x_vector[2]);
//   // // 13 result.emplace_back(arithmetic_gmw_share_x_vector[2] -
//   // arithmetic_gmw_share_x_vector[3]); // 14
//   result.emplace_back(arithmetic_gmw_share_x_vector[3]
//   // - arithmetic_gmw_share_x_vector[4]); // 15
//   // result.emplace_back(arithmetic_gmw_share_x_vector[4] - arithmetic_gmw_share_x_vector[5]); //
//   // 16

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m)
//     const;

// template std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m)
//     const;

// template std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m)
//     const;

// template std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m)
//     const;

// template std::vector<ShareWrapper> ShareWrapper::ObliviousModPow2m<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_m)
//     const;

// // added by Liang Zhao
// // TODO compare with LogicalRightShift_BitDecomposition
// // ! this protocol is slower than LogicalRightShift_BitDecomposition for SIMD=1 (need retest)
// template <typename T>
// ShareWrapper ShareWrapper::LogicalRightShift_EGKRS(const ShareWrapper& arithmetic_gmw_share_a,
//                                                    std::size_t m, std::size_t l) const {
//   // std::cout << "LogicalRightShift_BitDecomposition" << std::endl;
//   std::size_t k = sizeof(T) * 8;

//   assert(k >= m);
//   assert(k >= l);
//   assert(m != 0);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <r>^A and <r>^B of length l-m
//   //   auto edaBit_Gate =
//   //       std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend(), l - m);
//   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   //   ShareWrapper boolean_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   //   ShareWrapper arithmetic_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
//   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(l - m, num_of_simd);
//   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

//   //   share_->GetRegister()->UnsetPrecomputationMode();

//   // <b>^A = <a>^A - (<a>^A mod 2^m)
//   ShareWrapper arithmetic_gmw_share_b =
//       arithmetic_gmw_share_a - ModPow2m<T>(arithmetic_gmw_share_a, m);

//   // 2^(k-l)
//   // std::cout << "2^(k-l)" << std::endl;
//   //   std::vector<T> power_of_2_k_minus_l{T(1) << (k - l)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_k_minus_l);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_l =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (k - l), num_of_simd);

//   // 2^(l-m)
//   // std::cout << "2^(l-m)" << std::endl;
//   //   std::vector<T> power_of_2_l_minus_m{T(1) << (l - m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_l_minus_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (l - m), num_of_simd);

//   // 2^(k-l+m)
//   // std::cout << "2^(k-l+m)" << std::endl;
//   //   std::vector<T> power_of_2_k_minus_l_plus_m{T(1) << (k - l + m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_l_plus_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_k_minus_l_plus_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_l_plus_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (k - l + m), num_of_simd);

//   // convert constant arithmetic share 2^(k-l+m) to arithmetic gmw share (publicly known value)
//   ShareWrapper arithmetic_value_power_of_2_k_minus_l_plus_m =
//       ConstantArithmeticGmwToArithmeticValue<T>(
//           constant_arithmetic_gmw_share_power_of_2_k_minus_l_plus_m);

//   // 2^m
//   // std::cout << "2^m" << std::endl;
//   //   std::vector<T> power_of_2_m{T(1) << (m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (m), num_of_simd);

//   // 2^(k-l) * (<b>^A + 2^m * <r>^A)
//   // std::cout << "2^(k-l) * (<b>^A + 2^m * <r>^A)" << std::endl;
//   ShareWrapper sharewrapper_arithmetic_gmw_share_to_recontruct =
//       constant_arithmetic_gmw_share_power_of_2_k_minus_l *
//       (arithmetic_gmw_share_b +
//        constant_arithmetic_gmw_share_power_of_2_m * arithmetic_gmw_share_r);

//   // reconstruct d^A and bit-decompose it to obtain d^B
//   // d = rec(2^(k-l) * (<b>^A + 2^m * <r>^A))
//   // std::cout << "d = rec(2^(k-l) * (<b>^A + 2^m * <r>^A))" << std::endl;
//   //   auto arithmetic_gmw_share_to_reconstruct =
//   //       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(
//   //           *sharewrapper_arithmetic_gmw_share_to_recontruct);
//   //   auto rec_and_bitDecompose_gate =
//   //
//   //
//   std::make_shared<proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
//   //           arithmetic_gmw_share_to_reconstruct);
//   //   share_->GetRegister()->RegisterNextGate(rec_and_bitDecompose_gate);
//   //   ShareWrapper boolean_gmw_value_d =
//   // std::static_pointer_cast<Share>(rec_and_bitDecompose_gate->GetOutputAsBooleanGmwValue());
//   //   ShareWrapper arithmetic_gmw_value_d =
//   // std::static_pointer_cast<Share>(rec_and_bitDecompose_gate->GetOutputAsArithmeticGmwValue());
//   std::vector<ShareWrapper> reconstruct_and_bit_decompose_vector =
//       ReconstructArithmeticGmwShareAndBitDecompose<T>(
//           sharewrapper_arithmetic_gmw_share_to_recontruct);
//   ShareWrapper boolean_gmw_value_d = reconstruct_and_bit_decompose_vector[0];
//   ShareWrapper arithmetic_gmw_value_d = reconstruct_and_bit_decompose_vector[1];

//   // slice d^B and <r>^B for LT operation
//   // std::cout << "slice d^B and <r>^B for LT operation" << std::endl;
//   std::vector<ShareWrapper> d_split = boolean_gmw_value_d.Split();
//   std::vector<ShareWrapper> d_subvector =
//       std::vector(d_split.cbegin() + k - l + m, d_split.cbegin() + k);
//   ShareWrapper sharewrapper_d_subvector = Concatenate(d_subvector);
//   std::vector<ShareWrapper> r_split = boolean_gmw_share_r.Split();
//   std::vector<ShareWrapper> r_subvector = std::vector(r_split.cbegin(), r_split.cbegin() + l -
//   m); ShareWrapper sharewrapper_r_subvector = Concatenate(r_subvector);

//   // TODO: use LTBits() or circuit to compare
//   // std::cout << "LTTBITS" << std::endl;
//   sharewrapper_d_subvector->SetAsPubliclyKnownShare();
//   ShareWrapper boolean_gmw_share_u = LTTBits(sharewrapper_d_subvector, sharewrapper_r_subvector);
//   // ??? using circuit for the comparison, performance difference

//   // convert <u>^B to <u>^A using BooleanGmwBitsToArithmeticGmwGate
//   // auto boolean_gmw_to_arithmetic_gmw_gate =
//   //     std::make_shared<BooleanGmwBitsToArithmeticGmwGate<T>>(*boolean_gmw_share_u);
//   // share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
//   // ShareWrapper arithmetic_gmw_share_u =
//   //     ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());
//   ShareWrapper arithmetic_gmw_share_u = boolean_gmw_share_u.BooleanGmwBitsToArithmeticGmw<T>();

//   // 2^(l-m) * <u>^A - <r>^A
//   // std::cout << "2^(l-m) * <u>^A - <r>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_y_part1 =
//       constant_arithmetic_gmw_share_power_of_2_l_minus_m * arithmetic_gmw_share_u -
//       arithmetic_gmw_share_r;

//   // d/2^(k-l+m)
//   // std::cout << "d/2^(k-l+m)" << std::endl;
//   ShareWrapper arithmetic_value_c_div_power_of_2_k_minus_l_plus_m = ArithmeticValueDivision<T>(
//       arithmetic_gmw_value_d, arithmetic_value_power_of_2_k_minus_l_plus_m);

//   // <y>^A = 2^(l-m) * <u>^A + d/2^(k-l+m) - <r>^A
//   // std::cout << "<y>^A = 2^(l-m) * <u>^A + d/2^(k-l+m) - <r>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_y = ArithmeticValueAddition<T>(
//       arithmetic_value_c_div_power_of_2_k_minus_l_plus_m, arithmetic_gmw_share_y_part1);

//   return arithmetic_gmw_share_y;
// }

// template ShareWrapper ShareWrapper::LogicalRightShift_EGKRS<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_EGKRS<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_EGKRS<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_EGKRS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_EGKRS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const {
//   // std::cout << "LogicalRightShiftByBitDecompose" << std::endl;
//   std::size_t k = sizeof(T) * 8;

//   assert(k >= m);
//   assert(k >= l);
//   assert(m != 0);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   if (arithmetic_gmw_share_a->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     auto constant_arithmetic_gmw_share_a =
//         std::dynamic_pointer_cast<proto::ConstantArithmeticShare<T>>(arithmetic_gmw_share_a.share_);

//     auto constant_arithmetic_gmw_wire_a =
//         constant_arithmetic_gmw_share_a->GetConstantArithmeticWire();

//     std::vector<T> constant_arithmetic_gmw_wire_value_a =
//         constant_arithmetic_gmw_wire_a->GetValues();

//     std::vector<T> constant_arithmetic_gmw_wire_value_a_logical_right_shift_m(num_of_simd);
//     for (std::size_t i = 0; i < num_of_simd; i++) {
//       constant_arithmetic_gmw_wire_value_a_logical_right_shift_m[i] =
//           constant_arithmetic_gmw_wire_value_a[i] >> m;
//     }

//     // print_u128_u("constant_arithmetic_gmw_wire_value_a: ",
//     // constant_arithmetic_gmw_wire_value_a);

//     // std::cout << "return" << std::endl;
//     ShareWrapper constant_arithmetic_gmw_share_a_shift = CreateConstantArithmeticGmwInput<T>(
//         constant_arithmetic_gmw_wire_value_a_logical_right_shift_m);

//     return constant_arithmetic_gmw_share_a_shift;
//     // throw std::runtime_error(
//     //     fmt::format("constant logical right shift not implemented yet",
//     //     share_->GetBitLength()));
//   } else if (arithmetic_gmw_share_a->GetProtocol() == MpcProtocol::kArithmeticGmw) {
//     ShareWrapper boolean_gmw_share_a =
//     arithmetic_gmw_share_a.Convert<MpcProtocol::kBooleanGmw>();
//     //   std::cout << "000" << std::endl;

//     std::vector<ShareWrapper> boolean_gmw_share_a_vector = boolean_gmw_share_a.Split();
//     ShareWrapper constant_boolean_gmw_share_zero =
//         boolean_gmw_share_a_vector[0] ^ boolean_gmw_share_a_vector[0];

//     std::vector<ShareWrapper> boolean_gmw_share_a_shift_vector(k);
//     //   std::cout << "111" << std::endl;
//     for (std::size_t i = 0; i < k; i++) {
//       boolean_gmw_share_a_shift_vector[i] = constant_boolean_gmw_share_zero;
//     }

//     //   std::cout << "222" << std::endl;
//     for (std::size_t i = 0; i < k - m; i++) {
//       boolean_gmw_share_a_shift_vector[i] = boolean_gmw_share_a_vector[i + m];
//     }

//     ShareWrapper boolean_gmw_share_a_shift = Concatenate(boolean_gmw_share_a_shift_vector);

//     //   std::cout << "333" << std::endl;
//     ShareWrapper arithmetic_gmw_share_a_shift =
//         boolean_gmw_share_a_shift.Convert<MpcProtocol::kArithmeticGmw>();

//     return arithmetic_gmw_share_a_shift;
//   }
// }

// template ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalRightShift_BitDecomposition<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticRightShift(const ShareWrapper& arithmetic_gmw_share_a,
//                                                 std::size_t m, std::size_t l) const {
//   assert(m != 0);
//   std::size_t k = sizeof(T) * 8;

//   assert(k >= m);
//   assert(k >= l);
//   assert(m != 0);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   // 2^(l-1)
//   //   std::cout << "2^(l-1)" << std::endl;
//   //   std::vector<T> power_of_2_l_minus_1{T(1) << (l - 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_l_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (l - 1), num_of_simd);

//   // 2^(l-m-1)
//   //   std::cout << "2^(l-m-1)" << std::endl;
//   //   std::vector<T> power_of_2_l_minus_m_minus_1{T(1) << (l - m - 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_m_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_l_minus_m_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_l_minus_m_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (l - m - 1), num_of_simd);

//   // TODO use LogicalRightShift_EGKRS
//   ShareWrapper arithmetic_gmw_share_a_plus_power_of_2_l_minus_1_logical_right_shift_m =
//       LogicalRightShift_BitDecomposition<T>(
//           arithmetic_gmw_share_a + constant_arithmetic_gmw_share_power_of_2_l_minus_1, m, l);

//   // std::cout << "floor(alpha/2^m) = LogShift_m(a + 2^(l-1)) -2^(l-m-1) mod 2^k" << std::endl;
//   // floor(alpha/2^m) = LogShift_m(a + 2^(l-1)) -2^(l-m-1) mod 2^k
//   ShareWrapper arithmetic_gmw_share_result =
//       arithmetic_gmw_share_a_plus_power_of_2_l_minus_1_logical_right_shift_m -
//       constant_arithmetic_gmw_share_power_of_2_l_minus_m_minus_1;

//   // modulo reducation is not necessary because operation is limitted in the ring 2^k
//   // ??? cause random output
//   // ShareWrapper arithmetic_share_arithmetic_right_shift_m =
//   ModPow2m<T>(arithmetic_share_to_mod,
//   // k);

//   return arithmetic_gmw_share_result;
// }

// template ShareWrapper ShareWrapper::ArithmeticRightShift<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticRightShift<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticRightShift<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticRightShift<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticRightShift<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LogicalLeftShift(const ShareWrapper& arithmetic_gmw_share_a,
//                                             std::size_t m, std::size_t l) const {
//   assert(m != 0);
//   std::size_t k = sizeof(T) * 8;

//   assert(k >= m);
//   assert(k >= l);
//   assert(m != 0);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   // 2^(m)
//   // std::cout << "2^(m)" << std::endl;
//   //   std::vector<T> power_of_2_m{T(1) << (m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (m), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_result =
//       arithmetic_gmw_share_a * constant_arithmetic_gmw_share_power_of_2_m;

//   return arithmetic_gmw_share_result;
// }

// template ShareWrapper ShareWrapper::LogicalLeftShift<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalLeftShift<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalLeftShift<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalLeftShift<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::LogicalLeftShift<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticLeftShift(const ShareWrapper& arithmetic_gmw_share_a,
//                                                std::size_t m, std::size_t l) const {
//   ShareWrapper arithmetic_gmw_share_result = LogicalLeftShift<T>(arithmetic_gmw_share_a, m, l);

//   return arithmetic_gmw_share_result;
// }

// template ShareWrapper ShareWrapper::ArithmeticLeftShift<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticLeftShift<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticLeftShift<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticLeftShift<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template ShareWrapper ShareWrapper::ArithmeticLeftShift<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t m, std::size_t l) const;

// template <typename T, typename U>
// ShareWrapper ShareWrapper::TruncateAndReduce(const ShareWrapper& arithmetic_value_a) const {
//   // each party locally split the arithmetic share in two parts: a = b || c
//   std::vector<ShareWrapper> arithmetic_value_b_c_vector =
//       ArithmeticValueSplit<T, U>(arithmetic_value_a);
//   ShareWrapper arithmetic_gmw_share_b = arithmetic_value_b_c_vector[0];
//   ShareWrapper arithmetic_gmw_share_c = arithmetic_value_b_c_vector[1];

//   // compute the wrap of the summation of share c
//   ShareWrapper arithmetic_gmw_share_summation_c_wrap =
//       SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<U,
//       T>(arithmetic_gmw_share_c)[0];

//   ShareWrapper arithmetic_gmw_share_truncation_and_reduce =
//       arithmetic_gmw_share_b + arithmetic_gmw_share_summation_c_wrap;

//   return arithmetic_gmw_share_truncation_and_reduce;
// }

// template ShareWrapper ShareWrapper::TruncateAndReduce<__uint128_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint64_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint32_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint16_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// // added by Liang Zhao
// template <typename T, typename U>
// ShareWrapper ShareWrapper::TruncateAndReduce(const ShareWrapper& arithmetic_gmw_share_x,
//                                              std::size_t s, bool arithmetic_shift) const {
//   assert(s >= (sizeof(T) * 8 - sizeof(U) * 8));
//   ShareWrapper arithmetic_gmw_share_x_right_shift_s;

//   if (arithmetic_shift) {
//     arithmetic_gmw_share_x_right_shift_s = ArithmeticRightShift<T>(arithmetic_gmw_share_x, s);
//   } else {
//     arithmetic_gmw_share_x_right_shift_s =
//         LogicalRightShift_BitDecomposition<T>(arithmetic_gmw_share_x, s);
//   }

//   // std::cout << "11" << std::endl;
//   //   std::vector<T> constant_modulo{T(1) << (sizeof(T) * 8 - s)};
//   //   ShareWrapper constant_arithmetic_gmw_share_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_modulo);
//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (sizeof(T) * 8 - s));

//   // modulo operation
//   ShareWrapper arithmetic_value_x_right_shift_s_mod_l_minus_s =
//       ModPow2m<T>(arithmetic_gmw_share_x_right_shift_s, sizeof(T) * 8 - s);

//   // convert share from T to U
//   ShareWrapper arithmetic_value_x_right_shift_s_mod_l_minus_s_field_U =
//       ArithmeticValueModularReductionWithWrap<T, U>(
//           arithmetic_value_x_right_shift_s_mod_l_minus_s)[0];

//   // std::cout << "44" << std::endl;
//   return arithmetic_value_x_right_shift_s_mod_l_minus_s_field_U;
// }

// template ShareWrapper ShareWrapper::TruncateAndReduce<__uint128_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_value_x, std::size_t s, bool arithmetic_shift) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint64_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value_x, std::size_t s, bool arithmetic_shift) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint32_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value_x, std::size_t s, bool arithmetic_shift) const;

// template ShareWrapper ShareWrapper::TruncateAndReduce<std::uint16_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_value_x, std::size_t s, bool arithmetic_shift) const;

// // added by Liang Zhao
// template <typename M, typename N>
// ShareWrapper ShareWrapper::UnsignedExtension(const ShareWrapper& arithmetic_gmw_share_x) const {
//   ShareWrapper arithmetic_value_x_field_N =
//       ArithmeticValueFieldConversion<M, N>(arithmetic_gmw_share_x);

//   ShareWrapper arithmetic_gmw_share_summation_x_wrap_field_N =
//       SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<M,
//       N>(arithmetic_gmw_share_x)[0];

//   //   std::vector<N> power_of_2_m{N(1) << (sizeof(M) * 8)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//       CreateConstantArithmeticGmwInput<N>(N(1) << (sizeof(M) * 8));

//   ShareWrapper arithmetic_gmw_share_x_field_N =
//       arithmetic_value_x_field_N -
//       arithmetic_gmw_share_summation_x_wrap_field_N * constant_arithmetic_gmw_share_power_of_2_m;

//   return arithmetic_gmw_share_x_field_N;
// }

// // should support now
// template ShareWrapper ShareWrapper::UnsignedExtension<std::uint64_t, __uint128_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::UnsignedExtension<std::uint32_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::UnsignedExtension<std::uint16_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::UnsignedExtension<std::uint8_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::UnsignedExtension<std::uint16_t, __uint128_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// // added by Liang Zhao
// template <typename M, typename N>
// ShareWrapper ShareWrapper::SignedExtension(const ShareWrapper& arithmetic_gmw_share_x) const {
//   // compute 2^(m-1) in field M
//   std::size_t m = sizeof(M) * 8;
//   std::vector<M> power_of_2_m_minus_1_field_M{M(1) << (m - 1)};
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m_minus_1_field_M =
//       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m_minus_1_field_M);

//   // compute x' = x + 2^(m-1) mod M
//   ShareWrapper arithmetic_gmw_share_x_prime =
//       arithmetic_gmw_share_x + constant_arithmetic_gmw_share_power_of_2_m_minus_1_field_M;

//   // compute 2^(m-1) in field N
//   std::vector<N> power_of_2_m_minus_1_field_N{N(1) << (m - 1)};
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m_minus_1_field_N =
//       share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m_minus_1_field_N);

//   // compute SExt(x,m,n) = ZExt(x',m,n) - 2^(m-1)
//   ShareWrapper arithmetic_gmw_share_x_prime_field_N =
//       UnsignedExtension<M, N>(arithmetic_gmw_share_x_prime);

//   ShareWrapper arithmetic_gmw_share_x_field_N =
//       arithmetic_gmw_share_x_prime_field_N -
//       constant_arithmetic_gmw_share_power_of_2_m_minus_1_field_N;

//   return arithmetic_gmw_share_x_field_N;
// }

// // should support now
// template ShareWrapper ShareWrapper::SignedExtension<std::uint64_t, __uint128_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::SignedExtension<std::uint32_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::SignedExtension<std::uint16_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// template ShareWrapper ShareWrapper::SignedExtension<std::uint8_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value_x) const;

// // added by Liang Zhao
// // extend both x and y to field L, then multiply
// template <typename M, typename N, typename L>
// ShareWrapper ShareWrapper::UnsignedMultiplicationWithExtension(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y) const
//     {
//   /*   std::size_t m = sizeof(M) * 8;
// std::size_t n = sizeof(N) * 8;

// // convert local share x and y to field L
// ShareWrapper arithmetic_value_x_field_L =
// ArithmeticValueFieldConversion<M, L>(arithmetic_gmw_share_x);
// ShareWrapper arithmetic_value_y_field_L =
// ArithmeticValueFieldConversion<N, L>(arithmetic_gmw_share_y);

// // compute 2^m in field L
// std::vector<L> power_of_2_m_field_L{L(1) << m};
// ShareWrapper constant_arithmetic_gmw_share_power_of_2_m_field_L =
// share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m_field_L);

// // compute 2^n in field L
// std::vector<L> power_of_2_n_field_L{L(1) << n};
// ShareWrapper constant_arithmetic_gmw_share_power_of_2_n_field_L =
// share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_n_field_L);

// std::cout << "1. compute wrap in larger field" << std::endl;

// // compute the wrap of share x in field L
// ShareWrapper arithmetic_gmw_share_summation_x_wrap_field_L =
// SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<M,
// L>(arithmetic_gmw_share_x)[0];

// // compute the wrap of share y in field L
// ShareWrapper arithmetic_gmw_share_summation_y_wrap_field_L =
// SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<N,
// L>(arithmetic_gmw_share_y)[0];

// std::cout << "2. wrap multiplication" << std::endl;

// // compute 2^m * <wrap_x>_i
// ShareWrapper arithmetic_gmw_share_x_wrap_multiply_2_power_m_field_L =
// constant_arithmetic_gmw_share_power_of_2_m_field_L *
// arithmetic_gmw_share_summation_x_wrap_field_L;

// // compute 2^n * <wrap_y>_i
// ShareWrapper arithmetic_gmw_share_y_wrap_multiply_2_power_n_field_L =
// constant_arithmetic_gmw_share_power_of_2_n_field_L *
// arithmetic_gmw_share_summation_y_wrap_field_L;

// std::cout << "3. ArithmeticValueSubtraction" << std::endl;

// // compute <x>_i - 2^m * <wrap_x>_i locally
// ShareWrapper arithmetic_gmw_share_x_minus_wrap_multiply_2_power_m_field_L =
// ArithmeticValueSubtraction<L>(arithmetic_value_x_field_L,
// arithmetic_gmw_share_x_wrap_multiply_2_power_m_field_L);

// // compute <y>_i - 2^n * <wrap_y>_i locally
// ShareWrapper arithmetic_gmw_share_y_minus_wrap_multiply_2_power_n_field_L =
// ArithmeticValueSubtraction<L>(arithmetic_value_y_field_L,
// arithmetic_gmw_share_y_wrap_multiply_2_power_n_field_L);

// // compute the product:
// // x * y =
// // ((<x>_0-2^m*<wrap_x>_0) + ... + (<x>_(P-1)-2^m*<wrap_x>_(P-1))) *
// // ((<y>_0-2^n*<wrap_y>_0) + ... + (<y>_(P-1)-2^n*<wrap_y>_(P-1)))
// // P: number of parties

// // test if mulitiplication has problem
// ShareWrapper arithmetic_x_multiply_y_field_L =
// arithmetic_gmw_share_x_minus_wrap_multiply_2_power_m_field_L *
// arithmetic_gmw_share_y_minus_wrap_multiply_2_power_n_field_L; */

//   // simplified code
//   ShareWrapper arithmetic_gmw_share_x_field_L = UnsignedExtension<M, L>(arithmetic_gmw_share_x);
//   ShareWrapper arithmetic_gmw_share_y_field_L = UnsignedExtension<N, L>(arithmetic_gmw_share_y);

//   ShareWrapper arithmetic_x_multiply_y_field_L =
//       arithmetic_gmw_share_x_field_L * arithmetic_gmw_share_y_field_L;

//   return arithmetic_x_multiply_y_field_L;
// }

// template ShareWrapper
// ShareWrapper::UnsignedMultiplicationWithExtension<std::uint8_t, std::uint8_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::UnsignedMultiplicationWithExtension<std::uint16_t, std::uint16_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::UnsignedMultiplicationWithExtension<std::uint32_t, std::uint32_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::UnsignedMultiplicationWithExtension<std::uint64_t, std::uint64_t, __uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// // added by Liang Zhao
// template <typename M, typename N, typename L>
// ShareWrapper ShareWrapper::SignedMultiplicationWithExtension(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y) const
//     {
//   ShareWrapper arithmetic_gmw_share_x_field_L = SignedExtension<M, L>(arithmetic_gmw_share_x);
//   ShareWrapper arithmetic_gmw_share_y_field_L = SignedExtension<N, L>(arithmetic_gmw_share_y);

//   ShareWrapper arithmetic_x_multiply_y_field_L =
//       arithmetic_gmw_share_x_field_L * arithmetic_gmw_share_y_field_L;

//   return arithmetic_x_multiply_y_field_L;
// }

// template ShareWrapper
// ShareWrapper::SignedMultiplicationWithExtension<std::uint8_t, std::uint8_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::SignedMultiplicationWithExtension<std::uint16_t, std::uint16_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::SignedMultiplicationWithExtension<std::uint32_t, std::uint32_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// template ShareWrapper
// ShareWrapper::SignedMultiplicationWithExtension<std::uint64_t, std::uint64_t, __uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y)
//     const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueAddition(const ShareWrapper& share,
//                                                    const ShareWrapper& other) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*other);
//   auto other_wire_a = other_a->GetArithmeticWire();
//   assert(other_wire_a);

//   if (share->IsPubliclyKnownShare()) {
//     this_wire_a->SetAsPubliclyKnownWire();
//   }

//   if (other->IsPubliclyKnownShare()) {
//     other_wire_a->SetAsPubliclyKnownWire();
//   }

//   auto arithmetic_value_addition_gate =
//       std::make_shared<proto::ArithmeticGmwValueAdditionGate<T>>(this_wire_a, other_wire_a);
//   auto arithmetic_value_addition_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_addition_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_addition_gate_cast);
//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_addition_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueAddition<std::uint8_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueAddition<std::uint16_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueAddition<std::uint32_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueAddition<std::uint64_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueAddition<__uint128_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueSubtraction(const ShareWrapper& share,
//                                                       const ShareWrapper& other) const {
//   // std::cout << "ArithmeticValueSubtraction" << std::endl;
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   // std::cout << "11" << std::endl;

//   auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*other);
//   // std::cout << "22" << std::endl;
//   // ??? errors
//   auto other_wire_a = other_a->GetArithmeticWire();
//   // std::cout << "33" << std::endl;
//   assert(other_wire_a);

//   if (share->IsPubliclyKnownShare()) {
//     this_wire_a->SetAsPubliclyKnownWire();
//   }

//   if (other->IsPubliclyKnownShare()) {
//     other_wire_a->SetAsPubliclyKnownWire();
//   }

//   // std::cout << "before create arithmetic_value_subtraction_gate" << std::endl;

//   auto arithmetic_value_subtraction_gate =
//       std::make_shared<proto::ArithmeticGmwValueSubtractionGate<T>>(this_wire_a, other_wire_a);
//   auto arithmetic_value_subtraction_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_subtraction_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_subtraction_gate_cast);
//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_subtraction_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueSubtraction<std::uint8_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueSubtraction<std::uint16_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueSubtraction<std::uint32_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueSubtraction<std::uint64_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueSubtraction<__uint128_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueMinus(const ShareWrapper& share) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_minus_gate =
//       std::make_shared<proto::ArithmeticGmwValueMinusGate<T>>(this_wire_a);
//   auto arithmetic_value_minus_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_minus_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_minus_gate_cast);
//   auto result =
//       std::static_pointer_cast<Share>(arithmetic_value_minus_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueMinus<std::uint8_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMinus<std::uint16_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMinus<std::uint32_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMinus<std::uint64_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMinus<__uint128_t>(
//     const ShareWrapper& share) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueMultiplication(const ShareWrapper& share,
//                                                          const ShareWrapper& other) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*other);
//   auto other_wire_a = other_a->GetArithmeticWire();
//   assert(other_wire_a);

//   auto arithmetic_value_multiplication_gate =
//       std::make_shared<proto::ArithmeticGmwValueMultiplicationGate<T>>(this_wire_a,
//       other_wire_a);
//   auto arithmetic_value_multiplication_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_multiplication_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_multiplication_gate_cast);
//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_multiplication_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueMultiplication<std::uint8_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMultiplication<std::uint16_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMultiplication<std::uint32_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMultiplication<std::uint64_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueMultiplication<__uint128_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueDivision(const ShareWrapper& share,
//                                                    const ShareWrapper& other) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*other);
//   auto other_wire_a = other_a->GetArithmeticWire();
//   assert(other_wire_a);

//   auto arithmetic_value_division_gate =
//       std::make_shared<proto::ArithmeticGmwValueDivisionGate<T>>(this_wire_a, other_wire_a);

//   auto arithmetic_value_division_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_division_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_division_gate_cast);
//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_division_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueDivision<std::uint8_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueDivision<std::uint16_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueDivision<std::uint32_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueDivision<std::uint64_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// template ShareWrapper ShareWrapper::ArithmeticValueDivision<__uint128_t>(
//     const ShareWrapper& share, const ShareWrapper& other) const;

// // added by Liang Zhao
// // convert arithmetic value to boolean value
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition(const ShareWrapper& share) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_bit_decomposion_gate =
//       std::make_shared<proto::ArithmeticGmwValueBitDecompositionGate<T>>(this_wire_a);
//   auto arithmetic_value_bit_decomposition_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_bit_decomposion_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_bit_decomposition_gate_cast);
//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_bit_decomposion_gate->GetOutputAsBooleanGmwValue());

//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition<std::uint8_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition<std::uint16_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition<std::uint32_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition<std::uint64_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueBitDecomposition<__uint128_t>(
//     const ShareWrapper& arithmetic_value) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueLessThan(const ShareWrapper& share,
//                                                    const ShareWrapper& other,
//                                                    bool return_boolean_value,
//                                                    bool set_zero_as_maximum) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*other);
//   auto other_wire_a = other_a->GetArithmeticWire();
//   assert(other_wire_a);

//   auto arithmetic_value_less_than_gate =
//   std::make_shared<proto::ArithmeticGmwValueLessThanGate<T>>(
//       this_wire_a, other_wire_a, set_zero_as_maximum);
//   auto arithmetic_value_less_than_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_less_than_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_less_than_gate_cast);

//   if (return_boolean_value) {
//     auto result = std::static_pointer_cast<Share>(
//         arithmetic_value_less_than_gate->GetOutputAsBooleanGmwValue());
//     return ShareWrapper(result);
//   } else {
//     auto result = std::static_pointer_cast<Share>(
//         arithmetic_value_less_than_gate->GetOutputAsArithmeticGmwValue());
//     return ShareWrapper(result);
//   }
// }

// template ShareWrapper ShareWrapper::ArithmeticValueLessThan<std::uint8_t>(
//     const ShareWrapper& share, const ShareWrapper& other, bool return_boolean_value,
//     bool set_zero_as_maximum) const;

// template ShareWrapper ShareWrapper::ArithmeticValueLessThan<std::uint16_t>(
//     const ShareWrapper& share, const ShareWrapper& other, bool return_boolean_value,
//     bool set_zero_as_maximum) const;

// template ShareWrapper ShareWrapper::ArithmeticValueLessThan<std::uint32_t>(
//     const ShareWrapper& share, const ShareWrapper& other, bool return_boolean_value,
//     bool set_zero_as_maximum) const;

// template ShareWrapper ShareWrapper::ArithmeticValueLessThan<std::uint64_t>(
//     const ShareWrapper& share, const ShareWrapper& other, bool return_boolean_value,
//     bool set_zero_as_maximum) const;

// template ShareWrapper ShareWrapper::ArithmeticValueLessThan<__uint128_t>(
//     const ShareWrapper& share, const ShareWrapper& other, bool return_boolean_value,
//     bool set_zero_as_maximum) const;

// // added by Liang Zhao
// template <typename T, typename U>
// std::vector<ShareWrapper> ShareWrapper::ArithmeticValueModularReductionWithWrap(
//     const ShareWrapper& arithmetic_value) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_modular_conversion_gate =
//       std::make_shared<proto::ArithmeticGmwValueModularReductionWithWrapGate<T, U>>(this_wire_a);
//   auto arithmetic_value_modular_conversion_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_modular_conversion_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_modular_conversion_gate_cast);
//   auto remainder = std::static_pointer_cast<Share>(
//       arithmetic_value_modular_conversion_gate->GetRemainderAsArithmeticGmwValue());
//   auto wrap = std::static_pointer_cast<Share>(
//       arithmetic_value_modular_conversion_gate->GetWrapAsArithmeticGmwValue());

//   std::vector<ShareWrapper> result = {ShareWrapper(remainder), ShareWrapper(wrap)};

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueModularReductionWithWrap<
//     __uint128_t, std::uint64_t>(const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueModularReductionWithWrap<
//     std::uint64_t, std::uint32_t>(const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueModularReductionWithWrap<
//     std::uint32_t, std::uint16_t>(const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueModularReductionWithWrap<
//     std::uint16_t, std::uint8_t>(const ShareWrapper& arithmetic_value) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ArithmeticValueModularReduction(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value_x);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto this_b =
//       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value_modulo);
//   auto this_wire_b = this_b->GetArithmeticWire();
//   assert(this_wire_b);

//   auto arithmetic_value_modular_reduction_gate =
//       std::make_shared<proto::ArithmeticGmwValueModularReductionGate<T>>(this_wire_a,
//       this_wire_b);
//   auto arithmetic_value_modular_reduction_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_modular_reduction_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_modular_reduction_gate_cast);
//   auto remainder = std::static_pointer_cast<Share>(
//       arithmetic_value_modular_reduction_gate->GetRemainderAsArithmeticGmwValue());

//   ShareWrapper result = ShareWrapper(remainder);

//   return result;
// }

// template ShareWrapper ShareWrapper::ArithmeticValueModularReduction<std::uint8_t>(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const;

// template ShareWrapper ShareWrapper::ArithmeticValueModularReduction<std::uint16_t>(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const;

// template ShareWrapper ShareWrapper::ArithmeticValueModularReduction<std::uint32_t>(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const;

// template ShareWrapper ShareWrapper::ArithmeticValueModularReduction<std::uint64_t>(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const;

// template ShareWrapper ShareWrapper::ArithmeticValueModularReduction<__uint128_t>(
//     const ShareWrapper& arithmetic_value_x, const ShareWrapper& arithmetic_value_modulo) const;

// // added by Liang Zhao
// template <typename T, typename U>
// std::vector<ShareWrapper> ShareWrapper::ArithmeticValueSplit(
//     const ShareWrapper& arithmetic_value) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_split_gate =
//       std::make_shared<proto::ArithmeticGmwValueSplitGate<T, U>>(this_wire_a);
//   auto arithmetic_value_split_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_split_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_split_gate_cast);
//   auto share_a = std::static_pointer_cast<Share>(
//       arithmetic_value_split_gate->GetOutputAsArithmeticGmwValueVectorA());
//   auto share_b = std::static_pointer_cast<Share>(
//       arithmetic_value_split_gate->GetOutputAsArithmeticGmwValueVectorB());

//   std::vector<ShareWrapper> result = {ShareWrapper(share_a), ShareWrapper(share_b)};

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueSplit<__uint128_t,
// std::uint64_t>(
//     const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueSplit<std::uint64_t,
// std::uint32_t>(
//     const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueSplit<std::uint32_t,
// std::uint16_t>(
//     const ShareWrapper& arithmetic_value) const;

// template std::vector<ShareWrapper> ShareWrapper::ArithmeticValueSplit<std::uint16_t,
// std::uint8_t>(
//     const ShareWrapper& arithmetic_value) const;

// // added by Liang Zhao
// template <typename T, typename U>
// ShareWrapper ShareWrapper::ArithmeticValueFieldConversion(
//     const ShareWrapper& arithmetic_value) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_extension_gate =
//       std::make_shared<proto::ArithmeticGmwValueFieldConversionGate<T, U>>(this_wire_a);
//   auto arithmetic_value_extension_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_extension_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_extension_gate_cast);
//   auto share_a = std::static_pointer_cast<Share>(
//       arithmetic_value_extension_gate->GetOutputAsArithmeticGmwValue());
//   return share_a;
// }

// template ShareWrapper ShareWrapper::ArithmeticValueFieldConversion<std::uint64_t, __uint128_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueFieldConversion<std::uint32_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueFieldConversion<std::uint16_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value) const;

// template ShareWrapper ShareWrapper::ArithmeticValueFieldConversion<std::uint8_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value) const;

// // added by Liang Zhao
// // convert constant arithmetic share to arithmetic gmw share (publicly known value)
// template <typename T>
// ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue(const ShareWrapper& share)
// const {
//   auto this_a = std::dynamic_pointer_cast<proto::ConstantArithmeticShare<T>>(*share);

//   auto this_wire_a = this_a->GetConstantArithmeticWire();
//   assert(this_wire_a);

//   auto constant_arithmetic_gmw_to_arithmetic_value_gate =
//       std::make_shared<proto::ArithmeticGmwConstantToArithmeticGmwValueGate<T>>(this_wire_a);
//   auto constant_arithmetic_gmw_to_arithmetic_value_gate_cast =
//       std::static_pointer_cast<Gate>(constant_arithmetic_gmw_to_arithmetic_value_gate);
//   share_->GetRegister()->RegisterNextGate(constant_arithmetic_gmw_to_arithmetic_value_gate_cast);

//   auto result = std::static_pointer_cast<Share>(
//       constant_arithmetic_gmw_to_arithmetic_value_gate->GetOutputAsArithmeticGmwValue());

//   return ShareWrapper(result);
//   // return share;
// }

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue<std::uint8_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue<std::uint16_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue<std::uint32_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue<std::uint64_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToArithmeticValue<__uint128_t>(
//     const ShareWrapper& share) const;

// // added by Liang Zhao
// // convert constant arithmetic share to arithmetic gmw share (publicly known value)
// template <typename T>
// ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue(const ShareWrapper& share,
//                                                                bool as_boolean_gmw_share) const {
//   auto this_a = std::dynamic_pointer_cast<proto::ConstantArithmeticShare<T>>(*share);

//   auto this_wire_a = this_a->GetConstantArithmeticWire();
//   assert(this_wire_a);

//   auto constant_arithmetic_gmw_to_boolean_value_gate =
//       std::make_shared<proto::ArithmeticGmwConstantToBooleanGmwValueGate<T>>(this_wire_a,
//                                                                              as_boolean_gmw_share);
//   auto constant_arithmetic_gmw_to_boolean_value_gate_cast =
//       std::static_pointer_cast<Gate>(constant_arithmetic_gmw_to_boolean_value_gate);
//   share_->GetRegister()->RegisterNextGate(constant_arithmetic_gmw_to_boolean_value_gate_cast);

//   auto result = std::static_pointer_cast<Share>(
//       constant_arithmetic_gmw_to_boolean_value_gate->GetOutputAsBooleanGmwValue());

//   return ShareWrapper(result);
//   // return share;
// }

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue<std::uint8_t>(
//     const ShareWrapper& share, bool as_boolean_gmw_share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue<std::uint16_t>(
//     const ShareWrapper& share, bool as_boolean_gmw_share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue<std::uint32_t>(
//     const ShareWrapper& share, bool as_boolean_gmw_share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue<std::uint64_t>(
//     const ShareWrapper& share, bool as_boolean_gmw_share) const;

// template ShareWrapper ShareWrapper::ConstantArithmeticGmwToBooleanValue<__uint128_t>(
//     const ShareWrapper& share, bool as_boolean_gmw_share) const;

// // added by Liang Zhao
// // xor gate: when at least one input is publicly known
// ShareWrapper ShareWrapper::BooleanValueXor(const ShareWrapper& share,
//                                            const ShareWrapper& other) const {
//   // std::cout << "11" << std::endl;
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*share);
//   auto other_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

//   // other_a->GetBackend();
//   // std::cout << "22" << std::endl;

//   // convert each wire to publicly known
//   if (share->IsPubliclyKnownShare()) {
//     auto this_a_wires = this_a->GetWires();
//     for (std::size_t i = 0; i < this_a_wires.size(); i++) {
//       this_a_wires.at(i)->SetAsPubliclyKnownWire();
//     }
//   }

//   if (other->IsPubliclyKnownShare()) {
//     auto other_a_wires = other_a->GetWires();
//     for (std::size_t i = 0; i < other_a_wires.size(); i++) {
//       other_a_wires.at(i)->SetAsPubliclyKnownWire();
//     }
//   }

//   auto constant_boolean_xor_gate =
//       std::make_shared<proto::BooleanGmwValueMixXorGate>(this_a, other_a);
//   // std::cout << "33" << std::endl;

//   auto constant_boolean_xor_gate_cast =
//   std::static_pointer_cast<Gate>(constant_boolean_xor_gate);
//   share_->GetRegister()->RegisterNextGate(constant_boolean_xor_gate_cast);
//   // std::cout << "44" << std::endl;
//   ShareWrapper result =
//       std::static_pointer_cast<Share>(constant_boolean_xor_gate->GetOutputAsGmwShare());

//   // std::cout << "55" << std::endl;

//   return result;
// }

// // added by Liang Zhao
// // and gate: when at least one input is publicly known
// ShareWrapper ShareWrapper::BooleanValueAnd(const ShareWrapper& share,
//                                            const ShareWrapper& other) const {
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*share);
//   auto other_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*other);

//   auto constant_boolean_and_gate =
//       std::make_shared<proto::BooleanGmwValueMixAndGate>(this_a, other_a);
//   auto constant_boolean_and_gate_cast =
//   std::static_pointer_cast<Gate>(constant_boolean_and_gate);
//   share_->GetRegister()->RegisterNextGate(constant_boolean_and_gate_cast);
//   ShareWrapper result =
//       std::static_pointer_cast<Share>(constant_boolean_and_gate->GetOutputAsGmwShare());
//   return result;
// }

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::PrecomputationEdaBit() const {
//   // std::cout << "is unsigned" << std::is_unsigned<__uint128_t>::value << '\n';
//   // std::cout << "is unsigned_v" << std::is_unsigned_v<__uint128_t> << '\n';

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//   // std::cout << "create edaBit_gate" << std::endl;
//   auto edaBit_Gate =
//   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   ShareWrapper boolean_gmw_share_r =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // ShareWrapper operation_result = boolean_gmw_share_r ^ boolean_gmw_share_r;

//   return boolean_gmw_share_r;
// }

// template ShareWrapper ShareWrapper::PrecomputationEdaBit<std::uint64_t>() const;

// template ShareWrapper ShareWrapper::PrecomputationEdaBit<std::uint32_t>() const;

// added by Liang Zhao
template <typename T>
std::vector<ShareWrapper> ShareWrapper::EdaBit(std::size_t bit_size,
                                               std::size_t num_of_simd) const {
  //   share_->GetRegister()->SetAsPrecomputationMode();

  // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
  // std::cout << "create edaBit_gate" << std::endl;
  // auto edaBit_Gate = std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend(),
  //                                                                           bit_size,
  //                                                                           num_of_simd);
  // share_->GetRegister()->RegisterNextGate(edaBit_Gate);

  auto edaBit_Gate = share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::edaBitGate<T>>(
      share_->GetBackend(), bit_size, num_of_simd);

  ShareWrapper boolean_gmw_share_r =
      std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());

  ShareWrapper arithmetic_gmw_share_r =
      std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

  std::vector<SharePointer> share_r_of_each_bit_vector =
      edaBit_Gate->GetOutputAsArithmeticShareOfEachBit();

  std::vector<ShareWrapper> arithmetic_gmw_share_r_of_each_bit_vector;
  arithmetic_gmw_share_r_of_each_bit_vector.reserve(bit_size);
  for (std::size_t i = 0; i < bit_size; i++) {
    arithmetic_gmw_share_r_of_each_bit_vector.emplace_back(share_r_of_each_bit_vector[i]);
  }

  std::vector<ShareWrapper> result;
  result.reserve(2);
  result.emplace_back(boolean_gmw_share_r);
  result.emplace_back(arithmetic_gmw_share_r);

  //   share_->GetRegister()->UnsetPrecomputationMode();

  return result;
}

template std::vector<ShareWrapper> ShareWrapper::EdaBit<std::uint8_t>(
    std::size_t bit_size, std::size_t num_of_simd) const;

template std::vector<ShareWrapper> ShareWrapper::EdaBit<std::uint16_t>(
    std::size_t bit_size, std::size_t num_of_simd) const;

template std::vector<ShareWrapper> ShareWrapper::EdaBit<std::uint32_t>(
    std::size_t bit_size, std::size_t num_of_simd) const;

template std::vector<ShareWrapper> ShareWrapper::EdaBit<std::uint64_t>(
    std::size_t bit_size, std::size_t num_of_simd) const;

template std::vector<ShareWrapper> ShareWrapper::EdaBit<__uint128_t>(std::size_t bit_size,
                                                                     std::size_t num_of_simd) const;

// std::vector<ShareWrapper> ShareWrapper::ReshareBooleanGmw() const {
//   const std::size_t number_of_parties_{
//       share_->GetBackend().GetCommunicationLayer().GetNumberOfParties()};

//   std::vector<ShareWrapper> inputs_share_vector(number_of_parties_);

//   // reshare the new input
//   for (std::uint32_t party_id = 0; party_id < number_of_parties_; ++party_id) {
//     inputs_share_vector[party_id] =
//         share_->GetBackend().ReshareBooleanGmwShareAsInput(party_id, share_);
//   }

//   return inputs_share_vector;
// }

// // added by Liang Zhao
// // template <typename T>
// ShareWrapper ShareWrapper::SummationBooleanGMW(
//     const std::vector<ShareWrapper>& boolean_share_vector) const {
//   // std::cout << "SummationBooleanGMW" << std::endl;
//   const std::size_t number_of_parties_{
//       share_->GetBackend().GetCommunicationLayer().GetNumberOfParties()};

//   std::vector<SecureUnsignedInteger> summation_results;
//   summation_results.reserve(number_of_parties_ - 1);

//   SecureUnsignedInteger addition_result = SecureUnsignedInteger(boolean_share_vector[0]) +
//                                           SecureUnsignedInteger(boolean_share_vector[1]);
//   summation_results.emplace_back(addition_result);

//   // ??? need further test for three parites
//   for (std::uint8_t party_id = 2; party_id < number_of_parties_; ++party_id) {
//     SecureUnsignedInteger addition_result_tmp =
//         summation_results[party_id - 2] + SecureUnsignedInteger(boolean_share_vector[party_id]);
//     summation_results.emplace_back(addition_result_tmp);
//   }

//   return summation_results.back().Get();
// }

// ShareWrapper ShareWrapper::SummationArithmeticGMW(
//     const std::vector<ShareWrapper>& arithmetic_share_vector) const {
//   // std::cout << "SummationArithmeticGMW" << std::endl;
//   const std::size_t number_of_parties_{
//       share_->GetBackend().GetCommunicationLayer().GetNumberOfParties()};

//   std::vector<ShareWrapper> summation_results;
//   summation_results.reserve(number_of_parties_ - 1);

//   ShareWrapper addition_result = arithmetic_share_vector[0] + arithmetic_share_vector[1];
//   summation_results.emplace_back(addition_result);

//   // ??? need further test for three parites
//   for (std::uint8_t party_id = 2; party_id < number_of_parties_; ++party_id) {
//     ShareWrapper addition_result_tmp =
//         summation_results[party_id - 2] + arithmetic_share_vector[party_id];
//     summation_results.emplace_back(addition_result_tmp);
//   }

//   return summation_results.back();
// }

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw(
//     const std::vector<ShareWrapper>& boolean_share_vector) const {
//   std::size_t vector_size = boolean_share_vector.size();

//   std::vector<ShareWrapper> arithmetic_share_vector;
//   arithmetic_share_vector.reserve(vector_size);

//   for (uint8_t i = 0; i < vector_size; i++) {
//     arithmetic_share_vector.emplace_back(
//         boolean_share_vector[i].BooleanGmwBitsToArithmeticGmw<T>());
//   }

//   ShareWrapper arithmetic_share_sum = arithmetic_share_vector[0];
//   for (uint8_t i = 1; i < vector_size; i++) {
//     arithmetic_share_sum = arithmetic_share_sum + arithmetic_share_vector[i];
//   }

//   return arithmetic_share_sum;
// }

// template ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw<std::uint8_t>(
//     const std::vector<ShareWrapper>& boolean_share_vector) const;

// template ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw<std::uint16_t>(
//     const std::vector<ShareWrapper>& boolean_share_vector) const;

// template ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw<std::uint32_t>(
//     const std::vector<ShareWrapper>& boolean_share_vector) const;

// template ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw<std::uint64_t>(
//     const std::vector<ShareWrapper>& boolean_share_vector) const;
// template ShareWrapper ShareWrapper::SummationBooleanGmwBitToArithmeticGmw<__uint128_t>(
//     std::vector<ShareWrapper> boolean_share_vector) const;

// template <typename T>
// ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw() const {
//   // convert <share_>^B to <share_>^A using b2a_gate
//   auto boolean_gmw_to_arithmetic_gmw_gate =
//       std::make_shared<BooleanGmwBitsToArithmeticGmwGate<T>>(share_);
//   share_->GetRegister()->RegisterNextGate(boolean_gmw_to_arithmetic_gmw_gate);
//   ShareWrapper arithmetic_gmw_share_v =
//       ShareWrapper(boolean_gmw_to_arithmetic_gmw_gate->GetOutputAsShare());

//   return arithmetic_gmw_share_v;
// }

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint8_t>() const;
// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint16_t>() const;
// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint32_t>() const;
// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint64_t>() const;
// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<__uint128_t>() const;

// // added by Liang Zhao
// ShareWrapper ShareWrapper::ReconstructInLargerField(std::size_t output_owner) const {
//   // std::cout << "ShareWrapper::Out" << std::endl;
//   assert(share_);
//   auto& backend = share_->GetBackend();
//   SharePointer result{nullptr};
//   switch (share_->GetProtocol()) {
//     case MpcProtocol::kArithmeticGmw: {
//       switch (share_->GetBitLength()) {
//         case 8u: {
//           result = backend.ArithmeticGmwOutputInLargerField<std::uint8_t, std::uint16_t>(
//               share_, output_owner);
//           break;
//         }
//         case 16u: {
//           result = backend.ArithmeticGmwOutputInLargerField<std::uint16_t, std::uint32_t>(
//               share_, output_owner);
//           break;
//         }
//         case 32u: {
//           result = backend.ArithmeticGmwOutputInLargerField<std::uint32_t, std::uint64_t>(
//               share_, output_owner);
//           break;
//         }
//         case 64u: {
//           result = backend.ArithmeticGmwOutputInLargerField<std::uint64_t, __uint128_t>(
//               share_, output_owner);
//           break;
//         }

//         default: {
//           throw std::runtime_error(
//               fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength()));
//         }
//       }
//     } break;
//       // case MpcProtocol::kBooleanGmw: {
//       //   result = backend.BooleanGmwOutput(share_, output_owner);
//       //   // std::cout << "result->GetWires().size(): " << (result->GetWires().size()) <<
//       //   std::endl; break;
//       // }

//       //   // added by Liang Zhao
//       // case MpcProtocol::kBooleanConstant: {
//       //   // std::cout << "Out(), kBooleanConstant" << std::endl;
//       //   // std::cout << "share_->GetWires().size(): " << share_->GetWires().size() <<
//       //   std::endl; result = backend.ConstantBooleanGmwOutput(share_, output_owner); break;
//       // }

//       // // added by Liang Zhao
//       // case MpcProtocol::kBooleanMix: {
//       //   result = backend.BooleanGmwConstantMixOutput(share_, output_owner);
//       //   break;
//       // }

//       // case MpcProtocol::kBmr: {
//       //   result = backend.BmrOutput(share_, output_owner);
//       //   break;
//       // }
//     default: {
//       throw std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
//                                            static_cast<unsigned int>(share_->GetProtocol())));
//     }
//   }
//   return ShareWrapper(result);
// }

// // added by Liang Zhao
// // For example:
// // T: std::uint64_t, U: __uint128_t
// template <typename T, typename U>
// std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField(
//     const ShareWrapper& arithmetic_gmw_share_xi) const {
//   std::size_t size_of_T = sizeof(T);
//   std::size_t size_of_U = sizeof(U);
//   std::size_t bit_length_of_T = sizeof(T) * 8;
//   std::size_t bit_length_of_U = sizeof(U) * 8;

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <r>^A and <r>^B of length 64 bits
//   // std::cout << "create 64-bit edaBit_gate" << std::endl;
//   auto edaBit_Gate =
//   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   ShareWrapper boolean_gmw_share_ri =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   ShareWrapper arithmetic_gmw_share_ri =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // ------------------------------------------------------------

//   // // each party locally compute t^1_i = ([<x>^A_i + <r>^A_i]) < <r>^A_i
//   ShareWrapper arithmetic_value_xi_plus_ri =
//       ArithmeticValueAddition<T>(arithmetic_gmw_share_xi, arithmetic_gmw_share_ri);

//   bool return_boolean_value = false;
//   ShareWrapper arithmetic_gmw_share_t1 = ArithmeticValueLessThan<T>(
//       arithmetic_value_xi_plus_ri, arithmetic_gmw_share_ri, return_boolean_value);

//   // each party broadcast [<x>^A_i + <r>^A_i] to other parties and compute the sum of [<x>^A_i +
//   // <r>^A_i] in data type D (equivalent to reconstruct the value of <x>^A_i + <r>^A_i with carry
//   // bits)
//   // std::cout << "ReconstructInLargerField" << std::endl;
//   ShareWrapper arithmetic_value_sum_xi_plus_ri =
//       arithmetic_value_xi_plus_ri.ReconstructInLargerField();
//   std::vector<ShareWrapper> arithmetic_value_sum_xi_plus_ri_modular_reduction =
//       arithmetic_value_sum_xi_plus_ri.ArithmeticValueModularReductionWithWrap<U, T>(
//           arithmetic_value_sum_xi_plus_ri);
//   ShareWrapper arithmetic_value_x_plus_r = arithmetic_value_sum_xi_plus_ri_modular_reduction[0];
//   ShareWrapper arithmetic_value_t2 = arithmetic_value_sum_xi_plus_ri_modular_reduction[1];
//   arithmetic_value_t2.Get()->GetWires().at(0)->SetAsPubliclyKnownWire();
//   arithmetic_value_t2->SetAsPubliclyKnownShare();

//   // ------------------------------------------------------------

//   // std::cout << "boolean_gmw_share_ri.Split().size(): " << boolean_gmw_share_ri.Split().size()
//   //           << std::endl;

//   // parties compute sum of r^A_i as private input with addition circuits

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // parties first convert <r>^A_i to its boolean values r^B
//   ShareWrapper boolean_value_of_arithmetic_gmw_share_ri =
//       ArithmeticValueToBooleanValue<T, U>(arithmetic_gmw_share_ri);

//   // parties reshare r^B as private input
//   std::vector<ShareWrapper> boolean_reshare_of_arithmetic_gmw_share_ri =
//       boolean_value_of_arithmetic_gmw_share_ri.ReshareBooleanGmw();

//   // parties compute sum(r^B)
//   ShareWrapper summation_of_arithmetic_gmw_share_ri =
//       SummationBooleanGMW(boolean_reshare_of_arithmetic_gmw_share_ri);

//   // parties locally extract the carry bits
//   std::vector<ShareWrapper> summation_of_arithmetic_gmw_share_ri_split =
//       summation_of_arithmetic_gmw_share_ri.Split();
//   std::vector<ShareWrapper> summation_of_arithmetic_gmw_share_ri_carry_bits_vector(
//       summation_of_arithmetic_gmw_share_ri_split.cbegin() + bit_length_of_T,
//       summation_of_arithmetic_gmw_share_ri_split.cbegin() + bit_length_of_T + bit_length_of_T);
//   ShareWrapper boolean_gmw_share_t3 =
//       Concatenate(summation_of_arithmetic_gmw_share_ri_carry_bits_vector);

//   // can be improved with following method by assuming bit_length_t3
//   // ShareWrapper arithmetic_gmw_share_t3 = boolean_gmw_share_t3.BooleanGmwToArithmeticGmw();

//   // bit_size_t3 depends on the number of parties,
//   // for example, when bit_size_t3 = 8, the maximal number of allowed parties is 2^8=256
//   std::size_t num_of_parties = share_->GetBackend().GetCommunicationLayer().GetNumberOfParties();
//   std::size_t bit_size_t3 = ceil(log2(num_of_parties));
//   ShareWrapper arithmetic_gmw_share_t3 =
//       boolean_gmw_share_t3.BooleanGmwBitsToArithmeticGmw<T>(bit_size_t3);

//   arithmetic_value_x_plus_r->SetAsPubliclyKnownShare();

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // ------------------------------------------------------------

//   // <t4>^B = (x + r) < <r>^A
//   // solution 1:
//   ShareWrapper boolean_gmw_share_t4 = ~LTEQC<T>(arithmetic_gmw_share_ri,
//   arithmetic_value_x_plus_r); ShareWrapper arithmetic_gmw_share_t4 =
//   boolean_gmw_share_t4.BooleanGmwBitsToArithmeticGmw<T>();

//   // TODO: alternative solution: use other comparison protocol

//   // std::cout << "arithmetic_gmw_share_t1: "
//   //           << arithmetic_gmw_share_t1.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;
//   // std::cout << "arithmetic_value_t2: "
//   //           << arithmetic_value_t2.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   std::endl;
//   // std::cout << "arithmetic_gmw_share_t3: "
//   //           << arithmetic_gmw_share_t3.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;
//   // std::cout << "arithmetic_gmw_share_t4: "
//   //           << arithmetic_gmw_share_t4.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2 =
//       ArithmeticValueAddition<T>(arithmetic_gmw_share_t1, arithmetic_value_t2);

//   // ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3 =
//   //     ArithmeticValueSubtraction<T>(arithmetic_gmw_share_t1_plus_t2, arithmetic_gmw_share_t3);

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3 =
//       arithmetic_gmw_share_t1_plus_t2 - arithmetic_gmw_share_t3;

//   // ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4 =
//   //     ArithmeticValueSubtraction<T>(arithmetic_gmw_share_t1_plus_t2_minus_t3,
//   //     arithmetic_gmw_share_t4);

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4 =
//       arithmetic_gmw_share_t1_plus_t2_minus_t3 - arithmetic_gmw_share_t4;

//   // return arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4;

//   std::vector<ShareWrapper> result = {
//       arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4  // 0
//                                                          // ,
//                                                          // arithmetic_gmw_share_t1, //
//                                                          // 1 arithmetic_value_t2, // 2
//                                                          // arithmetic_gmw_share_t3, //
//                                                          // 3 arithmetic_gmw_share_t4, // 4
//                                                          // arithmetic_value_xi_plus_ri, //
//                                                          // 5 arithmetic_gmw_share_ri, // 6
//                                                          // boolean_gmw_share_t4, //
//                                                          // 7 arithmetic_value_x_plus_r, // 8
//                                                          // arithmetic_value_x_plus_r_minus_ri //
//                                                          // 9

//   };
//   return result;
// }

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<
//     std::uint8_t, std::uint16_t>(const ShareWrapper& arithmetic_share_vector) const;

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<
//     std::uint16_t, std::uint32_t>(const ShareWrapper& arithmetic_share_vector) const;

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<
//     std::uint32_t, std::uint64_t>(const ShareWrapper& arithmetic_share_vector) const;

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<
//     std::uint64_t, __uint128_t>(const ShareWrapper& arithmetic_share_vector) const;

// // added by Liang Zhao
// // For example:
// // T: std::uint32_t, U: std::uint64_t
// template <typename T, typename U>
// std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField(
//     const ShareWrapper& arithmetic_gmw_share_xi) const {
//   std::size_t size_of_T = sizeof(T);
//   std::size_t size_of_U = sizeof(U);
//   std::size_t bit_length_of_T = sizeof(T) * 8;
//   std::size_t bit_length_of_U = sizeof(U) * 8;

//   // generate edaBits: <r>^A and <r>^B of length 64 bits
//   // std::cout << "create 64-bit edaBit_gate" << std::endl;
//   auto edaBit_Gate =
//   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   ShareWrapper boolean_gmw_share_ri =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   ShareWrapper arithmetic_gmw_share_ri =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

//   // // each party locally compute t^1_i = ([<x>^A_i + <r>^A_i]) < <r>^A_i
//   ShareWrapper arithmetic_value_xi_plus_ri =
//       ArithmeticValueAddition<T>(arithmetic_gmw_share_xi, arithmetic_gmw_share_ri);

//   bool return_boolean_value = false;
//   ShareWrapper arithmetic_gmw_share_t1 = ArithmeticValueLessThan<T>(
//       arithmetic_value_xi_plus_ri, arithmetic_gmw_share_ri, return_boolean_value);

//   // convert t1 to field U
//   ShareWrapper arithmetic_gmw_share_t1_field_U =
//       ArithmeticValueFieldConversion<T, U>(arithmetic_gmw_share_t1);

//   // each party broadcast [<x>^A_i + <r>^A_i] to other parties and compute the sum of [<x>^A_i +
//   // <r>^A_i] in data type D (equivalent to reconstruct the value of <x>^A_i + <r>^A_i with carry
//   // bits)
//   // std::cout << "ReconstructInLargerField" << std::endl;
//   ShareWrapper arithmetic_value_sum_xi_plus_ri =
//       arithmetic_value_xi_plus_ri.ReconstructInLargerField();
//   std::vector<ShareWrapper> arithmetic_value_sum_xi_plus_ri_modular_reduction =
//       arithmetic_value_sum_xi_plus_ri.ArithmeticValueModularReductionWithWrap<U, T>(
//           arithmetic_value_sum_xi_plus_ri);
//   ShareWrapper arithmetic_value_x_plus_r = arithmetic_value_sum_xi_plus_ri_modular_reduction[0];
//   ShareWrapper arithmetic_value_t2 = arithmetic_value_sum_xi_plus_ri_modular_reduction[1];
//   arithmetic_value_t2.Get()->GetWires().at(0)->SetAsPubliclyKnownWire();
//   arithmetic_value_t2->SetAsPubliclyKnownShare();

//   // convert t2 to field U
//   ShareWrapper arithmetic_value_t2_field_U =
//       ArithmeticValueFieldConversion<T, U>(arithmetic_value_t2);
//   arithmetic_value_t2_field_U->SetAsPubliclyKnownShare();

//   // std::cout << "boolean_gmw_share_ri.Split().size(): " << boolean_gmw_share_ri.Split().size()
//   //           << std::endl;

//   // parties compute sum of r^A_i as private input with addtion circuits
//   // parties first convert <r>^A_i to its boolean values r^B
//   ShareWrapper boolean_value_of_arithmetic_gmw_share_ri =
//       ArithmeticValueToBooleanValue<T, U>(arithmetic_gmw_share_ri);

//   // parties reshare r^B as private input
//   std::vector<ShareWrapper> boolean_reshare_of_arithmetic_gmw_share_ri =
//       boolean_value_of_arithmetic_gmw_share_ri.ReshareBooleanGmw();

//   // parties compute sum(r^B)
//   ShareWrapper summation_of_arithmetic_gmw_share_ri =
//       SummationBooleanGMW(boolean_reshare_of_arithmetic_gmw_share_ri);

//   // parties locally extract the carry bits
//   std::vector<ShareWrapper> summation_of_arithmetic_gmw_share_ri_split =
//       summation_of_arithmetic_gmw_share_ri.Split();
//   std::vector<ShareWrapper> summation_of_arithmetic_gmw_share_ri_carry_bits_vector(
//       summation_of_arithmetic_gmw_share_ri_split.cbegin() + bit_length_of_T,
//       summation_of_arithmetic_gmw_share_ri_split.cbegin() + bit_length_of_T + bit_length_of_T);
//   ShareWrapper boolean_gmw_share_t3 =
//       Concatenate(summation_of_arithmetic_gmw_share_ri_carry_bits_vector);

//   // can be improved with following method by assuming bit_length_t3
//   // ShareWrapper arithmetic_gmw_share_t3 = boolean_gmw_share_t3.BooleanGmwToArithmeticGmw();

//   // bit_size_t3 depends on the number of parties,
//   // for example, when bit_size_t3 = 8, the maximal number of allowed parties is 2^8=256
//   std::size_t num_of_parties = share_->GetBackend().GetCommunicationLayer().GetNumberOfParties();
//   std::size_t bit_size_t3 = ceil(log2(num_of_parties));

//   // convert t3 to field U
//   ShareWrapper arithmetic_gmw_share_t3_field_U =
//       boolean_gmw_share_t3.BooleanGmwBitsToArithmeticGmw<U>(bit_size_t3);

//   arithmetic_value_x_plus_r->SetAsPubliclyKnownShare();
//   // TODO; improve later

//   ShareWrapper boolean_gmw_share_t4 = ~LTEQC<T>(arithmetic_gmw_share_ri,
//   arithmetic_value_x_plus_r);

//   // ShareWrapper arithmetic_gmw_share_t4 =
//   // boolean_gmw_share_t4.BooleanGmwBitsToArithmeticGmw<T>();

//   // convert t4 to field U
//   ShareWrapper arithmetic_gmw_share_t4_field_U =
//       boolean_gmw_share_t4.BooleanGmwBitsToArithmeticGmw<U>();

//   // std::cout << "arithmetic_gmw_share_t1: "
//   //           << arithmetic_gmw_share_t1.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;
//   // std::cout << "arithmetic_value_t2: "
//   //           << arithmetic_value_t2.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   std::endl;
//   // std::cout << "arithmetic_gmw_share_t3: "
//   //           << arithmetic_gmw_share_t3.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;
//   // std::cout << "arithmetic_gmw_share_t4: "
//   //           << arithmetic_gmw_share_t4.Get()->GetWires().at(0)->IsPubliclyKnownWire() <<
//   //           std::endl;

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2_field_U =
//       ArithmeticValueAddition<U>(arithmetic_gmw_share_t1_field_U, arithmetic_value_t2_field_U);

//   // ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3 =
//   //     ArithmeticValueSubtraction<T>(arithmetic_gmw_share_t1_plus_t2, arithmetic_gmw_share_t3);

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3_field_U =
//       arithmetic_gmw_share_t1_plus_t2_field_U - arithmetic_gmw_share_t3_field_U;

//   // ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4 =
//   //     ArithmeticValueSubtraction<T>(arithmetic_gmw_share_t1_plus_t2_minus_t3,
//   //     arithmetic_gmw_share_t4);

//   ShareWrapper arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4_field_U =
//       arithmetic_gmw_share_t1_plus_t2_minus_t3_field_U - arithmetic_gmw_share_t4_field_U;

//   // return arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4;

//   std::vector<ShareWrapper> result_field_U = {
//       arithmetic_gmw_share_t1_plus_t2_minus_t3_minus_t4_field_U, arithmetic_gmw_share_t1_field_U,
//       arithmetic_value_t2_field_U, arithmetic_gmw_share_t3_field_U,
//       arithmetic_gmw_share_t4_field_U};
//   return result_field_U;
// }

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<
//     std::uint8_t, std::uint16_t>(const ShareWrapper& arithmetic_share_vector) const;

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<
//     std::uint16_t, std::uint32_t>(const ShareWrapper& arithmetic_share_vector) const;

// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<
//     std::uint32_t, std::uint64_t>(const ShareWrapper& arithmetic_share_vector) const;

// // should support now
// template std::vector<ShareWrapper>
// ShareWrapper::SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField<
//     std::uint64_t, __uint128_t>(const ShareWrapper& arithmetic_share_vector) const;

// // added by Liang Zhao
// template <typename T, typename U>
// ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue(const ShareWrapper& share) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_to_boolean_value_gate =
//       std::make_shared<proto::ArithmeticGmwValueToBooleanGmwValueGate<T, U>>(this_wire_a);
//   auto arithmetic_value_to_boolean_value_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_to_boolean_value_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_to_boolean_value_gate_cast);

//   auto result = std::static_pointer_cast<Share>(
//       arithmetic_value_to_boolean_value_gate->GetOutputAsBooleanGmwValue());
//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue<std::uint8_t, std::uint16_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue<std::uint16_t, std::uint32_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue<std::uint32_t, std::uint64_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue<std::uint64_t, __uint128_t>(
//     const ShareWrapper& share) const;
// // template ShareWrapper ShareWrapper::ArithmeticValueToBooleanValue<__uint128_t>(
// //     ShareWrapper share) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::BooleanValueToArithmeticValue(const ShareWrapper& share) const {
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*share);
//   assert(this_a);
//   // auto this_wire_a = this_a->GetArithmeticWire();
//   // assert(this_wire_a);

//   auto boolean_value_to_arithmetic_value_gate =
//       std::make_shared<proto::BooleanGmwValueToArithmeticGmwValueGate<T>>(this_a);
//   auto boolean_value_to_arithmetic_value_gate_cast =
//       std::static_pointer_cast<Gate>(boolean_value_to_arithmetic_value_gate);
//   share_->GetRegister()->RegisterNextGate(boolean_value_to_arithmetic_value_gate_cast);

//   auto result = std::static_pointer_cast<Share>(
//       boolean_value_to_arithmetic_value_gate->GetOutputAsArithmeticGmwValue());
//   return ShareWrapper(result);
// }

// template ShareWrapper ShareWrapper::BooleanValueToArithmeticValue<std::uint8_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::BooleanValueToArithmeticValue<std::uint16_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::BooleanValueToArithmeticValue<std::uint32_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::BooleanValueToArithmeticValue<std::uint64_t>(
//     const ShareWrapper& share) const;

// template ShareWrapper ShareWrapper::BooleanValueToArithmeticValue<__uint128_t>(
//     const ShareWrapper& share) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw(std::size_t bit_size) const {
//   if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
//     auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(share_);
//     assert(this_a);
//     // auto this_wire_a = this_a->GetArithmeticWire();
//     // assert(this_wire_a);

//     auto boolean_gmw_bit_to_arithmetic_gmw_bit_gate =
//         std::make_shared<motion::BooleanGmwBitsToArithmeticGmwGate<T>>(this_a, bit_size);
//     auto boolean_gmw_bit_to_arithmetic_gmw_bit_gate_cast =
//         std::static_pointer_cast<Gate>(boolean_gmw_bit_to_arithmetic_gmw_bit_gate);
//     share_->GetRegister()->RegisterNextGate(boolean_gmw_bit_to_arithmetic_gmw_bit_gate_cast);

//     auto result = std::static_pointer_cast<Share>(
//         boolean_gmw_bit_to_arithmetic_gmw_bit_gate->GetOutputAsShare());
//     return ShareWrapper(result);
//   } else if (share_->GetProtocol() == MpcProtocol::kBooleanConstant) {
//     // std::vector<T> constant_one{T(1)};
//     // ShareWrapper constant_arithmetic_gmw_share_one =
//     //     share_->GetBackend().ConstantArithmeticGmwInput(constant_one);

//     // return constant_arithmetic_gmw_share_one;

//     auto constant_boolean_wire =
//         std::dynamic_pointer_cast<const encrypto::motion::proto::ConstantBooleanWire>(
//             share_->GetWires().at(0));

//     bool constant_boolean_wire_value = constant_boolean_wire->GetValues().Get(0);

//     if (constant_boolean_wire_value == true) {
//       std::vector<T> constant_one{T(1)};
//       ShareWrapper constant_arithmetic_gmw_share_one =
//           share_->GetBackend().ConstantArithmeticGmwInput(constant_one);

//       return constant_arithmetic_gmw_share_one;
//     } else {
//       std::vector<T> constant_zero{T(0)};
//       ShareWrapper constant_arithmetic_gmw_share_zero =
//           share_->GetBackend().ConstantArithmeticGmwInput(constant_zero);

//       return constant_arithmetic_gmw_share_zero;
//     }
//   }
// }

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint8_t>(
//     std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint16_t>(
//     std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint32_t>(
//     std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint64_t>(
//     std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<__uint128_t>(
//     std::size_t bit_size) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw(const ShareWrapper& boolean_gmw_share_a,
//                                                          std::size_t bit_size) const {
//   std::size_t num_of_simd = boolean_gmw_share_a->GetNumberOfSimdValues();

//   if (boolean_gmw_share_a->GetProtocol() == MpcProtocol::kBooleanGmw) {
//     auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_a);
//     assert(this_a);
//     // auto this_wire_a = this_a->GetArithmeticWire();
//     // assert(this_wire_a);

//     auto boolean_gmw_bit_to_arithmetic_gmw_bit_gate =
//         std::make_shared<motion::BooleanGmwBitsToArithmeticGmwGate<T>>(this_a, bit_size);
//     auto boolean_gmw_bit_to_arithmetic_gmw_bit_gate_cast =
//         std::static_pointer_cast<Gate>(boolean_gmw_bit_to_arithmetic_gmw_bit_gate);
//     share_->GetRegister()->RegisterNextGate(boolean_gmw_bit_to_arithmetic_gmw_bit_gate_cast);

//     auto result = std::static_pointer_cast<Share>(
//         boolean_gmw_bit_to_arithmetic_gmw_bit_gate->GetOutputAsShare());
//     return ShareWrapper(result);
//   }

//   else if (boolean_gmw_share_a->GetProtocol() == MpcProtocol::kBooleanConstant && bit_size == 1)
//   {
//     // std::cout << "boolean_gmw_share_a->GetProtocol() == MpcProtocol::kBooleanConstant" <<
//     // std::endl;

//     auto constant_boolean_wire =
//         std::dynamic_pointer_cast<const encrypto::motion::proto::ConstantBooleanWire>(
//             boolean_gmw_share_a->GetWires().at(0));

//     BitVector<> constant_boolean_wire_value = constant_boolean_wire->GetValues();
//     std::vector<T> constant_arithmetic_wire_value(num_of_simd);
//     // todo:: need test
//     for (std::size_t i = 0; i < num_of_simd; i++) {
//       if (constant_boolean_wire_value.Get(i)) {
//         // std::vector<T> constant_one{T(1)};
//         // ShareWrapper constant_arithmetic_gmw_share_one =
//         //     boolean_gmw_share_a->GetBackend().ConstantArithmeticGmwInput(constant_one);

//         // return constant_arithmetic_gmw_share_one;
//         constant_arithmetic_wire_value[i] = T(1);
//       } else {
//         // std::vector<T> constant_zero{T(0)};
//         // ShareWrapper constant_arithmetic_gmw_share_zero =
//         //     boolean_gmw_share_a->GetBackend().ConstantArithmeticGmwInput(constant_zero);

//         // return constant_arithmetic_gmw_share_zero;
//         constant_arithmetic_wire_value[i] = T(0);
//       }
//     }
//     ShareWrapper constant_arithmetic_gmw_share =
//         boolean_gmw_share_a->GetBackend().ConstantArithmeticGmwInput(
//             constant_arithmetic_wire_value);
//     return constant_arithmetic_gmw_share;
//   }
// }

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint8_t>(
//     const ShareWrapper& boolean_gmw_share_a, std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint16_t>(
//     const ShareWrapper& boolean_gmw_share_a, std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint32_t>(
//     const ShareWrapper& boolean_gmw_share_a, std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<std::uint64_t>(
//     const ShareWrapper& boolean_gmw_share_a, std::size_t bit_size) const;

// template ShareWrapper ShareWrapper::BooleanGmwBitsToArithmeticGmw<__uint128_t>(
//     const ShareWrapper& boolean_gmw_share_a, std::size_t bit_size) const;

// // added by Liang Zhao
// template <typename T, typename U>
// ShareWrapper ShareWrapper::ArithmeticGmwToBooleanGmwBit(
//     const ShareWrapper& arithmetic_gmw_share_a) const {
//   // locally bit decompose the arithmetic gmw share
//   ShareWrapper boolean_value_a = ArithmeticValueBitDecomposition<T>(arithmetic_gmw_share_a);

//   std::vector<ShareWrapper> boolean_value_a_vector = boolean_value_a.Split();

//   ShareWrapper boolean_gmw_share_lsb = boolean_value_a_vector.front();

//   ShareWrapper arithmetic_gmw_share_lsb =
//   BooleanGmwBitsToArithmeticGmw<U>(boolean_gmw_share_lsb);

//   return arithmetic_gmw_share_lsb;
// }

// // added by Liang Zhao
// ShareWrapper ShareWrapper::BooleanGmwBitDemux(const ShareWrapper& boolean_gmw_share_a) const {
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_a);
//   assert(this_a);
//   auto boolean_gmw_bit_demux_gate =
//       std::make_shared<proto::boolean_gmw::BooleanGmwBitDemuxGate>(this_a);
//   auto boolean_gmw_bit_demux_gate_cast =
//   std::static_pointer_cast<Gate>(boolean_gmw_bit_demux_gate);
//   share_->GetRegister()->RegisterNextGate(boolean_gmw_bit_demux_gate_cast);
//   auto result = std::static_pointer_cast<Share>(boolean_gmw_bit_demux_gate->GetOutputAsShare());
//   return ShareWrapper(result);
// }

// // added by Liang Zhao
// ShareWrapper ShareWrapper::BooleanValueExpand(const ShareWrapper& boolean_gmw_share_a) const {
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_a);
//   assert(this_a);
//   auto boolean_value_expand_gate = std::make_shared<proto::boolean_gmw::BooleanValueExpandGate>(
//       this_a, (this_a->GetWires().size()));
//   auto boolean_value_expand_gate_cast =
//   std::static_pointer_cast<Gate>(boolean_value_expand_gate);
//   share_->GetRegister()->RegisterNextGate(boolean_value_expand_gate_cast);
//   auto result = std::static_pointer_cast<Share>(boolean_value_expand_gate->GetOutputAsShare());
//   return ShareWrapper(result);
// }

// // added by Liang Zhao
// ShareWrapper ShareWrapper::BooleanValueReplicate(const ShareWrapper& boolean_gmw_share_a) const {
//   auto this_a = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_a);
//   assert(this_a);
//   auto boolean_value_replicate_gate =
//       std::make_shared<proto::boolean_gmw::BooleanValueReplicateGate>(this_a,
//                                                                       (this_a->GetWires().size()));
//   auto boolean_value_replicate_gate_cast =
//       std::static_pointer_cast<Gate>(boolean_value_replicate_gate);
//   share_->GetRegister()->RegisterNextGate(boolean_value_replicate_gate_cast);
//   auto result =
//   std::static_pointer_cast<Share>(boolean_value_replicate_gate->GetOutputAsShare()); return
//   ShareWrapper(result);
// }

// // added by Liang Zhao
// std::vector<ShareWrapper> ShareWrapper::BooleanValueExpandAndReplicateAndMultiply(
//     const std::vector<ShareWrapper>& boolean_gmw_share_a_vector) const {
//   std::size_t num_pairs = boolean_gmw_share_a_vector.size() / 2;

//   // std::cout << "num_pairs: " << num_pairs << std::endl;

//   std::vector<ShareWrapper> muliply_result_vector;
//   muliply_result_vector.reserve(num_pairs);

//   for (std::size_t i = 0; i < num_pairs; i++) {
//     ShareWrapper expand_tmp = BooleanValueExpand(boolean_gmw_share_a_vector[2 * i]);
//     ShareWrapper replicate_tmp = BooleanValueReplicate(boolean_gmw_share_a_vector[2 * i + 1]);

//     muliply_result_vector.emplace_back(expand_tmp & replicate_tmp);
//   }

//   return muliply_result_vector;
// }

// // added by Liang Zhao
// ShareWrapper ShareWrapper::Demux(const ShareWrapper& boolean_gmw_share) const {
//   std::vector<ShareWrapper> boolean_gmw_share_vector = boolean_gmw_share.Split();

//   // reverse the bit order to change endian type
//   // may change later
//   std::reverse(boolean_gmw_share_vector.begin(), boolean_gmw_share_vector.end());

//   std::vector<ShareWrapper> bit_demux_vector;
//   std::size_t num_of_input_bits = boolean_gmw_share_vector.size();
//   bit_demux_vector.reserve(num_of_input_bits);

//   // std::cout << "num_of_input_bits: " << num_of_input_bits << std::endl;
//   for (std::size_t i = 0; i < num_of_input_bits; i++) {
//     bit_demux_vector.emplace_back(BooleanGmwBitDemux(boolean_gmw_share_vector[i]));
//   }

//   std::size_t num_of_rounds = std::uint64_t(log2(num_of_input_bits));
//   // std::cout << "num_of_rounds: " << num_of_rounds << std::endl;

//   std::vector<ShareWrapper> multiply_result_round_1 =
//       BooleanValueExpandAndReplicateAndMultiply(bit_demux_vector);

//   std::vector<ShareWrapper> multiply_result_round_i = multiply_result_round_1;
//   std::vector<ShareWrapper> multiply_result_round_2 =
//       BooleanValueExpandAndReplicateAndMultiply(multiply_result_round_1);

//   for (std::size_t i = 1; i < num_of_rounds; i++) {
//     multiply_result_round_i = BooleanValueExpandAndReplicateAndMultiply(multiply_result_round_i);
//   }
//   assert(multiply_result_round_i.size() == 1);

//   ShareWrapper demux_result = Concatenate(multiply_result_round_i);
//   return demux_result;
// }

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::SecretShareLookupTable(
//     const std::vector<std::vector<bool>>& lookup_table,
//     const ShareWrapper& arithmetic_gmw_share_lookup_table_index) const {
//   assert(lookup_table[0].size() >= 1);

// //   share_->GetRegister()->SetAsPrecomputationMode();

//   // generate edaBits: <s>^A and <s>^B of length sizeof(T)*8
//   auto edaBit_Gate =
//   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   ShareWrapper boolean_gmw_share_s =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   ShareWrapper arithmetic_gmw_share_s =
//       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

//   // convert
//   ShareWrapper boolean_gmw_share_s_prime = Demux(boolean_gmw_share_s);

//   // generate the secret share lookup table
//   auto secret_share_lookup_table_gate =
//       std::make_shared<proto::SecretShareLookupTableGate>(*boolean_gmw_share_s_prime,
//       lookup_table);
//   share_->GetRegister()->RegisterNextGate(secret_share_lookup_table_gate);
//   ShareWrapper boolean_gmw_share_secret_share_lookup_table =
//       std::static_pointer_cast<Share>(secret_share_lookup_table_gate->GetOutputAsShare());

// //   share_->GetRegister()->UnsetPrecomputationMode();

//   // mask the private lookup table index
//   // <h> = <index> - <s>
//   // h: masked index that will be reconstructed as the index of the secret shared lookup table
//   // std::cout << "<h> = <index> - <s>" << std::endl;
//   ShareWrapper arithmetic_gmw_share_h =
//       arithmetic_gmw_share_lookup_table_index - arithmetic_gmw_share_s;
//   //  std::cout << "before out" << std::endl;
//   //  ShareWrapper arithmetic_gmw_share_h_out = arithmetic_gmw_share_h.Out();
//   //  std::cout << "after out" << std::endl;

//   //  std::vector<ShareWrapper> boolean_gmw_share_secret_share_lookup_table_vector =
//   //      boolean_gmw_share_secret_share_lookup_table.Split();

//   // ??? cause error, because h is not evaluated yet
//   // ??? need RecArithmeticShareAndSelectionFromVectorGate
//   //  T arithmetic_gmw_value_h = arithmetic_gmw_share_h_out.As<T>();

//   // get the secret shared lookup table in boolean gmw shares
//   //  std::cout << "get the secret shared lookup table in boolean gmw shares" << std::endl;
//   //  std::vector<ShareWrapper> boolean_gmw_share_vector_at_index_h = std::vector<ShareWrapper>(
//   //      boolean_gmw_share_secret_share_lookup_table_vector.begin() +
//   //          arithmetic_gmw_value_h * table_entry_bit_size,
//   //      boolean_gmw_share_secret_share_lookup_table_vector.begin() +
//   //          arithmetic_gmw_value_h * table_entry_bit_size + table_entry_bit_size);

//   // select lookup table with index h
//   // std::cout << "select lookup table with index h" << std::endl;
//   std::size_t num_of_rows_ = lookup_table.size();
//   std::size_t table_entry_bit_size = lookup_table[0].size();
//   ShareWrapper boolean_gmw_share_select =
//   ReconstructArithmeticGmwShareAndSelectFromShareVector<T>(
//       arithmetic_gmw_share_h, table_entry_bit_size, table_entry_bit_size,
//       boolean_gmw_share_secret_share_lookup_table);
//   return boolean_gmw_share_select;
// }

// template ShareWrapper ShareWrapper::SecretShareLookupTable<std::uint8_t>(
//     const std::vector<std::vector<bool>>& lookup_table,
//     const ShareWrapper& arithmetic_gmw_share_lookup_table_index) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::ReconstructArithmeticGmwShareAndSelectFromShareVector(
//     const ShareWrapper& share_index_head, std::size_t offset, std::size_t num_of_select_elements,
//     const ShareWrapper& share_vector_to_select) const {
//   auto arithmetic_gmw_share_index_head =
//       std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*share_index_head);
//   assert(arithmetic_gmw_share_index_head);
//   auto arithmetic_gmw_wire_index_head = arithmetic_gmw_share_index_head->GetArithmeticWire();

//   auto boolean_gmw_share =
//       std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*share_vector_to_select);

//   auto reconstruct_arithmetic_gmw_share_and_select_from_share_vector_gate = std::make_shared<
//       proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndSelectFromShareVectorGate<T>>(
//       arithmetic_gmw_wire_index_head, offset, num_of_select_elements, boolean_gmw_share);

//   auto reconstruct_arithmetic_gmw_share_and_select_from_share_vector_gate_cast =
//       std::static_pointer_cast<Gate>(
//           reconstruct_arithmetic_gmw_share_and_select_from_share_vector_gate);

//   share_->GetRegister()->RegisterNextGate(
//       reconstruct_arithmetic_gmw_share_and_select_from_share_vector_gate_cast);

//   ShareWrapper select_share_vector = std::static_pointer_cast<Share>(
//       reconstruct_arithmetic_gmw_share_and_select_from_share_vector_gate
//           ->GetSelectBooleanGmwShareAsBooleanShare());

//   return select_share_vector;
// }

// template ShareWrapper ShareWrapper::ReconstructArithmeticGmwShareAndSelectFromShareVector<
//     std::uint8_t>(const ShareWrapper& arithmetic_gmw_share_index_head, std::size_t offset,
//                   std::size_t num_of_select_elements,
//                   const ShareWrapper& boolean_gmw_share_vector_to_select) const;

// added by Liang Zhao
// reconstruct the arithmetic gmw share x and bit decompose it
template <typename T>
std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose(
    const ShareWrapper& arithmetic_share_x) const {
  auto arithmetic_gmw_share_x =
      std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_share_x);

  // create reconstruct and bit-decomposition gate for <2^a>^A + <r>^A
  auto rec_and_bit_decompose_gate =
      share_->GetRegister()
          ->template EmplaceGate<
              proto::arithmetic_gmw::ReconstructArithmeticGmwShareAndBitDecomposeGate<T>>(
              arithmetic_gmw_share_x);

  // share_->GetRegister()->RegisterNextGate(rec_and_bit_decompose_gate);
  ShareWrapper boolean_value_x =
      std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsBooleanGmwValue());
  ShareWrapper arithmetic_value_x =
      std::static_pointer_cast<Share>(rec_and_bit_decompose_gate->GetOutputAsArithmeticGmwValue());

  boolean_value_x->SetAsPubliclyKnownShare();
  arithmetic_value_x->SetAsPubliclyKnownShare();

  std::vector<ShareWrapper> result;
  result.reserve(2);
  result.emplace_back(boolean_value_x);
  result.emplace_back(arithmetic_value_x);

  return result;
}

template std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose<
    std::uint8_t>(const ShareWrapper& arithmetic_share_x) const;

template std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose<
    std::uint16_t>(const ShareWrapper& arithmetic_share_x) const;

template std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose<
    std::uint32_t>(const ShareWrapper& arithmetic_share_x) const;

template std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose<
    std::uint64_t>(const ShareWrapper& arithmetic_share_x) const;

template std::vector<ShareWrapper> ShareWrapper::ReconstructArithmeticGmwShareAndBitDecompose<
    __uint128_t>(const ShareWrapper& arithmetic_share_x) const;

// // backup file
// // added by Liang Zhao
// // basic idea, for example: for a 32-bit arithmetic share <a>^A, each party first locally
// // decompose their share into two 16-bit integers <a1>^A || <a2>^A, then using the wrap protocol
// // to compute the wrap of <a2>^A and add it to <a1>^A to get the correct digit decomposition
// // result
// template <typename XType, typename DigitType>
// std::vector<ShareWrapper> ShareWrapper::DigitDecomposition(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const {
//   assert(sizeof(XType) * 8 >= final_digit_bit_size_d);
//   assert(sizeof(DigitType) * 8 >= final_digit_bit_size_d);
//   assert(final_digit_bit_size_d > 1);

//   // std::size_t num_of_digits_after_decomposition_c = ceil(double(sizeof(T) * 8) /
//   // digit_bit_size_d);

//   std::size_t num_of_digits_after_decomposition_c = sizeof(XType) * 8 / final_digit_bit_size_d;
//   //   std::cout << "num_of_digits_after_decomposition_c: " <<
//   num_of_digits_after_decomposition_c
//   //             << std::endl;

//   std::vector<ShareWrapper> arithmetic_gmw_share_digit_decomposition_result_vector;
//   arithmetic_gmw_share_digit_decomposition_result_vector.reserve(
//       num_of_digits_after_decomposition_c);

//   // x is already the desired size of digit
//   if (num_of_digits_after_decomposition_c == 1) {
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(arithmetic_gmw_share_x);
//     return arithmetic_gmw_share_digit_decomposition_result_vector;
//   }

//   // decompose x recursively in two parts
//   else {
//     std::vector<ShareWrapper> arithmetic_gmw_value_local_digit_decomposition_vector =
//         ArithmeticValueDigitDecomposition<XType, DigitType>(arithmetic_gmw_share_x,
//                                                             sizeof(DigitType) * 8);

//     //     std::cout << "ArithmeticValueDigitDecomposition finish" << std::endl;

//     ShareWrapper arithmetic_gmw_value_high_bit_digit =
//         arithmetic_gmw_value_local_digit_decomposition_vector[1];
//     ShareWrapper arithmetic_gmw_share_low_bit_digit =
//         arithmetic_gmw_value_local_digit_decomposition_vector[0];
//     arithmetic_gmw_value_high_bit_digit->SetAsPubliclyUnknownShare();
//     arithmetic_gmw_share_low_bit_digit->SetAsPubliclyUnknownShare();

//     ShareWrapper arithmetic_gmw_share_lower_bit_digit_wrap =
//         SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<DigitType, XType>(
//             arithmetic_gmw_share_low_bit_digit)[0];

//     //     ShareWrapper arithmetic_gmw_share_high_bit_digit = ArithmeticValueAddition<DigitType>(
//     //         arithmetic_gmw_value_high_bit_digit, arithmetic_gmw_share_lower_bit_digit_wrap);

//     ShareWrapper arithmetic_gmw_share_high_bit_digit =
//         arithmetic_gmw_value_high_bit_digit + arithmetic_gmw_share_lower_bit_digit_wrap;

//     std::vector<ShareWrapper> arithmetic_gmw_share_high_bit_digit_decomposition_result_vector =
//         DigitDecomposition<DigitType>(arithmetic_gmw_share_high_bit_digit,
//         final_digit_bit_size_d);

//     std::vector<ShareWrapper> arithmetic_gmw_share_low_bit_digit_decomposition_result_vector =
//         DigitDecomposition<DigitType>(arithmetic_gmw_share_low_bit_digit,
//         final_digit_bit_size_d);

//     for (const auto& high_bit_digit_decomposition :
//          arithmetic_gmw_share_high_bit_digit_decomposition_result_vector) {
//       arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//           high_bit_digit_decomposition);
//     }

//     for (const auto& low_bit_digit_decomposition :
//          arithmetic_gmw_share_low_bit_digit_decomposition_result_vector) {
//       arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//           low_bit_digit_decomposition);
//     }
//     //     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//     //         arithmetic_gmw_share_lower_bit_digit_wrap);
//     //
//     //
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(arithmetic_gmw_value_high_bit_digit);

//     return arithmetic_gmw_share_digit_decomposition_result_vector;
//   }
// }

// // only for debug
// template <typename XType, typename DigitType>
// std::vector<ShareWrapper> ShareWrapper::DigitDecomposition(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const {
//   assert(sizeof(XType) * 8 >= final_digit_bit_size_d);
//   assert(sizeof(DigitType) * 8 >= final_digit_bit_size_d);
//   assert(final_digit_bit_size_d > 1);

//   // std::size_t num_of_digits_after_decomposition_c = ceil(double(sizeof(T) * 8) /
//   // digit_bit_size_d);

//   std::size_t num_of_digits_after_decomposition_c = sizeof(XType) * 8 / final_digit_bit_size_d;
//   //   std::cout << "num_of_digits_after_decomposition_c: " <<
//   num_of_digits_after_decomposition_c
//   //             << std::endl;

//   std::vector<ShareWrapper> arithmetic_gmw_share_digit_decomposition_result_vector;
//   arithmetic_gmw_share_digit_decomposition_result_vector.reserve(
//       num_of_digits_after_decomposition_c);

//   //   // x is already the desired size of digit
//   if (num_of_digits_after_decomposition_c == 1) {
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(arithmetic_gmw_share_x);
//     return arithmetic_gmw_share_digit_decomposition_result_vector;
//   }

//   // decompose x recursively in two parts
//   else {
//     std::vector<ShareWrapper> arithmetic_gmw_value_local_digit_decomposition_vector =
//         ArithmeticValueDigitDecomposition<XType, DigitType>(arithmetic_gmw_share_x,
//                                                             sizeof(DigitType) * 8);

//     //     std::cout << "ArithmeticValueDigitDecomposition finish" << std::endl;

//     ShareWrapper arithmetic_gmw_value_high_bit_digit =
//         arithmetic_gmw_value_local_digit_decomposition_vector[1];
//     ShareWrapper arithmetic_gmw_share_low_bit_digit =
//         arithmetic_gmw_value_local_digit_decomposition_vector[0];
//     arithmetic_gmw_value_high_bit_digit->SetAsPubliclyUnknownShare();
//     arithmetic_gmw_share_low_bit_digit->SetAsPubliclyUnknownShare();

//     std::vector<ShareWrapper> arithmetic_gmw_share_lower_bit_digit_wrap_vector =
//         SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField<DigitType, XType>(
//             arithmetic_gmw_share_low_bit_digit);

//     ShareWrapper arithmetic_gmw_share_lower_bit_digit_wrap =
//         arithmetic_gmw_share_lower_bit_digit_wrap_vector[0];

//     //     ShareWrapper arithmetic_gmw_share_high_bit_digit =
//     ArithmeticValueAddition<DigitType>(
//     //         arithmetic_gmw_value_high_bit_digit, arithmetic_gmw_share_lower_bit_digit_wrap);

//     ShareWrapper arithmetic_gmw_share_high_bit_digit =
//         arithmetic_gmw_value_high_bit_digit + arithmetic_gmw_share_lower_bit_digit_wrap;

//     //     std::vector<ShareWrapper>
//     arithmetic_gmw_share_high_bit_digit_decomposition_result_vector
//     //     =
//     //         DigitDecomposition<DigitType>(arithmetic_gmw_share_high_bit_digit,
//     //         final_digit_bit_size_d);

//     //     std::vector<ShareWrapper>
//     arithmetic_gmw_share_low_bit_digit_decomposition_result_vector
//     //     =
//     //         DigitDecomposition<DigitType>(arithmetic_gmw_share_low_bit_digit,
//     //         final_digit_bit_size_d);

//     //     for ( auto high_bit_digit_decomposition :
//     //          arithmetic_gmw_share_high_bit_digit_decomposition_result_vector) {
//     //       arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//     //           high_bit_digit_decomposition);
//     //     }

//     //     for ( auto low_bit_digit_decomposition :
//     //          arithmetic_gmw_share_low_bit_digit_decomposition_result_vector) {
//     //       arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//     //           low_bit_digit_decomposition);
//     //     }
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//         arithmetic_gmw_share_high_bit_digit);
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//         arithmetic_gmw_share_low_bit_digit);
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(
//         arithmetic_gmw_share_lower_bit_digit_wrap);
//     //
//     arithmetic_gmw_share_digit_decomposition_result_vector.emplace_back(arithmetic_gmw_value_high_bit_digit);

//     return arithmetic_gmw_share_digit_decomposition_result_vector;
//   }
// }

// template std::vector<ShareWrapper> ShareWrapper::DigitDecomposition<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const;

// template std::vector<ShareWrapper> ShareWrapper::DigitDecomposition<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const;

// template std::vector<ShareWrapper> ShareWrapper::DigitDecomposition<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const;

// template std::vector<ShareWrapper> ShareWrapper::DigitDecomposition<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const;

// // // support this after find errors
// template std::vector<ShareWrapper> ShareWrapper::DigitDecomposition<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t final_digit_bit_size_d) const;

// // added by Liang Zhao
// template <typename T, typename DigitType>
// std::vector<ShareWrapper> ShareWrapper::ArithmeticValueDigitDecomposition(
//     const ShareWrapper& arithmetic_value, std::size_t digit_bit_size_d) const {
//   auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(*arithmetic_value);
//   auto this_wire_a = this_a->GetArithmeticWire();
//   assert(this_wire_a);

//   auto arithmetic_value_digit_decomposition_gate =
//       std::make_shared<proto::ArithmeticGmwValueDigitDecompositionGate<T, DigitType>>(
//           this_wire_a, digit_bit_size_d);
//   auto arithmetic_value_digit_decomposition_gate_cast =
//       std::static_pointer_cast<Gate>(arithmetic_value_digit_decomposition_gate);
//   share_->GetRegister()->RegisterNextGate(arithmetic_value_digit_decomposition_gate_cast);

//   std::vector<motion::proto::arithmetic_gmw::SharePointer<DigitType>>
//       arithmetic_gmw_share_result_vector =
//           arithmetic_value_digit_decomposition_gate->GetOutputAsArithmeticGmwShareVector();
//   //  auto result = std::static_pointer_cast<Share>(
//   //      arithmetic_value_digit_decomposition_gate->GetOutputAsArithmeticGmwValue());
//   std::vector<ShareWrapper> arithmetic_gmw_sharewrapper_result_vector;
//   arithmetic_gmw_sharewrapper_result_vector.reserve(arithmetic_gmw_share_result_vector.size());
//   for (std::size_t i = 0; i < arithmetic_gmw_share_result_vector.size(); i++) {
//     arithmetic_gmw_sharewrapper_result_vector.emplace_back(
//         ShareWrapper(arithmetic_gmw_share_result_vector[i]));
//   }
//   return arithmetic_gmw_sharewrapper_result_vector;
// }

// template std::vector<ShareWrapper>
// ShareWrapper::ArithmeticValueDigitDecomposition<std::uint16_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_value, std::size_t digit_bit_size_d) const;

// template std::vector<ShareWrapper>
// ShareWrapper::ArithmeticValueDigitDecomposition<std::uint64_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_value, std::size_t digit_bit_size_d) const;

// template std::vector<ShareWrapper>
// ShareWrapper::ArithmeticValueDigitDecomposition<std::uint64_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_value, std::size_t digit_bit_size_d) const;

// template std::vector<ShareWrapper>
// ShareWrapper::ArithmeticValueDigitDecomposition<std::uint64_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_value, std::size_t digit_bit_size_d) const;

ShareWrapper ShareWrapper::BooleanValueSelection(const ShareWrapper& boolean_gmw_share_a,
                                                 const ShareWrapper& boolean_gmw_share_b,
                                                 const ShareWrapper& boolean_gmw_share_c) const {
  //        auto this_a =
  //        std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_a); auto
  //        this_b = std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_b);
  //        auto this_c =
  //        std::dynamic_pointer_cast<proto::boolean_gmw::Share>(*boolean_gmw_share_c);

  // auto boolean_value_selection_gate = std::make_shared<proto::BooleanValueSelectionGate>(
  //     *boolean_gmw_share_a, *boolean_gmw_share_b, *boolean_gmw_share_c);
  // auto boolean_value_selection_gate_cast =
  //     std::static_pointer_cast<Gate>(boolean_value_selection_gate);

  // share_->GetRegister()->RegisterNextGate(boolean_value_selection_gate_cast);

  // TODO:
  auto boolean_value_selection_gate =
      share_->GetRegister()->EmplaceGate<proto::BooleanValueSelectionGate>(
          *boolean_gmw_share_a, *boolean_gmw_share_b, *boolean_gmw_share_c);

  motion::proto::boolean_gmw::SharePointer boolean_gmw_share_selection_result =
      boolean_value_selection_gate->GetOutputAsBooleanShare();
  return ShareWrapper(boolean_gmw_share_selection_result);
}

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LTEQC(const ShareWrapper& arithmetic_share_x,
//                                  const ShareWrapper& arithmetic_value_R) const {
//   ShareWrapper boolean_gmw_share_x_less_than_R =
//       LTC_MRVW<T>(arithmetic_share_x, arithmetic_value_R)[0];
//   ShareWrapper boolean_gmw_share_x_equal_R = EQC<T>(arithmetic_share_x, arithmetic_value_R);

//   return boolean_gmw_share_x_less_than_R | boolean_gmw_share_x_equal_R;
// }

// template ShareWrapper ShareWrapper::LTEQC<std::uint8_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_value_R) const;

// template ShareWrapper ShareWrapper::LTEQC<std::uint16_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_value_R) const;

// template ShareWrapper ShareWrapper::LTEQC<std::uint32_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_value_R) const;

// template ShareWrapper ShareWrapper::LTEQC<std::uint64_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_value_R) const;

// template ShareWrapper ShareWrapper::LTEQC<__uint128_t>(
//     const ShareWrapper& arithmetic_share_x, const ShareWrapper& arithmetic_value_R) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LTEQS(const ShareWrapper& arithmetic_gmw_share_a,
//                                  const ShareWrapper& arithmetic_gmw_share_b) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();
//   ShareWrapper boolean_gmw_share_a_less_than_b =
//       LTS_MRVW<T>(arithmetic_gmw_share_a, arithmetic_gmw_share_b)[0];

//   //   std::vector<T> zero_T{0};
//   //   ShareWrapper constant_value_zero =
//   share_->GetBackend().ConstantArithmeticGmwInput(zero_T); ShareWrapper constant_value_zero =
//   CreateConstantArithmeticGmwInput<T>(T(0), num_of_simd);

//   ShareWrapper boolean_gmw_share_a_equal_b = EQ<T>(arithmetic_gmw_share_a, constant_value_zero);

//   return boolean_gmw_share_a_less_than_b | boolean_gmw_share_a_equal_b;
// }

// template ShareWrapper ShareWrapper::LTEQS<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LTEQS<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LTEQS<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LTEQS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template <typename XType, typename DigitType, typename OutputType>
// std::vector<ShareWrapper> ShareWrapper::MSNZB_SIRNN(
//     const ShareWrapper& arithmetic_gmw_share_x,
//     const std::vector<std::vector<bool>>& lookup_table_MSNZB, std::size_t input_bit_size_d) const
//     {
//   std::size_t lookup_table_output_bit_size = log2(input_bit_size_d) + 1;

//   // std::cout << "lookup_table_output_bit_size: " << lookup_table_output_bit_size << std::endl;

//   // each party get a digit decomposition of share x
//   // the share of digits will be used as the index the lookup table
//   std::vector<ShareWrapper> arithmetic_gmw_share_digit_decomposition_y_vector =
//       DigitDecomposition<XType>(arithmetic_gmw_share_x, input_bit_size_d);

//   // // generate the publicly known lookup table
//   // const std::vector<std::vector<bool>> lookup_table_MSNZB =
//   //     GenerateLookupTableMSNZB(input_bit_size_d);

//   std::size_t num_of_digits_c = arithmetic_gmw_share_digit_decomposition_y_vector.size();
//   std::vector<ShareWrapper> secret_share_lookup_table_vector;
//   secret_share_lookup_table_vector.reserve(num_of_digits_c);

//   std::vector<ShareWrapper> booleam_gmw_share_u_vector;
//   std::vector<ShareWrapper> booleam_gmw_share_v_vector;
//   std::vector<ShareWrapper> booleam_gmw_share_v_prime_vector;

//   // prepare the lookup table and secret share it for each digit y_i
//   // lookup table format: MSNZB(y_i) || c
//   // c = 0 if y_i !=0, c = 1 if y_i =0
//   // c is used as the choice index in the inverted binary tree
//   for (std::size_t i = 0; i < num_of_digits_c; i++) {
//     secret_share_lookup_table_vector.emplace_back(SecretShareLookupTable<DigitType>(
//         lookup_table_MSNZB, arithmetic_gmw_share_digit_decomposition_y_vector[i]));
//   }

//   // as we not only need the MSNZB(y_i) for each digit y_i, we also want to known i to compute
//   // the
//   // MSNZB (x), therefore, we merge i into the share of lookup table: lookup table format: i ||
//   // MSNZB(y_i) || c
//   std::vector<ShareWrapper> secret_share_lookup_table_with_index_vector;
//   secret_share_lookup_table_with_index_vector.reserve(num_of_digits_c);

//   // number of bit to store index i
//   std::size_t index_bit_size = ceil(log2(num_of_digits_c));

//   // std::cout << "num_of_digits_c: " << num_of_digits_c << std::endl;
//   // std::cout << "index_bit_size: " << index_bit_size << std::endl;

//   ShareWrapper constant_boolean_gmw_share_zero = secret_share_lookup_table_vector[0].Split()[0] ^
//                                                  secret_share_lookup_table_vector[0].Split()[0];
//   ShareWrapper constant_boolean_gmw_share_one = ~constant_boolean_gmw_share_zero;

//   for (std::size_t i = 0; i < num_of_digits_c; i++) {
//     // ===================================================================
//     // ??? index_bitvector_vector must equal to zero_bitvector_vector, otherwise OtExtension
//     error
//     // // BitVector to store index i
//     // std::vector<BitVector<>> index_bitvector_vector;

//     // // BitVector to store zero
//     // std::vector<BitVector<>> zero_bitvector_vector;

//     // // create boolean gmw share for index i (as boolean gmw share)
//     // for (std::size_t j = 0; j < index_bit_size; j++) {
//     //   index_bitvector_vector.emplace_back(1, (i >> j) & 1 == 1);
//     //   // zero_bitvector_vector.emplace_back(1, false);

//     //   // for debug
//     //   zero_bitvector_vector.emplace_back(1, (i >> j) & 1 == 0);
//     // }
//     // const bool set_as_constant_bitvector_value =
//     //     (arithmetic_gmw_share_x->GetWires().at(0)->GetWireId() %
//     //      share_->GetBackend().GetCommunicationLayer().GetNumberOfParties()) ==
//     //     share_->GetBackend().GetCommunicationLayer().GetMyId();
//     // ShareWrapper boolean_gmw_share_index;

//     // std::cout << "set_as_constant_bitvector_value: " << set_as_constant_bitvector_value
//     //           << std::endl;

//     // // only one party set the value of the BitVector
//     // // ??? the constant boolean gmw share seems cannot work together with boolean gmw share
//     // if (set_as_constant_bitvector_value) {
//     //   boolean_gmw_share_index =
//     //       share_->GetBackend().ConstantBooleanGmwInput(index_bitvector_vector);
//     // }
//     // // other parites only store it as zeros
//     // else {
//     //   boolean_gmw_share_index =
//     //   share_->GetBackend().ConstantBooleanGmwInput(zero_bitvector_vector);
//     // }

//     // =====================================================================
//     std::vector<ShareWrapper> boolean_gmw_share_index_vector;
//     for (std::size_t j = 0; j < index_bit_size; j++) {
//       if ((i >> j) & 1 == 1) {
//         boolean_gmw_share_index_vector.emplace_back(constant_boolean_gmw_share_one);
//       } else {
//         boolean_gmw_share_index_vector.emplace_back(constant_boolean_gmw_share_zero);
//       }
//     }

//     // =====================================================================

//     // split the secret share lookup table at i and insert i (as boolean gmw share) into it
//     std::vector<ShareWrapper> secret_share_lookup_table_i_vector =
//         secret_share_lookup_table_vector[i].Split();

//     // debug
//     // std::cout << "boolean_gmw_share_index.Split().size: " <<
//     // boolean_gmw_share_index.Split().size()
//     //           << std::endl;
//     // std::cout << "secret_share_lookup_table_i_vector.size: "
//     //           << secret_share_lookup_table_i_vector.size() << std::endl;
//     // std::vector<ShareWrapper> boolean_gmw_share_index_vector =
//     boolean_gmw_share_index.Split();

//     // ??? boolean_gmw_share_index_vector may cause error
//     secret_share_lookup_table_i_vector.insert(secret_share_lookup_table_i_vector.begin(),
//                                               boolean_gmw_share_index_vector.begin(),
//                                               boolean_gmw_share_index_vector.end());

//     ShareWrapper secret_share_lookup_table_i = Concatenate(secret_share_lookup_table_i_vector);
//     secret_share_lookup_table_with_index_vector.emplace_back(secret_share_lookup_table_i);
//   }

//   // use invert binary tree to select the lookup table of y_i, where i is the first index, that
//   // MSNZB (y_i) != 0
//   // ??? error, seems to be caused by secret_share_lookup_table_with_index_vector
//   ShareWrapper boolean_gmw_share_lookup_table_chosen =
//       InvertBinaryTreeSelection(secret_share_lookup_table_with_index_vector);

//   // only for debug, no problem any more
//   // ShareWrapper boolean_gmw_share_lookup_table_chosen =
//   //     InvertBinaryTreeSelection(secret_share_lookup_table_vector);

//   std::vector<ShareWrapper> boolean_gmw_share_lookup_table_chosen_vector =
//       boolean_gmw_share_lookup_table_chosen.Split();

//   std::vector<ShareWrapper> booleam_gmw_share_yi_index_vector =
//       std::vector(boolean_gmw_share_lookup_table_chosen_vector.begin(),
//                   boolean_gmw_share_lookup_table_chosen_vector.begin() + index_bit_size);
//   std::vector<ShareWrapper> booleam_gmw_share_yi_MSNZB_vector =
//       std::vector(boolean_gmw_share_lookup_table_chosen_vector.begin() + index_bit_size,
//                   boolean_gmw_share_lookup_table_chosen_vector.end() - 1);

//   // std::reverse(booleam_gmw_share_yi_index_vector.begin(),
//   // booleam_gmw_share_yi_index_vector.end());
//   // std::reverse(booleam_gmw_share_yi_MSNZB_vector.begin(),
//   // booleam_gmw_share_yi_MSNZB_vector.end());

//   // reverse the order of vector to format LSB...MSB
//   ShareWrapper booleam_gmw_share_yi_index = Concatenate(booleam_gmw_share_yi_index_vector);
//   ShareWrapper booleam_gmw_share_yi_MSNZB = Concatenate(booleam_gmw_share_yi_MSNZB_vector);

//   std::vector<OutputType> input_bit_size_d_vector{input_bit_size_d};

//   ShareWrapper constant_arithmetic_gmw_share_input_bit_size_d_vector =
//       share_->GetBackend().ConstantArithmeticGmwInput(input_bit_size_d_vector);
//   ShareWrapper arithmetic_gmw_share_yi_index =
//       booleam_gmw_share_yi_index.BooleanGmwBitsToArithmeticGmw<OutputType>(index_bit_size) *
//       constant_arithmetic_gmw_share_input_bit_size_d_vector;

//   ShareWrapper arithmetic_gmw_share_yi_MSNZB =
//       booleam_gmw_share_yi_MSNZB.BooleanGmwBitsToArithmeticGmw<OutputType>(
//           lookup_table_output_bit_size - 1);

//   ShareWrapper arithmetic_gmw_share_x_MSNZB =
//       arithmetic_gmw_share_yi_index + arithmetic_gmw_share_yi_MSNZB;

//   std::vector<ShareWrapper> result;
//   result.emplace_back(arithmetic_gmw_share_x_MSNZB);
//   result.emplace_back(arithmetic_gmw_share_yi_index);
//   result.emplace_back(arithmetic_gmw_share_yi_MSNZB);
//   result.emplace_back(boolean_gmw_share_lookup_table_chosen);
//   result.emplace_back(arithmetic_gmw_share_digit_decomposition_y_vector[0]);
//   result.emplace_back(secret_share_lookup_table_vector[0]);

//   return result;
// }

// template std::vector<ShareWrapper>
// ShareWrapper::MSNZB_SIRNN<std::uint64_t, std::uint8_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_x,
//     const std::vector<std::vector<bool>>& lookup_table_MSNZB, std::size_t input_bit_size_d)
//     const;

// added by Liang Zhao
ShareWrapper ShareWrapper::InvertBinaryTreeSelection(
    const std::vector<ShareWrapper>& share_y_c_vector) const {
  std::size_t num_of_leaf = share_y_c_vector.size();

  if (num_of_leaf == 1) {
    return share_y_c_vector[0];
  } else if (num_of_leaf == 2) {
    ShareWrapper x_left_leaf_c = share_y_c_vector[0].Split().back();
    ShareWrapper x_right_leaf_c = share_y_c_vector[1].Split().back();

    // compute the new leaf in the deeper layer
    ShareWrapper share_left_leaf_c_xor_right_leaf_c = x_left_leaf_c ^ x_right_leaf_c;

    ShareWrapper share_left_c_and_right_c = x_left_leaf_c & x_right_leaf_c;

    ShareWrapper share_left_selection_xor_right_selection =
        (x_left_leaf_c.XCOTMul(share_y_c_vector[0])) ^
        (x_right_leaf_c.XCOTMul(share_y_c_vector[1]));

    ShareWrapper x_new_leaf_y =
        (share_left_leaf_c_xor_right_leaf_c.XCOTMul(share_left_selection_xor_right_selection)) ^
        (share_left_c_and_right_c.XCOTMul(share_y_c_vector[0]));

    std::vector<ShareWrapper> x_new_leaf_y_c_vector = x_new_leaf_y.Split();

    ShareWrapper x_new_leaf_c = share_left_leaf_c_xor_right_leaf_c ^ share_left_c_and_right_c;

    // combine the new leaf y with the new choice bit c
    std::vector<ShareWrapper> x_new_leaf_vector(x_new_leaf_y_c_vector.begin(),
                                                x_new_leaf_y_c_vector.end() - 1);
    x_new_leaf_vector.emplace_back(x_new_leaf_c);

    return Concatenate(x_new_leaf_vector);

  }

  // recursive call
  else {
    ShareWrapper share_x_new_left_leaf = InvertBinaryTreeSelection(std::vector<ShareWrapper>(
        share_y_c_vector.begin(), share_y_c_vector.begin() + num_of_leaf / 2));
    ShareWrapper share_x_new_right_leaf = InvertBinaryTreeSelection(std::vector<ShareWrapper>(
        share_y_c_vector.begin() + num_of_leaf / 2, share_y_c_vector.end()));

    std::vector<ShareWrapper> share_new_leaf_vector;
    share_new_leaf_vector.reserve(2);
    share_new_leaf_vector.emplace_back(share_x_new_left_leaf);
    share_new_leaf_vector.emplace_back(share_x_new_right_leaf);

    ShareWrapper share_x_new_leaf = InvertBinaryTreeSelection(share_new_leaf_vector);
    return share_x_new_leaf;
  }
}

std::vector<ShareWrapper> ShareWrapper::InvertBinaryTreeSelection(
    const std::vector<ShareWrapper>& share_y_vector,
    const std::vector<ShareWrapper>& share_c_vector) const {
  std::size_t num_of_leaf = share_y_vector.size();

  if (num_of_leaf == 1) {
    std::vector<ShareWrapper> share_result_vector;
    share_result_vector.reserve(2);
    share_result_vector.emplace_back(share_y_vector[0]);
    share_result_vector.emplace_back(share_c_vector[0]);
    return share_result_vector;
  }

  else if (num_of_leaf == 2) {
    ShareWrapper left_leaf_c = share_c_vector[0];
    ShareWrapper right_leaf_c = share_c_vector[1];

    // compute the new leaf
    ShareWrapper share_left_leaf_c_xor_right_leaf_c = left_leaf_c ^ right_leaf_c;

    ShareWrapper share_left_selection_xor_right_selection =
        (left_leaf_c.XCOTMul(share_y_vector[0])) ^ (right_leaf_c.XCOTMul(share_y_vector[1]));

    ShareWrapper share_left_c_and_right_c = left_leaf_c & right_leaf_c;

    ShareWrapper new_leaf_y =
        (share_left_leaf_c_xor_right_leaf_c.XCOTMul(share_left_selection_xor_right_selection)) ^
        (share_left_c_and_right_c.XCOTMul(share_y_vector[0]));

    // std::vector<ShareWrapper> new_leaf_y_vector = new_leaf_y.Split();

    ShareWrapper new_leaf_c = share_left_leaf_c_xor_right_leaf_c ^ share_left_c_and_right_c;

    std::vector<ShareWrapper> share_new_leaf_vector;
    share_new_leaf_vector.reserve(2);
    share_new_leaf_vector.emplace_back(new_leaf_y);
    share_new_leaf_vector.emplace_back(new_leaf_c);
    return share_new_leaf_vector;

  }

  // recursive call
  else {
    std::vector<ShareWrapper> share_new_left_leaf_vector = InvertBinaryTreeSelection(
        std::vector<ShareWrapper>(share_y_vector.begin(), share_y_vector.begin() + num_of_leaf / 2),
        std::vector<ShareWrapper>(share_c_vector.begin(),
                                  share_c_vector.begin() + num_of_leaf / 2));
    std::vector<ShareWrapper> share_new_right_leaf_vector = InvertBinaryTreeSelection(
        std::vector<ShareWrapper>(share_y_vector.begin() + num_of_leaf / 2, share_y_vector.end()),
        std::vector<ShareWrapper>(share_c_vector.begin() + num_of_leaf / 2, share_c_vector.end()));

    std::vector<ShareWrapper> share_new_leaf_y_vector;
    share_new_leaf_y_vector.reserve(2);
    share_new_leaf_y_vector.emplace_back(share_new_left_leaf_vector[0]);
    share_new_leaf_y_vector.emplace_back(share_new_right_leaf_vector[0]);

    std::vector<ShareWrapper> share_new_leaf_c_vector;
    share_new_leaf_c_vector.reserve(2);
    share_new_leaf_c_vector.emplace_back(share_new_left_leaf_vector[1]);
    share_new_leaf_c_vector.emplace_back(share_new_right_leaf_vector[1]);

    std::vector<ShareWrapper> new_leaf_vector =
        InvertBinaryTreeSelection(share_new_leaf_y_vector, share_new_leaf_c_vector);
    return new_leaf_vector;
  }
}

// template <typename T>
// ShareWrapper ShareWrapper::MSNZB_ABZS(const ShareWrapper& arithmetic_gmw_share_x,
//                                       std::size_t l) const {
//   ShareWrapper boolean_gmw_share_x = arithmetic_gmw_share_x.Convert<MpcProtocol::kBooleanGmw>();

//   std::vector<ShareWrapper> boolean_gmw_share_x_vector = boolean_gmw_share_x.Split();
//   // std::size_t num_of_bits = boolean_gmw_share_x_vector.size();
//   std::size_t num_of_bits = l;

//   std::reverse(boolean_gmw_share_x_vector.begin(), boolean_gmw_share_x_vector.end());

//   ShareWrapper boolean_gmw_share_x_reverse_order = Concatenate(boolean_gmw_share_x_vector);

//   ShareWrapper boolean_gmw_share_x_pre_or = boolean_gmw_share_x_reverse_order.PreOrL();

//   ShareWrapper boolean_gmw_share_x_pre_or_invert = ~boolean_gmw_share_x_pre_or;

//   std::vector<ShareWrapper> boolean_gmw_share_x_pre_or_invert_vector =
//       boolean_gmw_share_x_pre_or_invert.Split();

//   std::vector<ShareWrapper> arithmetic_gmw_share_x_pre_or_vector;

//   for (std::size_t i = 0; i < num_of_bits; i++) {
//     arithmetic_gmw_share_x_pre_or_vector.emplace_back(
//         boolean_gmw_share_x_pre_or_invert_vector[i].BooleanGmwBitsToArithmeticGmw<T>());
//   }

//   ShareWrapper arithmetic_gmw_share_MSNZB = arithmetic_gmw_share_x_pre_or_vector[0];
//   for (std::size_t i = 1; i < num_of_bits; i++) {
//     arithmetic_gmw_share_MSNZB =
//         arithmetic_gmw_share_MSNZB + arithmetic_gmw_share_x_pre_or_vector[i];
//   }
//   return arithmetic_gmw_share_MSNZB;
// }

// template ShareWrapper ShareWrapper::MSNZB_ABZS<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::Pow2(ShareWrapper arithmetic_gmw_share_a, std::size_t m) const {
//   //   std::cout << "Pow2" << std::endl;
//   // std::size_t m = ceil(log2(l));
//   assert(m <= sizeof(T) * 8);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   if (arithmetic_gmw_share_a->GetProtocol() == MpcProtocol::kArithmeticConstant) {
//     // std::cout << "Pow2 constant" << std::endl;
//     auto constant_arithmetic_gmw_share_a =
//         std::dynamic_pointer_cast<proto::ConstantArithmeticShare<T>>(arithmetic_gmw_share_a.share_);

//     auto constant_arithmetic_gmw_wire_a =
//         constant_arithmetic_gmw_share_a->GetConstantArithmeticWire();

//     std::vector<T> constant_arithmetic_gmw_wire_value_a =
//         constant_arithmetic_gmw_wire_a->GetValues();

//     std::vector<T> constant_arithmetic_gmw_wire_value_pow2_a(num_of_simd);
//     for (std::size_t i = 0; i < num_of_simd; i++) {
//       constant_arithmetic_gmw_wire_value_pow2_a[i] = T(1)
//                                                      << constant_arithmetic_gmw_wire_value_a[i];
//     }

//     return CreateConstantArithmeticGmwInput<T>(constant_arithmetic_gmw_wire_value_pow2_a);

//   } else {
//     ShareWrapper boolean_gmw_share_a =
//     arithmetic_gmw_share_a.Convert<MpcProtocol::kBooleanGmw>();

//     std::vector<ShareWrapper> boolean_gmw_share_a_vector = boolean_gmw_share_a.Split();

//     std::vector<T> constant_one(num_of_simd, T(1));
//     ShareWrapper constant_arithmetic_gmw_share_one =
//         share_->GetBackend().ConstantArithmeticGmwInput(constant_one);

//     std::vector<ShareWrapper> arithmetic_gmw_share_v;
//     for (std::size_t i = 0; i < m; i++) {
//       // v = 2^(2^i) * <a_i>^A + 1 - <a_i>^A
//       std::vector<T> power_of_2_power_of_2_i(num_of_simd, T(1) << (T(1) << (i)));

//       ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_m =
//           share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_power_of_2_i);
//       ShareWrapper arithmetic_gmw_share_a_i =
//           boolean_gmw_share_a_vector[i].BooleanGmwBitsToArithmeticGmw<T>();

//       arithmetic_gmw_share_v.emplace_back(
//           constant_arithmetic_gmw_share_power_of_2_k_minus_m * arithmetic_gmw_share_a_i +
//           constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a_i);
//     }

//     ShareWrapper arithmetic_gmw_share_power_of_2_a = KMulL(arithmetic_gmw_share_v, 0, m - 1);
//     return arithmetic_gmw_share_power_of_2_a;
//   }
// }

// template ShareWrapper ShareWrapper::Pow2<std::uint8_t>(ShareWrapper arithmetic_gmw_share_a,
//                                                        std::size_t m) const;

// template ShareWrapper ShareWrapper::Pow2<std::uint16_t>(ShareWrapper arithmetic_gmw_share_a,
//                                                         std::size_t m) const;

// template ShareWrapper ShareWrapper::Pow2<std::uint32_t>(ShareWrapper arithmetic_gmw_share_a,
//                                                         std::size_t m) const;

// template ShareWrapper ShareWrapper::Pow2<std::uint64_t>(ShareWrapper arithmetic_gmw_share_a,
//                                                         std::size_t m) const;

// template ShareWrapper ShareWrapper::Pow2<__uint128_t>(ShareWrapper arithmetic_gmw_share_a,
//                                                       std::size_t m) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LTZ(const ShareWrapper& arithmetic_gmw_share_a) const {
//   std::size_t right_shift_bit = sizeof(T) * 8 - 1;
//   ShareWrapper arithmetic_gmw_share_a_right_shift =
//       LogicalRightShift_BitDecomposition<T>(arithmetic_gmw_share_a, right_shift_bit);

//   return arithmetic_gmw_share_a_right_shift;
// }

// template ShareWrapper ShareWrapper::LTZ<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a) const;

// template ShareWrapper ShareWrapper::LTZ<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a) const;

// template ShareWrapper ShareWrapper::LTZ<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a) const;

// template ShareWrapper ShareWrapper::LTZ<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a) const;

// template ShareWrapper ShareWrapper::LTZ<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::LT(const ShareWrapper& arithmetic_gmw_share_a,
//                               const ShareWrapper& arithmetic_gmw_share_b) const {
//   ShareWrapper arithmetic_gmw_share_a_minus_b = arithmetic_gmw_share_a - arithmetic_gmw_share_b;

//   ShareWrapper arithmetic_gmw_share_a_less_than_b = LTZ<T>(arithmetic_gmw_share_a_minus_b);

//   return arithmetic_gmw_share_a_less_than_b;
// }

// template ShareWrapper ShareWrapper::LT<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LT<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LT<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LT<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template ShareWrapper ShareWrapper::LT<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b)
//     const;

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::TruncPr(const ShareWrapper& arithmetic_gmw_share_x,
//                                                 std::size_t m) const {
//   std::size_t k = sizeof(T) * 8;
//   std::size_t num_of_simd = arithmetic_gmw_share_x->GetNumberOfSimdValues();

//   // as MSB(x) = 0, if m = k-1, the output is always 0
//   assert(m < k - 1);
//   assert(m != 0);

//   // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//   //   auto edaBit_Gate =
//   //   std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(share_->GetBackend());
//   //   share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//   //   ShareWrapper boolean_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//   //   ShareWrapper arithmetic_gmw_share_r =
//   //       std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());
//   std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
//   ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//   ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

//   // <c>^A = <x>^A + <r>^A
//   ShareWrapper arithmetic_gmw_share_c = arithmetic_gmw_share_x + arithmetic_gmw_share_r;

//   // open c
//   auto arithmetic_value_c = arithmetic_gmw_share_c.Out();
//   arithmetic_value_c->SetAsPubliclyKnownShare();

//   // 2^(k-m-1)
//   // std::cout << "2^(k-m-1)" << std::endl;
//   //  std::vector<T> power_of_2_k_minus_m_minus_1{T(1) << (k - m - 1)};
//   //  ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_m_minus_1 =
//   //      share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_k_minus_m_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_m_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (k - m - 1), num_of_simd);

//   ShareWrapper arithmetic_value_power_of_2_k_minus_m_minus_1 =
//       ConstantArithmeticGmwToArithmeticValue<T>(
//           constant_arithmetic_gmw_share_power_of_2_k_minus_m_minus_1);
//   arithmetic_value_power_of_2_k_minus_m_minus_1->SetAsPubliclyKnownShare();

//   // 2^(m)
//   // std::cout << "2^(m)" << std::endl;
//   //        std::vector<T> power_of_2_m{T(1) << (m)};
//   //        ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_m);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (m), num_of_simd);

//   ShareWrapper arithmetic_value_power_of_2_m =
//       ConstantArithmeticGmwToArithmeticValue<T>(constant_arithmetic_gmw_share_power_of_2_m);
//   arithmetic_value_power_of_2_m->SetAsPubliclyKnownShare();

//   // 2^(k-1)
//   // std::cout << "2^(k-1)" << std::endl;
//   //        std::vector<T> power_of_2_k_minus_1{T(1) << (k - 1)};
//   //        ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_1 =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_k_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_power_of_2_k_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (k - 1), num_of_simd);

//   ShareWrapper arithmetic_value_power_of_2_k_minus_1 =
//       ConstantArithmeticGmwToArithmeticValue<T>(constant_arithmetic_gmw_share_power_of_2_k_minus_1);
//   arithmetic_value_power_of_2_k_minus_1->SetAsPubliclyKnownShare();

//   // c/2^m
//   ShareWrapper arithmetic_value_c_div_power_of_2_m =
//       ArithmeticValueDivision<T>(arithmetic_value_c, arithmetic_value_power_of_2_m);

//   // c' = (c/2^m) mod 2^(k-m-1)
//   ShareWrapper arithmetic_value_c_prime = ArithmeticValueModularReduction<T>(
//       arithmetic_value_c_div_power_of_2_m, arithmetic_value_power_of_2_k_minus_m_minus_1);

//   // c/2^(k-1)
//   ShareWrapper arithmetic_value_c_div_power_of_2_k_minus_1 =
//       ArithmeticValueDivision<T>(arithmetic_value_c, arithmetic_value_power_of_2_k_minus_1);

//   // extract the boolean bit of c/2^(k-1)
//   ShareWrapper boolean_value_c_div_power_of_2_k_minus_1 =
//       ArithmeticValueBitDecomposition<T>(arithmetic_value_c_div_power_of_2_k_minus_1)
//           .Split()
//           .front();
//   boolean_value_c_div_power_of_2_k_minus_1->SetAsPubliclyKnownShare();

//   // extract the boolean bit of <r_(k-1)>^B
//   ShareWrapper boolean_gmw_share_r_k_minus_1 = boolean_gmw_share_r.Split().back();

//   // <b>^B = <r_(k-1)>^B ^ (c/2^(k-1))
//   ShareWrapper boolean_gmw_share_b =
//       BooleanValueXor(boolean_gmw_share_r_k_minus_1, boolean_value_c_div_power_of_2_k_minus_1);

//   // convert <b>^B to <b>^A
//   ShareWrapper arithmetic_gmw_share_b = boolean_gmw_share_b.BooleanGmwBitsToArithmeticGmw<T>();

//   // compute SUM_(i=m)^(k-2) <r_i>^B * 2^(i-m)

//   // first compute when i = m
//   //   std::vector<T> constant_power_of_2_m_minus_m{T(1) << (m - m)};
//   //   ShareWrapper constant_arithmetic_gmw_share_power_of_2_m_minus_m =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_power_of_2_m_minus_m);

//   // <r_m>^A
//   ShareWrapper arithmetic_gmw_share_rm =
//       boolean_gmw_share_r.Split().at(m).BooleanGmwBitsToArithmeticGmw<T>();

//   ShareWrapper arithmetic_gmw_share_sum_r_from_m_to_k_minus_2 = arithmetic_gmw_share_rm;

//   for (std::size_t i = m + 1; i <= k - 2; i++) {
//     // 2^(i-m)
//     //            std::vector<T> constant_power_of_2_i_minus_m{T(1) << (i - m)};
//     //            ShareWrapper constant_arithmetic_gmw_share_power_of_2_i_minus_m =
//     // share_->GetBackend().ConstantArithmeticGmwInput(constant_power_of_2_i_minus_m);
//     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i_minus_m =
//         CreateConstantArithmeticGmwInput<T>(T(1) << (i - m), num_of_simd);

//     // <r_i>^A
//     ShareWrapper arithmetic_gmw_share_ri =
//         boolean_gmw_share_r.Split().at(i).BooleanGmwBitsToArithmeticGmw<T>();

//     // <r_i>^A * 2^(i-m)
//     arithmetic_gmw_share_sum_r_from_m_to_k_minus_2 =
//         arithmetic_gmw_share_sum_r_from_m_to_k_minus_2 +
//         arithmetic_gmw_share_ri * constant_arithmetic_gmw_share_power_of_2_i_minus_m;
//   }

//   ShareWrapper arithmetic_gmw_share_trunc_pr =
//       ArithmeticValueSubtraction<T>(arithmetic_value_c_prime,
//                                     arithmetic_gmw_share_sum_r_from_m_to_k_minus_2) +
//       arithmetic_gmw_share_b * constant_arithmetic_gmw_share_power_of_2_k_minus_m_minus_1;

//   // // only for debugging
//   //   ShareWrapper arithmetic_gmw_share_trunc_pr =
//   //       arithmetic_gmw_share_b * constant_arithmetic_gmw_share_power_of_2_k_minus_m_minus_1;

//   //   // for debug
//   //   ShareWrapper arithmetic_gmw_share_trunc_pr = ArithmeticValueSubtraction<T>(
//   //       arithmetic_value_c_prime, arithmetic_gmw_share_sum_r_from_m_to_k_minus_2);

//   std::vector<ShareWrapper> result;
//   result.reserve(1);
//   result.emplace_back(arithmetic_gmw_share_trunc_pr);

//   //   // only for debugging
//   //     result.emplace_back(arithmetic_gmw_share_r);
//   //     result.emplace_back(arithmetic_value_c);
//   //     result.emplace_back(arithmetic_value_c_div_power_of_2_m);
//   //     result.emplace_back(arithmetic_value_c_prime);
//   //     result.emplace_back(arithmetic_value_c_div_power_of_2_k_minus_1);
//   //     result.emplace_back(boolean_value_c_div_power_of_2_k_minus_1);
//   //     result.emplace_back(boolean_gmw_share_r_k_minus_1);
//   //     result.emplace_back(arithmetic_gmw_share_b);
//   //     result.emplace_back(arithmetic_gmw_share_sum_r_from_m_to_k_minus_2);

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::TruncPr<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

// template std::vector<ShareWrapper> ShareWrapper::TruncPr<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

// template std::vector<ShareWrapper> ShareWrapper::TruncPr<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

// template std::vector<ShareWrapper> ShareWrapper::TruncPr<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

// template std::vector<ShareWrapper> ShareWrapper::TruncPr<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

// template <typename T>
// ShareWrapper ShareWrapper::ObliviousTrunc(const ShareWrapper& arithmetic_gmw_share_x,
//                                           const ShareWrapper& arithmetic_gmw_share_m,
//                                           std::size_t M) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_x->GetNumberOfSimdValues();
//   // <2^(M-m)>^A
//   //   std::vector<T> constant_M{T(M)};
//   //   ShareWrapper constant_arithmetic_gmw_share_M =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_M);
//   ShareWrapper constant_arithmetic_gmw_share_M =
//       CreateConstantArithmeticGmwInput(T(M), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_M_minus_m =
//       constant_arithmetic_gmw_share_M - arithmetic_gmw_share_m;
//   ShareWrapper arithmetic_gmw_share_pow2_M_minus_m = Pow2<T>(arithmetic_gmw_share_M_minus_m);

//   // <2^(M-m)>^A * <x>^A
//   ShareWrapper arithmetic_gmw_share_pow2_M_minus_m_mul_x =
//       arithmetic_gmw_share_pow2_M_minus_m * arithmetic_gmw_share_x;

//   // <y>^A = Turnc(<2^(M-m)*<x>>^A, M)
//   ShareWrapper arithmetic_gmw_share_y =
//       LogicalRightShift_BitDecomposition<T>(arithmetic_gmw_share_pow2_M_minus_m_mul_x, M);

//   // return arithmetic_gmw_share_y;
//   return arithmetic_gmw_share_y;
// }

// template ShareWrapper ShareWrapper::ObliviousTrunc<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_m,
//     std::size_t M) const;

// template ShareWrapper ShareWrapper::ObliviousTrunc<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_m,
//     std::size_t M) const;

// template ShareWrapper ShareWrapper::ObliviousTrunc<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_m,
//     std::size_t M) const;

// template ShareWrapper ShareWrapper::ObliviousTrunc<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_m,
//     std::size_t M) const;

// template ShareWrapper ShareWrapper::ObliviousTrunc<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_m,
//     std::size_t M) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::B2U(const ShareWrapper& arithmetic_gmw_share_a,
//                                             std::size_t l, bool return_boolean_share_vector,
//                                             bool return_pow2_a) const {
//   assert(l > 0);
//   assert(l <= sizeof(T) * 8);

//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   if (return_boolean_share_vector) {
//     ShareWrapper arithmetic_pow2_a = Pow2<T>(arithmetic_gmw_share_a, l);

//     // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//     std::vector<ShareWrapper> edaBit_vector = EdaBit<T>(sizeof(T) * 8, num_of_simd);
//     ShareWrapper boolean_gmw_share_r = edaBit_vector.at(0);
//     ShareWrapper arithmetic_gmw_share_r = edaBit_vector.at(1);

//     ShareWrapper arithmetic_share_pow2_a_plus_r = arithmetic_pow2_a + arithmetic_gmw_share_r;

//     std::vector<ShareWrapper> reconstruct_and_bit_decompose_vector =
//         ReconstructArithmeticGmwShareAndBitDecompose<T>(arithmetic_share_pow2_a_plus_r);
//     ShareWrapper boolean_value_pow2_a_plus_r = reconstruct_and_bit_decompose_vector[0];
//     ShareWrapper arithmetic_value_pow2_a_plus_r = reconstruct_and_bit_decompose_vector[1];

//     std::vector<ShareWrapper> boolean_value_pow2_a_plus_r_vector =
//         boolean_value_pow2_a_plus_r.Split();

//     std::vector<ShareWrapper> boolean_gmw_share_r_vector = boolean_gmw_share_r.Split();

//     std::vector<ShareWrapper> boolean_gmw_share_x_vector;
//     boolean_gmw_share_x_vector.reserve(l);

//     // // ? use SIMD to parallelize, not necessary as BooleanValueXor is a local computation
//     for (std::size_t i = 0; i < l; i++) {
//       boolean_gmw_share_x_vector.emplace_back(
//           BooleanValueXor(boolean_gmw_share_r_vector[i], boolean_value_pow2_a_plus_r_vector[i]));
//     }

//     ShareWrapper boolean_gmw_share_x = Concatenate(boolean_gmw_share_x_vector);

//     ShareWrapper boolean_gmw_share_y = PreOrL(boolean_gmw_share_x);

//     std::vector<ShareWrapper> boolean_gmw_share_y_vector = boolean_gmw_share_y.Split();

//     std::vector<ShareWrapper> boolean_gmw_share_a_vector;

//     if (!return_pow2_a) {
//       boolean_gmw_share_a_vector.reserve(l);
//       for (std::size_t i = 0; i < l; i++) {
//         boolean_gmw_share_a_vector.emplace_back(~boolean_gmw_share_y_vector[i]);
//       }
//     } else {
//       boolean_gmw_share_a_vector.reserve(l + 1);
//       for (std::size_t i = 0; i < l; i++) {
//         boolean_gmw_share_a_vector.emplace_back(~boolean_gmw_share_y_vector[i]);
//       }

//       // add <2^a>^A to the output
//       boolean_gmw_share_a_vector.emplace_back(arithmetic_pow2_a);
//     }

//     // std::vector<ShareWrapper> result;
//     // result.reserve(2);
//     // result.emplace_back(Concatenate(boolean_gmw_share_a_vector));
//     // result.emplace_back(arithmetic_pow2_a);

//     return boolean_gmw_share_a_vector;
//     // return boolean_value_pow2_a_plus_r_vector;
//     // return result;
//   }

//   // TODO: compare the benchmark when directly convert boolean_gmw_share_a_vector to arithmetic
//   // gmw share
//   else {
//     ShareWrapper arithmetic_pow2_a = Pow2<T>(arithmetic_gmw_share_a, l);

//     // share_->GetRegister()->SetAsPrecomputationMode();
//     // generate edaBits: <r>^A and <r>^B of length sizeof(T)*8
//     auto edaBit_Gate = std::make_shared<proto::arithmetic_gmw::edaBitGate<T>>(
//         share_->GetBackend(), sizeof(T) * 8, num_of_simd);
//     share_->GetRegister()->RegisterNextGate(edaBit_Gate);
//     ShareWrapper boolean_gmw_share_r =
//         std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsBooleanShare());
//     ShareWrapper arithmetic_gmw_share_r =
//         std::static_pointer_cast<Share>(edaBit_Gate->GetOutputAsArithmeticShare());

//     // arithmetic gmw share of each bit in  <r>^B
//     std::vector<SharePointer> share_r_of_each_bit_vector =
//         edaBit_Gate->GetOutputAsArithmeticShareOfEachBit();
//     std::vector<ShareWrapper> arithmetic_gmw_share_r_of_each_bit_vector;
//     arithmetic_gmw_share_r_of_each_bit_vector.reserve(l);
//     for (std::size_t i = 0; i < l; i++) {
//       arithmetic_gmw_share_r_of_each_bit_vector.emplace_back(share_r_of_each_bit_vector[i]);
//     }
//     // share_->GetRegister()->UnsetPrecomputationMode();

//     // <c>^A = 2^a + <r>^A
//     ShareWrapper arithmetic_share_pow2_a_plus_r = arithmetic_pow2_a + arithmetic_gmw_share_r;

//     std::vector<ShareWrapper> reconstruct_and_bit_decompose_vector =
//         ReconstructArithmeticGmwShareAndBitDecompose<T>(arithmetic_share_pow2_a_plus_r);
//     ShareWrapper boolean_value_pow2_a_plus_r = reconstruct_and_bit_decompose_vector[0];
//     ShareWrapper arithmetic_value_pow2_a_plus_r = reconstruct_and_bit_decompose_vector[1];

//     std::vector<ShareWrapper> boolean_value_pow2_a_plus_r_vector =
//         boolean_value_pow2_a_plus_r.Split();

//     std::vector<ShareWrapper> arithmetic_value_pow2_a_plus_r_vector;
//     arithmetic_value_pow2_a_plus_r_vector.reserve(l);

//     for (std::size_t i = 0; i < l; i++) {
//       ShareWrapper arithmetic_value_pow2_a_plus_r =
//           BooleanValueToArithmeticValue<T>(boolean_value_pow2_a_plus_r_vector[i]);
//       arithmetic_value_pow2_a_plus_r_vector.emplace_back(arithmetic_value_pow2_a_plus_r);
//     }

//     // std::vector<T> constant_one{T(1)};
//     // ShareWrapper constant_arithmetic_gmw_share_one =
//     //     share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//     ShareWrapper constant_arithmetic_gmw_share_one =
//         CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//     // std::vector<T> constant_two{T(2)};
//     // ShareWrapper constant_arithmetic_gmw_share_two =
//     //     share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//     ShareWrapper constant_arithmetic_gmw_share_two =
//         CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//     std::vector<ShareWrapper> arithmetic_gmw_share_x_vector;
//     arithmetic_gmw_share_x_vector.reserve(l);

//     // <xi>^A = ci + <ri>^A - 2 * ci * <ri>^A
//     for (std::size_t i = 0; i < l; i++) {
//       // ci + <ri>^A
//       ShareWrapper arithmetic_gmw_share_ci_plus_ri = ArithmeticValueAddition<T>(
//           arithmetic_gmw_share_r_of_each_bit_vector[i],
//           arithmetic_value_pow2_a_plus_r_vector[i]);

//       // ci * <ri>^A
//       ShareWrapper arithmetic_gmw_share_ci_mul_ri = ArithmeticValueMultiplication<T>(
//           arithmetic_gmw_share_r_of_each_bit_vector[i],
//           arithmetic_value_pow2_a_plus_r_vector[i]);

//       // 2 * ci * <ri>^A
//       ShareWrapper arithmetic_gmw_share_ci_mul_ri_mul_two =
//           constant_arithmetic_gmw_share_two * arithmetic_gmw_share_ci_mul_ri;

//       // <xi>^A = ci + <ri>^A - 2 * ci * <ri>^A
//       ShareWrapper arithmetic_gmw_share_ci_plus_ri_minus_ci_mul_ri_mul_two =
//           ArithmeticValueSubtraction<T>(arithmetic_gmw_share_ci_plus_ri,
//                                         arithmetic_gmw_share_ci_mul_ri_mul_two);
//       arithmetic_gmw_share_x_vector.emplace_back(
//           arithmetic_gmw_share_ci_plus_ri_minus_ci_mul_ri_mul_two);
//     }

//     std::vector<ShareWrapper> arithmetic_gmw_share_y_vector;
//     std::vector<ShareWrapper> arithmetic_gmw_share_a_vector;
//     arithmetic_gmw_share_y_vector.resize(l);

//     if (!return_pow2_a) {
//       arithmetic_gmw_share_a_vector.resize(l);
//     } else {
//       arithmetic_gmw_share_a_vector.resize(l + 1);
//     }

//     arithmetic_gmw_share_y_vector[0] = arithmetic_gmw_share_x_vector[0];
//     arithmetic_gmw_share_a_vector[0] =
//         constant_arithmetic_gmw_share_one - arithmetic_gmw_share_y_vector[0];
//     // ? cannot use SIMD to parallelize as it is a sequential computation
//     for (std::size_t i = 1; i < l; i++) {
//       // yi = x_(i) + y_(i-1) - x_(i) * y_(i-1)
//       // equivalent to y0, ..., y_(l-1) = PreOr(x0, ..., x_(l-1))
//       arithmetic_gmw_share_y_vector[i] =
//           arithmetic_gmw_share_y_vector[i - 1] + arithmetic_gmw_share_x_vector[i] -
//           arithmetic_gmw_share_y_vector[i - 1] * arithmetic_gmw_share_x_vector[i];
//     }

//     // <ai>^A = 1 - <yi>^A
//     for (std::size_t i = 0; i < l; i++) {
//       arithmetic_gmw_share_a_vector[i] =
//           constant_arithmetic_gmw_share_one - arithmetic_gmw_share_y_vector[i];
//     }

//     if (return_pow2_a) {
//       // add <2^a>^A to the output
//       arithmetic_gmw_share_a_vector[l] = (arithmetic_pow2_a);
//     }

//     return arithmetic_gmw_share_a_vector;

//     // std::vector<ShareWrapper> result;
//     // result.reserve(2);
//     // result.emplace_back(Concatenate(arithmetic_gmw_share_a_vector));
//     // result.emplace_back(arithmetic_pow2_a);

//     // return boolean_gmw_share_a_vector;
//     // return boolean_value_pow2_a_plus_r_vector;
//     // return result;

//     // only for debugging
//     // return arithmetic_gmw_share_x_vector;
//     // return arithmetic_gmw_share_y_vector;
//     // return arithmetic_gmw_share_r_of_each_bit_vector;
//   }
// }

// template std::vector<ShareWrapper> ShareWrapper::B2U<std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t l, bool return_boolean_share_vector,
//     bool return_pow2_a) const;

// template std::vector<ShareWrapper> ShareWrapper::B2U<std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t l, bool return_boolean_share_vector,
//     bool return_pow2_a) const;

// template std::vector<ShareWrapper> ShareWrapper::B2U<std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t l, bool return_boolean_share_vector,
//     bool return_pow2_a) const;

// template std::vector<ShareWrapper> ShareWrapper::B2U<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t l, bool return_boolean_share_vector,
//     bool return_pow2_a) const;

// template std::vector<ShareWrapper> ShareWrapper::B2U<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t l, bool return_boolean_share_vector,
//     bool return_pow2_a) const;

// added by Liang Zhao
std::vector<ShareWrapper> ShareWrapper::CreateFloatingPointShareVector(
    const ShareWrapper& arithmetic_gmw_share_v, const ShareWrapper& arithmetic_gmw_share_p,
    const ShareWrapper& arithmetic_gmw_share_z, const ShareWrapper& arithmetic_gmw_share_s,
    std::size_t l, std::size_t k) const {
  std::vector<ShareWrapper> floating_point_vector;
  //   floating_point_vector.reserve(4);
  floating_point_vector.emplace_back(arithmetic_gmw_share_v);
  floating_point_vector.emplace_back(arithmetic_gmw_share_p);
  floating_point_vector.emplace_back(arithmetic_gmw_share_z);
  floating_point_vector.emplace_back(arithmetic_gmw_share_s);

  return floating_point_vector;
}

// added by Liang Zhao
template <typename T>
std::vector<ShareWrapper> ShareWrapper::CreateConstantFloatingPointShareVector(
    T v, T p, T z, T s, std::size_t l, std::size_t k, std::size_t num_of_simd) const {
  std::vector<ShareWrapper> floating_point_vector;
  //   std::cout << "CreateConstantFloatingPointShareVector: " << std::endl;

  //   std::cout << "v: " << std::int64_t(v) << std::endl;
  //   std::cout << "p: " << std::int64_t(p) << std::endl;
  //   std::cout << "z: " << std::int64_t(z) << std::endl;
  //   std::cout << "s: " << std::int64_t(s) << std::endl;

  std::vector<T> constant_v(num_of_simd, T(v));
  ShareWrapper constant_arithmetic_gmw_share_v =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_v);
  std::vector<T> constant_p(num_of_simd, T(p));
  ShareWrapper constant_arithmetic_gmw_share_p =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_p);
  std::vector<T> constant_z(num_of_simd, T(z));
  ShareWrapper constant_arithmetic_gmw_share_z =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_z);
  std::vector<T> constant_s(num_of_simd, T(s));
  ShareWrapper constant_arithmetic_gmw_share_s =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_s);

  floating_point_vector = CreateFloatingPointShareVector(
      constant_arithmetic_gmw_share_v, constant_arithmetic_gmw_share_p,
      constant_arithmetic_gmw_share_z, constant_arithmetic_gmw_share_s, l, k);
  return floating_point_vector;
}

// added by Liang Zhao
template <typename T>
std::vector<ShareWrapper> ShareWrapper::CreateConstantFloatingPointShareVector(
    double floating_point_number, std::size_t l, std::size_t k, std::size_t num_of_simd) const {
  std::vector<T, std::allocator<T>> constant_floating_point =
      FloatingPointDecomposeToVector<T, std::allocator<T>>(floating_point_number);

  std::vector<ShareWrapper> floating_point_vector = CreateConstantFloatingPointShareVector(
      constant_floating_point[0], constant_floating_point[1], constant_floating_point[2],
      constant_floating_point[3], l, k, num_of_simd);
  return floating_point_vector;
}

// TODO:: wrap into other class
// added by Liang Zhao
FloatingPointShareStruct ShareWrapper::CreateFloatingPointShareStruct(
    const ShareWrapper& arithmetic_gmw_share_v, const ShareWrapper& arithmetic_gmw_share_p,
    const ShareWrapper& arithmetic_gmw_share_z, const ShareWrapper& arithmetic_gmw_share_s,
    std::size_t l, std::size_t k) const {
  FloatingPointShareStruct floating_point_struct;
  floating_point_struct.mantissa = arithmetic_gmw_share_v;
  floating_point_struct.exponent = arithmetic_gmw_share_p;
  floating_point_struct.zero = arithmetic_gmw_share_z;
  floating_point_struct.sign = arithmetic_gmw_share_s;
  floating_point_struct.l = l;
  floating_point_struct.k = k;

  return floating_point_struct;
}

// added by Liang Zhao
template <typename T>
FloatingPointShareStruct ShareWrapper::CreateConstantFloatingPointShareStruct(T v, T p, T z, T s,
                                                                              std::size_t l,
                                                                              std::size_t k) const {
  //   std::vector<ShareWrapper> floating_point_vector;

  std::vector<T> constant_v{T(v)};
  ShareWrapper constant_arithmetic_gmw_share_v =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_v);
  std::vector<T> constant_p{T(p)};
  ShareWrapper constant_arithmetic_gmw_share_p =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_p);
  std::vector<T> constant_z{T(z)};
  ShareWrapper constant_arithmetic_gmw_share_z =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_z);
  std::vector<T> constant_s{T(s)};
  ShareWrapper constant_arithmetic_gmw_share_s =
      share_->GetBackend().ConstantArithmeticGmwInput(constant_s);

  FloatingPointShareStruct floating_point_struct;
  floating_point_struct.mantissa = constant_arithmetic_gmw_share_v;
  floating_point_struct.exponent = constant_arithmetic_gmw_share_p;
  floating_point_struct.zero = constant_arithmetic_gmw_share_z;
  floating_point_struct.sign = constant_arithmetic_gmw_share_s;
  floating_point_struct.l = l;
  floating_point_struct.k = k;
  return floating_point_struct;
}

// added by Liang Zhao
template <typename T>
FloatingPointShareStruct ShareWrapper::CreateConstantFloatingPointShareStruct(
    double floating_point_number, std::size_t l, std::size_t k) const {
  std::vector<T, std::allocator<T>> constant_floating_point =
      FloatingPointDecomposeToVector<T, std::allocator<T>>(floating_point_number);

  FloatingPointShareStruct floating_point_struct = CreateConstantFloatingPointShareStruct(
      constant_floating_point[0], constant_floating_point[1], constant_floating_point[2],
      constant_floating_point[3], l, k);
  return floating_point_struct;
}

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLAdd_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   //   std::cout << "FLAdd_ABZS" << std::endl;
//   // constant share
//   //        std::vector<T> constant_one{T(1)};
//   //        ShareWrapper constant_arithmetic_gmw_share_one =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);

//   //        std::vector<T> constant_two{T(2)};
//   //        ShareWrapper constant_arithmetic_gmw_share_two =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);

//   //        std::vector<T> constant_l{T(l)};
//   //        ShareWrapper constant_arithmetic_gmw_share_l =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(constant_l);
//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(l), num_of_simd);

//   //        std::vector<T> constant_l_plus_2{T(l + 2)};
//   //        ShareWrapper constant_arithmetic_gmw_share_l_plus_two =
//   //                share_->GetBackend().ConstantArithmeticGmwInput(constant_l_plus_2);
//   ShareWrapper constant_arithmetic_gmw_share_l_plus_two =
//       CreateConstantArithmeticGmwInput<T>(T(l + 2), num_of_simd);

//   // ------------------------------------------------------------

//   //   std::cout << "FLAdd 000" << std::endl;
//   ShareWrapper arithmetic_gmw_share_a = LT<T>(arithmetic_gmw_share_p1, arithmetic_gmw_share_p2);

//   //   std::cout << "FLAdd 111" << std::endl;
//   ShareWrapper boolean_gmw_share_b = EQ<T>(arithmetic_gmw_share_p1, arithmetic_gmw_share_p2);

//   ShareWrapper arithmetic_gmw_share_b = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b);

//   //   std::cout << "FLAdd 222" << std::endl;
//   ShareWrapper arithmetic_gmw_share_c = LT<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_v2);

//   // ------------------------------------------------------------

//   // multiplication of arithmetic share to save computation
//   // std::cout << "multiplication of arithmetic share to save computation" << std::endl;
//   ShareWrapper arithmetic_gmw_share_a_mul_p1 = arithmetic_gmw_share_a * arithmetic_gmw_share_p1;
//   ShareWrapper arithmetic_gmw_share_a_mul_p2 = arithmetic_gmw_share_a * arithmetic_gmw_share_p2;
//   ShareWrapper arithmetic_gmw_share_1_minus_a =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a;
//   ShareWrapper arithmetic_gmw_share_1_minus_b =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b;
//   ShareWrapper arithmetic_gmw_share_1_minus_c =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c;

//   // std::cout << "arithmetic_gmw_share_1_minus_a" << std::endl;

//   ShareWrapper arithmetic_gmw_share_a_mul_v1 = arithmetic_gmw_share_a * arithmetic_gmw_share_v1;
//   ShareWrapper arithmetic_gmw_share_a_mul_v2 = arithmetic_gmw_share_a * arithmetic_gmw_share_v2;
//   ShareWrapper arithmetic_gmw_share_c_mul_v1 = arithmetic_gmw_share_c * arithmetic_gmw_share_v1;
//   ShareWrapper arithmetic_gmw_share_c_mul_v2 = arithmetic_gmw_share_c * arithmetic_gmw_share_v2;

//   // ------------------------------------------------------------
//   // compute <pmax>^A, <pmin>^A, <vmax>^A, <vmin>^A
//   // std::cout << "compute <pmax>^A, <pmin>^A, <vmax>^A, <vmin>^A" << std::endl;

//   ShareWrapper arithmetic_gmw_share_pmax =
//       arithmetic_gmw_share_a_mul_p2 + arithmetic_gmw_share_p1 - arithmetic_gmw_share_a_mul_p1;

//   ShareWrapper arithmetic_gmw_share_pmin =
//       arithmetic_gmw_share_p2 - arithmetic_gmw_share_a_mul_p2 + arithmetic_gmw_share_a_mul_p1;

//   ShareWrapper arithmetic_gmw_share_vmax =
//       arithmetic_gmw_share_1_minus_b * (arithmetic_gmw_share_a_mul_v2 + arithmetic_gmw_share_v1 -
//                                         arithmetic_gmw_share_a_mul_v1) +
//       arithmetic_gmw_share_b *
//           (arithmetic_gmw_share_c_mul_v2 + arithmetic_gmw_share_v1 -
//           arithmetic_gmw_share_c_mul_v1);

//   // // for debug
//   // ShareWrapper arithmetic_gmw_share_vmax =
//   //     arithmetic_gmw_share_1_minus_a * (arithmetic_gmw_share_a_mul_v2 );

//   ShareWrapper arithmetic_gmw_share_vmin =
//       arithmetic_gmw_share_1_minus_b * (arithmetic_gmw_share_a_mul_v1 + arithmetic_gmw_share_v2 -
//                                         arithmetic_gmw_share_a_mul_v2) +
//       arithmetic_gmw_share_b *
//           (arithmetic_gmw_share_c_mul_v1 + arithmetic_gmw_share_v2 -
//           arithmetic_gmw_share_c_mul_v2);

//   // ------------------------------------------------------------
//   // std::cout << "<s3>^A = <s1>^A + <s2>^A - 2 * <s1>^A * <s2>^A" << std::endl;

//   // <s3>^A = <s1>^A + <s2>^A - 2 * <s1>^A * <s2>^A
//   ShareWrapper arithmetic_gmw_share_s3 =
//       arithmetic_gmw_share_s1 + arithmetic_gmw_share_s2 -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1 * arithmetic_gmw_share_s2;

//   //   std::cout << "FLAdd 333" << std::endl;
//   // <d>^A = (l < (<pmax>^A - <pmin>^A))
//   ShareWrapper arithmetic_gmw_share_d = LT<T>(
//       constant_arithmetic_gmw_share_l, (arithmetic_gmw_share_pmax - arithmetic_gmw_share_pmin));

//   // <delta>^A = (1 - <d>^A) * (<pmax>^A - <pmin>^A)
//   ShareWrapper arithmetic_gmw_share_delta =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_d) *
//       (arithmetic_gmw_share_pmax - arithmetic_gmw_share_pmin);

//   //   std::cout << "FLAdd 444" << std::endl;
//   // <2^delta>^A = 2^((1 - <d>^A) * (<pmax>^A - <pmin>^A))
//   ShareWrapper arithmetic_gmw_share_pow2_delta = Pow2<T>(arithmetic_gmw_share_delta);

//   // <v3>^A = 2 * (<vmax>^A - <s3>^A) + 1
//   ShareWrapper arithmetic_gmw_share_v3 =
//       constant_arithmetic_gmw_share_two * (arithmetic_gmw_share_vmax - arithmetic_gmw_share_s3) +
//       constant_arithmetic_gmw_share_one;
//   // TODO: potential improvement

//   // <v4>^A = <vmax>^A * <2^delta>^A + (1 - 2 * <s3>^A) * <vmin>^A
//   ShareWrapper arithmetic_gmw_share_v4 =
//       arithmetic_gmw_share_vmax * arithmetic_gmw_share_pow2_delta +
//       (constant_arithmetic_gmw_share_one -
//        constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s3) *
//           arithmetic_gmw_share_vmin;

//   // ------------------------------------------------------------
//   // std::cout << "l - <delta>^A" << std::endl;

//   // l - <delta>^A
//   ShareWrapper arithmetic_gmw_share_l_minus_delta =
//       constant_arithmetic_gmw_share_l - arithmetic_gmw_share_delta;

//   //   std::cout << "FLAdd 555" << std::endl;
//   // <2^(l-delta)>^A
//   ShareWrapper arithmetic_gmw_share_pow2_1_minus_delta =
//       Pow2<T>(arithmetic_gmw_share_l_minus_delta);

//   // <v>^A = (<d>^A * <v3>^A + (1 - <d>^A) * <v4>^A) * <2^(l-delta)>^A
//   ShareWrapper arithmetic_gmw_share_v =
//       (arithmetic_gmw_share_d * arithmetic_gmw_share_v3 +
//        (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_d) * arithmetic_gmw_share_v4) *
//       arithmetic_gmw_share_pow2_1_minus_delta;

//   //   std::cout << "FLAdd 666" << std::endl;
//   // <v'>^A = Trunc(<v>^A, l-1)
//   ShareWrapper arithmetic_gmw_share_v_prime =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_v, l - 1);

//   // <u_(l+1)>^A, ..., <u_0>^A = BitDec(<v'>^A)
//   ShareWrapper boolean_gmw_share_u =
//       arithmetic_gmw_share_v_prime.Convert<MpcProtocol::kBooleanGmw>();

//   std::vector<ShareWrapper> boolean_gmw_share_u_vector = boolean_gmw_share_u.Split();
//   std::vector<ShareWrapper> boolean_gmw_share_u_from_0_to_l_plus_1_vector =
//       std::vector<ShareWrapper>(boolean_gmw_share_u_vector.begin(),
//                                 boolean_gmw_share_u_vector.begin() + l + 2);

//   // <h_0>^A, ..., <h_(l+1)>^A = PreOr(<u_(l+1)>^A, ..., <u_0>^A)
//   std::reverse(boolean_gmw_share_u_from_0_to_l_plus_1_vector.begin(),
//                boolean_gmw_share_u_from_0_to_l_plus_1_vector.end());
//   // std::reverse(boolean_gmw_share_u_vector.begin(), boolean_gmw_share_u_vector.end());
//   ShareWrapper boolean_gmw_share_u_reverse_order =
//       Concatenate(boolean_gmw_share_u_from_0_to_l_plus_1_vector);
//   ShareWrapper boolean_gmw_share_h = boolean_gmw_share_u_reverse_order.PreOrL();
//   std::vector<ShareWrapper> boolean_gmw_share_h_vector = boolean_gmw_share_h.Split();

//   // TODO: use SIMD to parallelize
//   // Sum_(i=0)^(l+1) <h_i>^A
//   std::vector<ShareWrapper> arithmetic_gmw_share_h_vector;
//   for (std::size_t i = 0; i <= l + 1; i++) {
//     arithmetic_gmw_share_h_vector.emplace_back(
//         boolean_gmw_share_h_vector[i].BooleanGmwBitsToArithmeticGmw<T>());
//   }

//   ShareWrapper arithmetic_gmw_share_sum_hi = arithmetic_gmw_share_h_vector[0];
//   for (std::size_t i = 1; i <= l + 1; i++) {
//     arithmetic_gmw_share_sum_hi = arithmetic_gmw_share_sum_hi + arithmetic_gmw_share_h_vector[i];
//   }

//   // <p0>^A = l + 2 - Sum_(i=0)^(l+1) <h_i>^A
//   // std::cout << "<p0>^A = l + 2 - Sum_(i=0)^(l+1) <h_i>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_p0 =
//       constant_arithmetic_gmw_share_l_plus_two - arithmetic_gmw_share_sum_hi;

//   // Sum_(i=0)^(l+1) 2^i * (1 - <h_i>^A)
//   // std::cout << "Sum_(i=0)^(l+1) 2^i * (1 - <h_i>^A)" << std::endl;
//   ShareWrapper arithmetic_gmw_share_sum_pow2_i_mul_1_minus_hi =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_h_vector[0];
//   for (std::size_t i = 1; i <= l + 1; i++) {
//     //            std::vector<T> constant_pow2_i{T(1) << i};
//     //            ShareWrapper constant_arithmetic_gmw_share_pow2_i =
//     //                    share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_i);
//     ShareWrapper constant_arithmetic_gmw_share_pow2_i =
//         CreateConstantArithmeticGmwInput<T>(T(1) << i, num_of_simd);

//     arithmetic_gmw_share_sum_pow2_i_mul_1_minus_hi =
//         arithmetic_gmw_share_sum_pow2_i_mul_1_minus_hi +
//         constant_arithmetic_gmw_share_pow2_i *
//             (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_h_vector[i]);
//   }

//   // <2^p0>^A = 1 + Sum_(i=0)^(l+1) 2^i * (1 - <h_i>^A)
//   ShareWrapper arithmetic_gmw_share_pow2_p0 =
//       constant_arithmetic_gmw_share_one + arithmetic_gmw_share_sum_pow2_i_mul_1_minus_hi;

//   // <v''>^A = Trunc(<2^p0>^A * <v'>^A, 2)
//   // std::cout << "<v''>^A = Trunc(<2^p0>^A * <v'>^A, 2)" << std::endl;
//   ShareWrapper arithmetic_gmw_share_v_prime_prime =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_pow2_p0 * arithmetic_gmw_share_v_prime, 2);

//   // <p>^A = <pmax>^A - <p0>^A + 1 - <d>^A
//   ShareWrapper arithmetic_gmw_share_p = arithmetic_gmw_share_pmax - arithmetic_gmw_share_p0 +
//                                         constant_arithmetic_gmw_share_one -
//                                         arithmetic_gmw_share_d;

//   // <z1>^A) * <z2>^A
//   ShareWrapper arithmetic_gmw_share_z1_mul_z2 = arithmetic_gmw_share_z1 *
//   arithmetic_gmw_share_z2;

//   // (1 - <z1>^A) * (1 - <z2>^A)
//   ShareWrapper arithmetic_gmw_share_1_minus_z1_mul_1_minus_z2 =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1 - arithmetic_gmw_share_z2 +
//       arithmetic_gmw_share_z1_mul_z2;

//   // <v'''>^A = (1 - <z1>^A) * (1 - <z2>^A) * <v''>^A + <z1>^A * <v2>^A + <z2>^A * <v1>^A
//   ShareWrapper arithmetic_gmw_share_v_prime_prime_prime =
//       arithmetic_gmw_share_1_minus_z1_mul_1_minus_z2 * arithmetic_gmw_share_v_prime_prime +
//       arithmetic_gmw_share_z1 * arithmetic_gmw_share_v2 +
//       arithmetic_gmw_share_z2 * arithmetic_gmw_share_v1;

//   // <z>^B = (<v'''>^A == 0)
//   // std::cout << "<z>^B = (<v'''>^A == 0)" << std::endl;
//   ShareWrapper boolean_gmw_share_z = EQZ<T>(arithmetic_gmw_share_v_prime_prime_prime);
//   ShareWrapper arithmetic_gmw_share_z = boolean_gmw_share_z.BooleanGmwBitsToArithmeticGmw<T>();

//   // <p'>^A = ((1 - <z1>^A) * (1 - <z2>^A) * <p>^A + <z1>^A * <p2>^A + <z2>^A * <p1>^A) * (1 -
//   // <z>^A)
//   // std::cout << "<p'>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_p_prime =
//       (arithmetic_gmw_share_1_minus_z1_mul_1_minus_z2 * arithmetic_gmw_share_p +
//        arithmetic_gmw_share_z1 * arithmetic_gmw_share_p2 +
//        arithmetic_gmw_share_z2 * arithmetic_gmw_share_p1) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   //  <s>^A = (1 - <b>^A) * (<a>^A * <s2>^A + (1 - <a>^A) * <s1>^A) + <b>^A * (<c>^A * <s2>^A +
//   (1
//   //  - <c>^A) * <s1>^A)
//   // std::cout << "<s>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_s =
//       arithmetic_gmw_share_1_minus_b *
//           (arithmetic_gmw_share_a * arithmetic_gmw_share_s2 +
//            (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a) *
//            arithmetic_gmw_share_s1) +
//       arithmetic_gmw_share_b *
//           (arithmetic_gmw_share_c * arithmetic_gmw_share_s2 +
//            (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c) *
//            arithmetic_gmw_share_s1);

//   // <s'>^A = (1 - <z1>^A) * (1 - <z2>^A) * <s>^A + (<z2>^A - <z1>^A * <z2>^A) * <s1>^A + (<z1>^A
//   // - <z1>^A * <z2>^A) * <s2>^A std::cout << "<s'>^A" << std::endl;
//   ShareWrapper arithmetic_gmw_share_s_prime =
//       arithmetic_gmw_share_1_minus_z1_mul_1_minus_z2 * arithmetic_gmw_share_s +
//       (arithmetic_gmw_share_z2 - arithmetic_gmw_share_z1_mul_z2) * arithmetic_gmw_share_s1 +
//       (arithmetic_gmw_share_z1 - arithmetic_gmw_share_z1_mul_z2) * arithmetic_gmw_share_s2;

//   std::vector<ShareWrapper> floating_point_addtion_result;
//   floating_point_addtion_result.reserve(4);
//   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v_prime_prime_prime);  // 0
//   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_p_prime);              // 1
//   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_z);                    // 2
//   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_s_prime);              // 3
//   //   floating_point_addtion_result.emplace_back(constant_arithmetic_gmw_share_one); // 3

//   //   // only for debug
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_a);              // 4
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_b);              // 5
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_c);              // 6
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_pmax);           // 7
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_pmin);           // 8
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_vmax);           // 9
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_vmin);           // 10
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_s3);             // 11
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_d);              // 12
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_delta);          // 13
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_l_minus_delta);  // 14
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v3);             // 15
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v4);             // 16
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v);              // 17
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v_prime);        // 18
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_p0);             // 19
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_pow2_p0);        // 20
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_v_prime_prime);  // 21
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_p);              // 22
//   //   floating_point_addtion_result.emplace_back(arithmetic_gmw_share_s);              // 23

//   return floating_point_addtion_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLAdd_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template std::vector<ShareWrapper> ShareWrapper::FLAdd_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLSub_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   //   std::cout << "FLSub_ABZS" << std::endl;
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();
//   //   std::cout << "num_of_simd: " << num_of_simd << std::endl;

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   std::vector<ShareWrapper> floating_point_subtraction_result = FLAdd_ABZS<T>(
//       arithmetic_gmw_share_v1, arithmetic_gmw_share_p1, arithmetic_gmw_share_z1,
//       arithmetic_gmw_share_s1, arithmetic_gmw_share_v2, arithmetic_gmw_share_p2,
//       arithmetic_gmw_share_z2, constant_arithmetic_gmw_share_one - arithmetic_gmw_share_s2, l,
//       k);

//   return floating_point_subtraction_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLSub_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template std::vector<ShareWrapper> ShareWrapper::FLSub_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// // TODO: use protocol from paper (Efficient Secure Floating-point Arithmetic using Shamir Secret
// // Sharing)?
// template <typename T>
// ShareWrapper ShareWrapper::SDiv_ABZS(const ShareWrapper& arithmetic_gmw_share_a,
//                                      const ShareWrapper& arithmetic_gmw_share_b,
//                                      std::size_t l) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   //   std::vector<T> constant_pow2_l_plus_1{T(1) << (l + 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l_plus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_plus_1);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l_plus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << (l + 1), num_of_simd);

//   std::size_t theta = ceil(log2(l));

//   ShareWrapper arithmetic_gmw_share_x = arithmetic_gmw_share_b;
//   ShareWrapper arithmetic_gmw_share_y = arithmetic_gmw_share_a;

//   for (std::size_t i = 1; i < theta; i++) {
//     // ============================================================
//     arithmetic_gmw_share_y = arithmetic_gmw_share_y *
//                              (constant_arithmetic_gmw_share_pow2_l_plus_1 -
//                              arithmetic_gmw_share_x);

//     // TODO: use more efficient truncation protocol?
//     // TODO: use ArithmeticRightShift to benchmark?
//     arithmetic_gmw_share_y = TruncPr<T>(arithmetic_gmw_share_y, l)[0];

//     arithmetic_gmw_share_x = arithmetic_gmw_share_x *
//                              (constant_arithmetic_gmw_share_pow2_l_plus_1 -
//                              arithmetic_gmw_share_x);
//     arithmetic_gmw_share_x = TruncPr<T>(arithmetic_gmw_share_x, l)[0];

//     // ============================================================
//     // TODO: use SIMD to parallelize two TruncPr?

//     // ============================================================
//   }

//   arithmetic_gmw_share_y = arithmetic_gmw_share_y *
//                            (constant_arithmetic_gmw_share_pow2_l_plus_1 -
//                            arithmetic_gmw_share_x);
//   arithmetic_gmw_share_y = TruncPr<T>(arithmetic_gmw_share_y, l)[0];

//   return arithmetic_gmw_share_y;
// }

// template ShareWrapper ShareWrapper::SDiv_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b,
//     std::size_t l) const;

// template ShareWrapper ShareWrapper::SDiv_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, const ShareWrapper& arithmetic_gmw_share_b,
//     std::size_t l) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLDiv_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   //   std::vector<T> constant_l_minus_1{T(l - 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//       CreateConstantArithmeticGmwInput(T(l - 1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   //   std::vector<T> constant_pow2_l{T(1) << l};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//       CreateConstantArithmeticGmwInput(T(1) << l, num_of_simd);

//   ShareWrapper arithmetic_gmw_share_v =
//       SDiv_ABZS<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_v2 + arithmetic_gmw_share_z2,
//       l);

//   ShareWrapper arithmetic_gmw_share_b =
//       LT<T>(arithmetic_gmw_share_v, constant_arithmetic_gmw_share_pow2_l);

//   ShareWrapper arithmetic_gmw_share_v_prime = ArithmeticRightShift<T>(
//       arithmetic_gmw_share_b * arithmetic_gmw_share_v + arithmetic_gmw_share_v, 1);

//   ShareWrapper arithmetic_gmw_share_p =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1) *
//       (arithmetic_gmw_share_p1 - arithmetic_gmw_share_p2 -
//       constant_arithmetic_gmw_share_l_minus_1 -
//        arithmetic_gmw_share_b);

//   ShareWrapper arithmetic_gmw_share_z = arithmetic_gmw_share_z1;

//   ShareWrapper arithmetic_gmw_share_s =
//       arithmetic_gmw_share_s1 + arithmetic_gmw_share_s2 -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1 * arithmetic_gmw_share_s2;

//   // TODO: use other error check method
//   ShareWrapper arithmetic_gmw_share_error = arithmetic_gmw_share_z2;

//   std::vector<ShareWrapper> floating_point_division_result;
//   floating_point_division_result.reserve(4);
//   floating_point_division_result.emplace_back(arithmetic_gmw_share_v_prime);
//   floating_point_division_result.emplace_back(arithmetic_gmw_share_p);
//   floating_point_division_result.emplace_back(arithmetic_gmw_share_z);
//   floating_point_division_result.emplace_back(arithmetic_gmw_share_s);
//   //   floating_point_division_result.emplace_back(arithmetic_gmw_share_error);

//   //   // only for debug
//   //   floating_point_division_result.emplace_back(arithmetic_gmw_share_v);

//   return floating_point_division_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLDiv_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template std::vector<ShareWrapper> ShareWrapper::FLDiv_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLMul_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();
//   //   std::vector<T> constant_l{T(l)};
//   //   ShareWrapper constant_arithmetic_gmw_share_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l);
//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(l), num_of_simd);

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);

//   //   std::vector<T> constant_pow2_l{T(1) << l};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//       CreateConstantArithmeticGmwInput<T>(T(1) << l, num_of_simd);

//   ShareWrapper arithmetic_gmw_share_v = arithmetic_gmw_share_v1 * arithmetic_gmw_share_v2;

//   ShareWrapper arithmetic_gmw_share_v_prime =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_v, l - 1);

//   ShareWrapper arithmetic_gmw_share_b =
//       LT<T>(arithmetic_gmw_share_v_prime, constant_arithmetic_gmw_share_pow2_l);

//   ShareWrapper arithmetic_gmw_share_v_prime_prime = ArithmeticRightShift<T>(
//       arithmetic_gmw_share_b * arithmetic_gmw_share_v_prime + arithmetic_gmw_share_v_prime, 1);

//   ShareWrapper arithmetic_gmw_share_z = arithmetic_gmw_share_z1 + arithmetic_gmw_share_z2 -
//                                         arithmetic_gmw_share_z1 * arithmetic_gmw_share_z2;

//   ShareWrapper arithmetic_gmw_share_s =
//       arithmetic_gmw_share_s1 + arithmetic_gmw_share_s2 -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1 * arithmetic_gmw_share_s2;

//   ShareWrapper arithmetic_gmw_share_p =
//       (arithmetic_gmw_share_p1 + arithmetic_gmw_share_p2 + constant_arithmetic_gmw_share_l -
//        arithmetic_gmw_share_b) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   std::vector<ShareWrapper> floating_point_multiplication_result;
//   floating_point_multiplication_result.reserve(4);
//   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_v_prime_prime);
//   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_p);
//   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_z);
//   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_s);

//   // only for debug
//   // floating_point_multiplication_result.emplace_back(constant_arithmetic_gmw_share_two);
//   // floating_point_multiplication_result.emplace_back(constant_arithmetic_gmw_share_two);
//   // floating_point_multiplication_result.emplace_back(constant_arithmetic_gmw_share_two);
//   // floating_point_multiplication_result.emplace_back(constant_arithmetic_gmw_share_two);

//   //   // only for debug
//   //   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_v);
//   //   floating_point_multiplication_result.emplace_back(arithmetic_gmw_share_v_prime);

//   return floating_point_multiplication_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLMul_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template std::vector<ShareWrapper> ShareWrapper::FLMul_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::FLLT_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_a = LT<T>(arithmetic_gmw_share_p1, arithmetic_gmw_share_p2);

//   ShareWrapper boolean_gmw_share_c = EQ<T>(arithmetic_gmw_share_p1, arithmetic_gmw_share_p2);
//   ShareWrapper arithmetic_gmw_share_c = boolean_gmw_share_c.BooleanGmwBitsToArithmeticGmw<T>();

//   ShareWrapper arithmetic_gmw_share_d =
//       LT<T>((constant_arithmetic_gmw_share_one -
//              constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1) *
//                 arithmetic_gmw_share_v1,
//             (constant_arithmetic_gmw_share_one -
//              constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s2) *
//                 arithmetic_gmw_share_v2);

//   ShareWrapper arithmetic_gmw_share_c_mul_d = arithmetic_gmw_share_c * arithmetic_gmw_share_d;
//   ShareWrapper arithmetic_gmw_share_c_mul_a = arithmetic_gmw_share_c * arithmetic_gmw_share_a;

//   ShareWrapper arithmetic_gmw_share_b_plus =
//       arithmetic_gmw_share_c_mul_d + arithmetic_gmw_share_a - arithmetic_gmw_share_c_mul_a;

//   ShareWrapper arithmetic_gmw_share_b_minus =
//       arithmetic_gmw_share_c_mul_d + constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a -
//       arithmetic_gmw_share_c + arithmetic_gmw_share_c_mul_a;

//   ShareWrapper arithmetic_gmw_share_z1_mul_z2 = arithmetic_gmw_share_z1 *
//   arithmetic_gmw_share_z2;

//   ShareWrapper arithmetic_gmw_share_s1_mul_s2 = arithmetic_gmw_share_s1 *
//   arithmetic_gmw_share_s2;

//   ShareWrapper arithmetic_gmw_share_b =
//       (arithmetic_gmw_share_z1 - arithmetic_gmw_share_z1_mul_z2) *
//           (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_s2) +
//       (arithmetic_gmw_share_z2 - arithmetic_gmw_share_z1_mul_z2) * arithmetic_gmw_share_s1 +
//       (constant_arithmetic_gmw_share_one + arithmetic_gmw_share_z1_mul_z2 -
//        arithmetic_gmw_share_z1 - arithmetic_gmw_share_z2) *
//           (arithmetic_gmw_share_s1 - arithmetic_gmw_share_s1_mul_s2 +
//            (constant_arithmetic_gmw_share_one + arithmetic_gmw_share_s1_mul_s2 -
//             arithmetic_gmw_share_s1 - arithmetic_gmw_share_s2) *
//                arithmetic_gmw_share_b_plus +
//            arithmetic_gmw_share_s1_mul_s2 * arithmetic_gmw_share_b_minus);

//   // TODO: combine error parameter

//   return arithmetic_gmw_share_b;
// }

// template ShareWrapper ShareWrapper::FLLT_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template ShareWrapper ShareWrapper::FLLT_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// template <typename T>
// ShareWrapper ShareWrapper::FLEQ_ABZS(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   // TODO: truncate v, p, and check the equality to improve performance

//   // v1 == v2
//   ShareWrapper boolean_gmw_share_b1 = EQ<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_v2, l);
//   ShareWrapper arithmetic_gmw_share_b1 = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b1);

//   // p1 == p2
//   ShareWrapper boolean_gmw_share_b2 =
//       EQ<T>(arithmetic_gmw_share_p1, arithmetic_gmw_share_p2, k + 1);
//   ShareWrapper arithmetic_gmw_share_b2 = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b2);

//   // z1 = 1, z2 = 1
//   ShareWrapper arithmetic_gmw_share_z1_mul_z2 = arithmetic_gmw_share_z1 *
//   arithmetic_gmw_share_z2;

//   // z1 | z2
//   ShareWrapper arithmetic_gmw_share_z1_or_z2 =
//       arithmetic_gmw_share_z1 + arithmetic_gmw_share_z2 - arithmetic_gmw_share_z1_mul_z2;

//   // z1 = 0, z2 = 0
//   ShareWrapper arithmetic_gmw_share_b3 =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1_or_z2;

//   // s1 = 1, s2 = 1
//   ShareWrapper arithmetic_gmw_share_s1_mul_s2 = arithmetic_gmw_share_s1 *
//   arithmetic_gmw_share_s2;

//   // s1 ^ s2
//   ShareWrapper arithmetic_gmw_share_s1_xor_s2 =
//       arithmetic_gmw_share_s1 + arithmetic_gmw_share_s2 -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1_mul_s2;

//   // s1 = s2
//   ShareWrapper arithmetic_gmw_share_b4 =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_s1_xor_s2;

//   // case(equality) = case(z1=1,z2=1) + case(v1=v2,p1=p2,s1=s2,z1=z2=0)
//   ShareWrapper arithmetic_gmw_share_equal_result =
//       arithmetic_gmw_share_z1_mul_z2 +
//       arithmetic_gmw_share_b1 * arithmetic_gmw_share_b2 * arithmetic_gmw_share_b3;

//   // TODO: combine error parameter

//   return arithmetic_gmw_share_equal_result;

//   // only for debug
//   //   return arithmetic_gmw_share_b3;
// }

// template ShareWrapper ShareWrapper::FLEQ_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// template ShareWrapper ShareWrapper::FLEQ_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
//     const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLRound_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                      const ShareWrapper& arithmetic_gmw_share_p1,
//                                                      const ShareWrapper& arithmetic_gmw_share_z1,
//                                                      const ShareWrapper& arithmetic_gmw_share_s1,
//                                                      std::size_t mode, std::size_t l,
//                                                      std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput<T>(T(0), num_of_simd);

//   //   std::vector<T> constant_one{T(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(l), num_of_simd);

//   //   std::vector<T> constant_minus_l_plus_1{T(-T(l) + 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_minus_l_plus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_minus_l_plus_1);
//   ShareWrapper constant_arithmetic_gmw_share_minus_l_plus_1 =
//       CreateConstantArithmeticGmwInput(T(-T(l) + 1), num_of_simd);

//   //   std::vector<T> constant_mode{T(mode)};
//   //   ShareWrapper constant_arithmetic_gmw_share_mode =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_mode);
//   ShareWrapper constant_arithmetic_gmw_share_mode =
//       CreateConstantArithmeticGmwInput(T(mode), num_of_simd);

//   //   std::vector<T> constant_pow2_l{T(1) << l};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//       CreateConstantArithmeticGmwInput(T(1) << l, num_of_simd);

//   //   std::vector<T> constant_pow2_l_minus_1{T(1) << (l - 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//       CreateConstantArithmeticGmwInput(T(1) << (l - 1), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_a = LTZ<T>(arithmetic_gmw_share_p1);

//   ShareWrapper arithmetic_gmw_share_b =
//       LT<T>(arithmetic_gmw_share_p1, constant_arithmetic_gmw_share_minus_l_plus_1);

//   ShareWrapper arithmetic_gmw_share_a_mul_b = arithmetic_gmw_share_a * arithmetic_gmw_share_b;

//   // std::cout << "000" << std::endl;

//   ShareWrapper arithmetic_gmw_share_a_mul_b_minus_1_mul_p1 =
//       (arithmetic_gmw_share_a_mul_b - arithmetic_gmw_share_a) * arithmetic_gmw_share_p1;

//   std::vector<ShareWrapper> arithmetic_gmw_share_modular_reduction_vector =
//       ObliviousModPow2m<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_a_mul_b_minus_1_mul_p1);

//   // std::cout << "111" << std::endl;

//   ShareWrapper arithmetic_gmw_share_v2 = arithmetic_gmw_share_modular_reduction_vector[0];
//   ShareWrapper arithmetic_gmw_share_pow2_minus_p1 =
//       arithmetic_gmw_share_modular_reduction_vector[1];

//   ShareWrapper boolean_gmw_share_c = EQZ<T>(arithmetic_gmw_share_v2);
//   ShareWrapper arithmetic_gmw_share_c = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_c);

//   ShareWrapper arithmetic_gmw_share_away_from_zero =
//       constant_arithmetic_gmw_share_mode + arithmetic_gmw_share_s1 -
//       constant_arithmetic_gmw_share_two * constant_arithmetic_gmw_share_mode *
//           arithmetic_gmw_share_s1;

//   //   // std::cout << "222" << std::endl;
//   //   ShareWrapper arithmetic_mode_xor_s1 =
//   //       constant_arithmetic_gmw_share_mode + arithmetic_gmw_share_s1 -
//   //       constant_arithmetic_gmw_share_two * constant_arithmetic_gmw_share_mode *
//   //           arithmetic_gmw_share_s1;

//   // std::cout << "333" << std::endl;

//   //   ShareWrapper arithmetic_gmw_share_v =
//   //       arithmetic_gmw_share_v1 - arithmetic_gmw_share_v2 +
//   //       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c) *
//   //           arithmetic_gmw_share_pow2_minus_p1 * arithmetic_mode_xor_s1;
//   ShareWrapper arithmetic_gmw_share_v =
//       arithmetic_gmw_share_v1 - arithmetic_gmw_share_v2 +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c) *
//           arithmetic_gmw_share_pow2_minus_p1 * arithmetic_gmw_share_away_from_zero;

//   ShareWrapper boolean_gmw_share_d =
//       EQ<T>(arithmetic_gmw_share_v, constant_arithmetic_gmw_share_pow2_l);

//   ShareWrapper arithmetic_gmw_share_d = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_d);

//   ShareWrapper arithmetic_gmw_share_v_prime =
//       arithmetic_gmw_share_d * constant_arithmetic_gmw_share_pow2_l_minus_1 +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_d) * arithmetic_gmw_share_v;

//   // incorrect version
//   //   <v''>^A = <a>^A * <v'>^A - <a>^A * <b>^A * <v'>^A + <a>^A * <b>^A * (mode - <s1>^A) + (1 -
//   //   <a>^A) * <v1>^A
//   //   ShareWrapper arithmetic_gmw_share_v_prime_prime =
//   //       arithmetic_gmw_share_a * arithmetic_gmw_share_v_prime -
//   //       arithmetic_gmw_share_a_mul_b * arithmetic_gmw_share_v_prime +
//   //       arithmetic_gmw_share_a_mul_b *
//   //           (constant_arithmetic_gmw_share_mode - arithmetic_gmw_share_s1) +
//   //       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a) *
//   arithmetic_gmw_share_v1;

//   // correct version
//   ShareWrapper arithmetic_gmw_share_v_prime_prime =
//       arithmetic_gmw_share_a * ((constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b) *
//                                     arithmetic_gmw_share_v_prime +
//                                 arithmetic_gmw_share_b * arithmetic_gmw_share_away_from_zero *
//                                     constant_arithmetic_gmw_share_pow2_l_minus_1) +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a) * arithmetic_gmw_share_v1;

//   ShareWrapper arithmetic_gmw_share_s =
//       (constant_arithmetic_gmw_share_one -
//        arithmetic_gmw_share_b * constant_arithmetic_gmw_share_mode) *
//       arithmetic_gmw_share_s1;

//   ShareWrapper boolean_gmw_share_v_prime_prime_eq_zero =
//   EQZ<T>(arithmetic_gmw_share_v_prime_prime);

//   ShareWrapper arithmetic_gmw_share_v_prime_prime_eq_zero =
//       BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_v_prime_prime_eq_zero);

//   ShareWrapper arithmetic_gmw_share_z =
//       arithmetic_gmw_share_v_prime_prime_eq_zero + arithmetic_gmw_share_z1 -
//       arithmetic_gmw_share_v_prime_prime_eq_zero * arithmetic_gmw_share_z1;

//   ShareWrapper arithmetic_gmw_share_v_prime_prime_prime =
//       arithmetic_gmw_share_v_prime_prime *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   ShareWrapper arithmetic_gmw_share_d_mul_a = arithmetic_gmw_share_d * arithmetic_gmw_share_a;

//   // incorrect version
//   //   // <p>^A = (<p1>^A + <d>^A * <a>^A - <d>^A * <a>^A * <b>^A) * (1 - <z>^A)
//   //   ShareWrapper arithmetic_gmw_share_p =
//   //       (arithmetic_gmw_share_p1 + arithmetic_gmw_share_d_mul_a -
//   //        arithmetic_gmw_share_d_mul_a * arithmetic_gmw_share_b) *
//   //       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   // correct version
//   ShareWrapper arithmetic_gmw_share_p =
//       ((arithmetic_gmw_share_p1 + arithmetic_gmw_share_d_mul_a) *
//            (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b) +
//        arithmetic_gmw_share_b * arithmetic_gmw_share_away_from_zero *
//            (constant_arithmetic_gmw_share_one - constant_arithmetic_gmw_share_l)) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   std::vector<ShareWrapper> floating_point_round_result;
//   floating_point_round_result.reserve(4);
//   floating_point_round_result.emplace_back(arithmetic_gmw_share_v_prime_prime_prime);  // 0
//   floating_point_round_result.emplace_back(arithmetic_gmw_share_p);                    // 1
//   floating_point_round_result.emplace_back(arithmetic_gmw_share_z);                    // 2
//   floating_point_round_result.emplace_back(arithmetic_gmw_share_s);                    // 3

//   //   // only for debug
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_a);                      //
//   4
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_b);                      //
//   5
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_v2);                     //
//   6
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_c);                      //
//   7
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_v);                      //
//   8
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_v_prime);                //
//   9
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_v_prime_prime);          //
//   10
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_v_prime_prime_eq_zero);  //
//   11
//   //   floating_point_round_result.emplace_back(arithmetic_gmw_share_pow2_minus_p1);          //
//   12

//   // TODO: combine error parameter

//   return floating_point_round_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLRound_ABZS<std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t mode, std::size_t l, std::size_t k) const;

// template std::vector<ShareWrapper> ShareWrapper::FLRound_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t mode, std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// // TODO: improve performance, benchmark, try to do more computation at the (smaller) data type as
// // it is cheap
// template <typename IntType, typename FLType>
// std::vector<ShareWrapper> ShareWrapper::Int2FL_ABZS(const ShareWrapper& arithmetic_gmw_share_a,
//                                                     std::size_t gamma, std::size_t l,
//                                                     std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   //   std::vector<FLType> constant_one{FLType(1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(FLType(1), num_of_simd);

//   //   std::vector<FLType> constant_two{FLType(2)};
//   //   ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(FLType(2), num_of_simd);

//   //   std::vector<FLType> constant_l{FLType(l)};
//   //   ShareWrapper constant_arithmetic_gmw_share_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l);
//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput(FLType(l), num_of_simd);

//   //   std::vector<FLType> constant_pow2_l_minus_gamma_plus_1{FLType(1) << (l - gamma + 1)};
//   //   ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_gamma_plus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_minus_gamma_plus_1);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_gamma_plus_1 =
//       CreateConstantArithmeticGmwInput(FLType(1) << (l - gamma + 1), num_of_simd);

//   std::size_t lambda = gamma - 1;

//   //   std::vector<FLType> constant_lambda{FLType(lambda)};
//   //   ShareWrapper constant_arithmetic_gmw_share_lambda =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_lambda);
//   ShareWrapper constant_arithmetic_gmw_share_lambda =
//       CreateConstantArithmeticGmwInput(FLType(lambda), num_of_simd);

//   //   std::vector<FLType> constant_gamma{FLType(gamma)};
//   //   ShareWrapper constant_arithmetic_gmw_share_gamma =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_gamma);
//   ShareWrapper constant_arithmetic_gmw_share_gamma =
//       CreateConstantArithmeticGmwInput(FLType(gamma), num_of_simd);

//   // <s>^A = (<a>^A < 0)
//   ShareWrapper arithmetic_gmw_share_s = LTZ<FLType>(arithmetic_gmw_share_a);

//   // <z>^A = (<a>^A == 0)
//   ShareWrapper boolean_gmw_share_z = EQZ<FLType>(arithmetic_gmw_share_a);
//   ShareWrapper arithmetic_gmw_share_z =
//   BooleanGmwBitsToArithmeticGmw<FLType>(boolean_gmw_share_z);

//   // turn <a>^A into a positive integer <a'>^A
//   ShareWrapper arithmetic_gmw_share_a_prime =
//       (constant_arithmetic_gmw_share_one -
//        constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s) *
//       arithmetic_gmw_share_a;

//   ShareWrapper boolean_gmw_share_a_prime_bit_decomposition =
//       arithmetic_gmw_share_a_prime.Convert<MpcProtocol::kBooleanGmw>();

//   std::vector<ShareWrapper> boolean_gmw_share_a_prime_bit_decomposition_vector =
//       boolean_gmw_share_a_prime_bit_decomposition.Split();

//   // extract <a_0>^B, ..., <a_lambda>^B
//   std::vector<ShareWrapper> boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_vector(
//       boolean_gmw_share_a_prime_bit_decomposition_vector.begin(),
//       boolean_gmw_share_a_prime_bit_decomposition_vector.begin() + lambda);

//   //   // discard the MSB of <a'>^B as it is already known as zero (as <a'>^A is a positive
//   //   integer) boolean_gmw_share_a_prime_bit_decomposition_vector.pop_back();

//   // reverse the order of <a'>^B
//   std::reverse(boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_vector.begin(),
//                boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_vector.end());

//   ShareWrapper boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_reverse =
//       Concatenate(boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_vector);

//   ShareWrapper boolean_gmw_share_b =
//       boolean_gmw_share_a_prime_bit_decomposition_from_0_to_lambda_reverse.PreOrL();
//   std::vector<ShareWrapper> boolean_gmw_share_b_vector = boolean_gmw_share_b.Split();

//   // convert each <bi>^B to arithmetic gmw share <bi>^A
//   std::vector<ShareWrapper> arithmetic_gmw_share_b_vector;
//   arithmetic_gmw_share_b_vector.reserve(lambda);
//   for (std::size_t i = 0; i < lambda; i++) {
//     arithmetic_gmw_share_b_vector.emplace_back(
//         BooleanGmwBitsToArithmeticGmw<FLType>(boolean_gmw_share_b_vector[i]));
//   }

//   // Sum_(0)^(lambda - 1) 2^i * (1 - <bi>^A)
//   ShareWrapper arithmetic_gmw_share_sum_pow2_i_mul_1_minus_b =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b_vector[0];
//   for (std::size_t i = 1; i < lambda; i++) {
//     // std::vector<FLType> power_of_2_i{FLType(1) << (i)};
//     // ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//     //     share_->GetBackend().ConstantArithmeticGmwInput(power_of_2_i);
//     ShareWrapper constant_arithmetic_gmw_share_power_of_2_i =
//         CreateConstantArithmeticGmwInput(FLType(1) << (i), num_of_simd);

//     arithmetic_gmw_share_sum_pow2_i_mul_1_minus_b =
//         arithmetic_gmw_share_sum_pow2_i_mul_1_minus_b +
//         constant_arithmetic_gmw_share_power_of_2_i *
//             (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b_vector[i]);
//   }

//   // <v>^A = <a'>^A * (1 + Sum_(0)^(lambda - 1) 2^i * (1 - <bi>^A))
//   ShareWrapper arithmetic_gmw_share_v =
//       arithmetic_gmw_share_a_prime *
//       (constant_arithmetic_gmw_share_one + arithmetic_gmw_share_sum_pow2_i_mul_1_minus_b);

//   // Sum_(0)^(lambda - 1) (1 - <bi>^A)
//   ShareWrapper arithmetic_gmw_share_sum_1_minus_b =
//       constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b_vector[0];
//   for (std::size_t i = 1; i < lambda; i++) {
//     arithmetic_gmw_share_sum_1_minus_b =
//         arithmetic_gmw_share_sum_1_minus_b +
//         (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b_vector[i]);
//   }

//   // Sum_(0)^(lambda - 1) (<bi>^A)
//   ShareWrapper arithmetic_gmw_share_sum_b = arithmetic_gmw_share_b_vector[0];
//   for (std::size_t i = 1; i < lambda; i++) {
//     arithmetic_gmw_share_sum_b = arithmetic_gmw_share_sum_b + (arithmetic_gmw_share_b_vector[i]);
//   }

//   // p  = Sum_(0)^(lambda - 1) (1 - <bi>^A) - lambda
//   ShareWrapper arithmetic_gmw_share_p =
//       arithmetic_gmw_share_sum_b - constant_arithmetic_gmw_share_lambda;

//   ShareWrapper arithmetic_gmw_share_v_prime;
//   if (gamma - 1 > l) {
//     arithmetic_gmw_share_v_prime =
//         ArithmeticRightShift<FLType>(arithmetic_gmw_share_v, gamma - l - 1);
//   } else {
//     arithmetic_gmw_share_v_prime =
//         constant_arithmetic_gmw_share_pow2_l_minus_gamma_plus_1 * arithmetic_gmw_share_v;
//   }

//   // <p'>^A = (<p>^A + gamma - 1 - l ) * (1 - <z>^A)
//   ShareWrapper arithmetic_gmw_share_p_prime =
//       (arithmetic_gmw_share_p + constant_arithmetic_gmw_share_gamma -
//        constant_arithmetic_gmw_share_one - constant_arithmetic_gmw_share_l) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   std::vector<ShareWrapper> integer_to_floating_point_result;
//   integer_to_floating_point_result.reserve(4);
//   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_v_prime);  // 0
//   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_p_prime);  // 1
//   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_z);        // 2
//   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_s);        // 3

//   //   // only for debug
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_a_prime);  // 4
//   //   integer_to_floating_point_result.emplace_back(
//   //       arithmetic_gmw_share_sum_pow2_i_mul_1_minus_b);                                 // 5
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_sum_1_minus_b);  // 6
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_a);              // 7
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_v);              // 8
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_p);              // 9
//   //   integer_to_floating_point_result.emplace_back(arithmetic_gmw_share_sum_b);          // 10

//   return integer_to_floating_point_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::Int2FL_ABZS<__uint128_t, __uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t gamma, std::size_t l,
//     std::size_t k) const;

// // backup file
// template <typename FLType,typename IntType>
// std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                        const ShareWrapper& arithmetic_gmw_share_p1,
//                                        const ShareWrapper& arithmetic_gmw_share_z1,
//                                        const ShareWrapper& arithmetic_gmw_share_s1, std::size_t
//                                        l, std::size_t k) {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   const ShareWrapper constant_arithmetic_gmw_share_l_FLType =
//       CreateConstantArithmeticGmwInput(FLType(l), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_zero_FLType =
//       CreateConstantArithmeticGmwInput(FLType(0), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_one_FLType =
//       CreateConstantArithmeticGmwInput(FLType(1), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_two_FLType =
//       CreateConstantArithmeticGmwInput(FLType(2), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_l_IntType =
//       CreateConstantArithmeticGmwInput(IntType(l), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_zero_IntType =
//       CreateConstantArithmeticGmwInput(IntType(0), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_one_IntType =
//       CreateConstantArithmeticGmwInput(IntType(1), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_two_IntType =
//       CreateConstantArithmeticGmwInput(IntType(2), num_of_simd);

//   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x =
//       CreateFloatingPointShareVector(arithmetic_gmw_share_v1, arithmetic_gmw_share_p1,
//                                      arithmetic_gmw_share_z1, arithmetic_gmw_share_s1, l, k);

//   // round the floating-point number x to the nearest integer
//   // add it with 0.5, then floor(x+0.5)
//   double constant_0_5 = 0.5;
//   std::vector<ShareWrapper> constant_floating_point_arithmetic_gmw_share_0_5 =
//       CreateConstantFloatingPointShareVector<FLType>(constant_0_5, l, k, num_of_simd);
//   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x_plus_0_5 =
//       FLAdd_ABZS<FLType>(floating_point_arithmetic_gmw_share_x,
//                          constant_floating_point_arithmetic_gmw_share_0_5, l, k);

// // // only for debug
// // std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x_plus_0_5 =
// //       FLAdd_ABZS<FLType>(
// // floating_point_arithmetic_gmw_share_x,floating_point_arithmetic_gmw_share_x, l, k);

// //   std::size_t floor_round_mode = 0;
// //   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_floor_x_plus_0_5 =
// //       FLRound_ABZS<FLType>(floating_point_arithmetic_gmw_share_x_plus_0_5, floor_round_mode,
// l, k);
// //   ShareWrapper floating_point_arithmetic_gmw_share_mantissa =
// //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[0];
// //   ShareWrapper floating_point_arithmetic_gmw_share_exponent =
// //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[1];
// //   ShareWrapper floating_point_arithmetic_gmw_share_zero =
// //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[2];
// //   ShareWrapper floating_point_arithmetic_gmw_share_sign =
// //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[3];

//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[0];
//   ShareWrapper floating_point_arithmetic_gmw_share_exponent =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[1];
//   ShareWrapper floating_point_arithmetic_gmw_share_zero =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[2];
//   ShareWrapper floating_point_arithmetic_gmw_share_sign =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[3];

//   // case 1:
//   // p < 0, output: 0
//   ShareWrapper arithmetic_gmw_share_exponent_less_than_zero =
//       LTZ<FLType>(floating_point_arithmetic_gmw_share_exponent);

//   // case 2:
//   // p > l-1, output: mantissa * 2^(p-l+1)
//   ShareWrapper arithmetic_gmw_share_exponent_greater_than_l_minus_1 =
//       LT<FLType>(constant_arithmetic_gmw_share_l_FLType -
//       constant_arithmetic_gmw_share_one_FLType,
//                  floating_point_arithmetic_gmw_share_exponent);

//   // case 3:
//   // 0 =< p =< l-1, output: mantissa / 2^(l-1-p))
//   ShareWrapper
//       arithmetic_gmw_share_exponent_less_than_or_equal_l_minus_1_and_greater_than_or_equal_zero =
//           constant_arithmetic_gmw_share_one_FLType -
//           (arithmetic_gmw_share_exponent_less_than_zero +
//            arithmetic_gmw_share_exponent_greater_than_l_minus_1);

//   // p - l + 1
//   ShareWrapper arithmetic_gmw_share_exponent_minus_l_plus_1 =
//       floating_point_arithmetic_gmw_share_exponent - constant_arithmetic_gmw_share_l_FLType +
//       constant_arithmetic_gmw_share_one_FLType;

//   // l - 1 - p
//   ShareWrapper arithmetic_gmw_share_l_minus_1_minus_exponent =
//       constant_arithmetic_gmw_share_l_FLType - constant_arithmetic_gmw_share_one_FLType -
//       floating_point_arithmetic_gmw_share_exponent;

//   // mantissa * 2^(p-l+1)
//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa_left_shift =
//       Pow2<FLType>(arithmetic_gmw_share_exponent_minus_l_plus_1) *
//       floating_point_arithmetic_gmw_share_mantissa;

//   // mantissa / 2^(l-1-p)
//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa_truncate =
//       ObliviousTrunc<FLType>(floating_point_arithmetic_gmw_share_mantissa,
//                              arithmetic_gmw_share_l_minus_1_minus_exponent, sizeof(IntType) * 8);

//   // the integer result in FLType field
//   ShareWrapper unsigned_integer_arithemtic_gmw_share_FLType =
//       (arithmetic_gmw_share_exponent_less_than_zero * constant_arithmetic_gmw_share_zero_FLType +
//        arithmetic_gmw_share_exponent_greater_than_l_minus_1 *
//            floating_point_arithmetic_gmw_share_mantissa_left_shift +
//        arithmetic_gmw_share_exponent_less_than_or_equal_l_minus_1_and_greater_than_or_equal_zero
//        *
//            floating_point_arithmetic_gmw_share_mantissa_truncate);

//   // each party locally convert share from FLType field into IntType field
//   ShareWrapper signed_integer_arithemtic_gmw_share_sign =
//       ArithmeticValueFieldConversion<FLType, IntType>(floating_point_arithmetic_gmw_share_sign);
//   ShareWrapper signed_integer_arithemtic_gmw_share_zero =
//       ArithmeticValueFieldConversion<FLType, IntType>(floating_point_arithmetic_gmw_share_zero);
// //   ShareWrapper unsigned_integer_arithemtic_gmw_share_mantissa_left_shift =
// //       ArithmeticValueFieldConversion<FLType, IntType>(
// //           floating_point_arithmetic_gmw_share_mantissa_left_shift);
// //   ShareWrapper unsigned_integer_arithemtic_gmw_share_mantissa_truncate =
// //       ArithmeticValueFieldConversion<FLType, IntType>(
// //           floating_point_arithmetic_gmw_share_mantissa_truncate);

//   ShareWrapper unsigned_integer_arithemtic_gmw_share_IntType =
//       ArithmeticValueFieldConversion<FLType,
//       IntType>(unsigned_integer_arithemtic_gmw_share_FLType);

//   ShareWrapper signed_integer_arithemtic_gmw_share_IntType =
//       (constant_arithmetic_gmw_share_one_IntType -
//        constant_arithmetic_gmw_share_two_IntType * signed_integer_arithemtic_gmw_share_sign) *
//       (constant_arithmetic_gmw_share_one_IntType - signed_integer_arithemtic_gmw_share_zero) *
//       unsigned_integer_arithemtic_gmw_share_IntType;

// std::vector<ShareWrapper>  result_vector;
// result_vector.reserve(1);
// result_vector.emplace_back(signed_integer_arithemtic_gmw_share_IntType);

// // only for debugging
// result_vector.emplace_back(arithmetic_gmw_share_exponent_less_than_zero); // 1
// result_vector.emplace_back(arithmetic_gmw_share_exponent_greater_than_l_minus_1); // 2
// result_vector.emplace_back(arithmetic_gmw_share_exponent_less_than_or_equal_l_minus_1_and_greater_than_or_equal_zero);
// // 3 result_vector.emplace_back(unsigned_integer_arithemtic_gmw_share_FLType); // 4
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa_left_shift); // 5
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa_truncate); // 6
// result_vector.emplace_back(arithmetic_gmw_share_l_minus_1_minus_exponent); // 7
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa); // 8
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_exponent); // 9
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_zero); // 10
// result_vector.emplace_back(floating_point_arithmetic_gmw_share_sign); // 11

//   return result_vector;
// }

// template <typename FLType, typename IntType>
// std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                     const ShareWrapper& arithmetic_gmw_share_p1,
//                                                     const ShareWrapper& arithmetic_gmw_share_z1,
//                                                     const ShareWrapper& arithmetic_gmw_share_s1,
//                                                     std::size_t l, std::size_t k) {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   const ShareWrapper constant_arithmetic_gmw_share_l_FLType =
//       CreateConstantArithmeticGmwInput(FLType(l), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_zero_FLType =
//       CreateConstantArithmeticGmwInput(FLType(0), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_one_FLType =
//       CreateConstantArithmeticGmwInput(FLType(1), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_two_FLType =
//       CreateConstantArithmeticGmwInput(FLType(2), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_l_IntType =
//       CreateConstantArithmeticGmwInput(IntType(l), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_zero_IntType =
//       CreateConstantArithmeticGmwInput(IntType(0), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_one_IntType =
//       CreateConstantArithmeticGmwInput(IntType(1), num_of_simd);

//   const ShareWrapper constant_arithmetic_gmw_share_two_IntType =
//       CreateConstantArithmeticGmwInput(IntType(2), num_of_simd);

//   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x =
//       CreateFloatingPointShareVector(arithmetic_gmw_share_v1, arithmetic_gmw_share_p1,
//                                      arithmetic_gmw_share_z1, arithmetic_gmw_share_s1, l, k);

//   // round the floating-point number x to the nearest integer
//   // if x > 0, add it with 0.5, then floor(x+0.5)
//   // if x < 0, add it with -0.5, then ceil(x-0.5)
//   double constant_0_5 = 0.5;
//   std::vector<ShareWrapper> constant_floating_point_arithmetic_gmw_share_0_5 =
//       CreateConstantFloatingPointShareVector<FLType>(constant_0_5, l, k, num_of_simd);
//   constant_floating_point_arithmetic_gmw_share_0_5[3] = arithmetic_gmw_share_s1;

//   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x_plus_0_5 =
//       FLAdd_ABZS<FLType>(floating_point_arithmetic_gmw_share_x,
//                          constant_floating_point_arithmetic_gmw_share_0_5, l, k);

//   // // only for debug
//   // std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_x_plus_0_5 =
//   //       FLAdd_ABZS<FLType>(
//   // floating_point_arithmetic_gmw_share_x,floating_point_arithmetic_gmw_share_x,
//   //                          l, k);

//   //   std::size_t floor_round_mode = 0;
//   //   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_floor_x_plus_0_5 =
//   //       FLRound_ABZS<FLType>(floating_point_arithmetic_gmw_share_x_plus_0_5, floor_round_mode,
//   l,
//   //       k);
//   //   ShareWrapper floating_point_arithmetic_gmw_share_mantissa =
//   //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[0];
//   //   ShareWrapper floating_point_arithmetic_gmw_share_exponent =
//   //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[1];
//   //   ShareWrapper floating_point_arithmetic_gmw_share_zero =
//   //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[2];
//   //   ShareWrapper floating_point_arithmetic_gmw_share_sign =
//   //       floating_point_arithmetic_gmw_share_floor_x_plus_0_5[3];

//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[0];
//   ShareWrapper floating_point_arithmetic_gmw_share_exponent =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[1];
//   ShareWrapper floating_point_arithmetic_gmw_share_zero =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[2];
//   ShareWrapper floating_point_arithmetic_gmw_share_sign =
//       floating_point_arithmetic_gmw_share_x_plus_0_5[3];

//   // case 1:
//   // -l =< p < 0, output: mantissa / 2^(-p)
//   ShareWrapper arithmetic_gmw_share_exponent_less_than_zero =
//       LTZ<FLType>(floating_point_arithmetic_gmw_share_exponent);
//   ShareWrapper arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l = LTZ<FLType>(
//       constant_arithmetic_gmw_share_zero_FLType -
//       (floating_point_arithmetic_gmw_share_exponent + constant_arithmetic_gmw_share_l_FLType +
//        constant_arithmetic_gmw_share_one_FLType));
//   ShareWrapper arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l_and_less_than_zero =
//       arithmetic_gmw_share_exponent_less_than_zero *
//       arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l;

//   // case 2:
//   // p < -l, output: 0
//   ShareWrapper arithmetic_gmw_share_exponent_less_than_neg_l = LT<FLType>(
//       floating_point_arithmetic_gmw_share_exponent,
//       constant_arithmetic_gmw_share_zero_FLType - constant_arithmetic_gmw_share_l_FLType);

//   // case 3:
//   // p >= 0, output: mantissa * 2^p
//   ShareWrapper arithmetic_gmw_share_exponent_greater_than_or_equal_zero =
//       constant_arithmetic_gmw_share_one_FLType -
//       (arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l_and_less_than_zero +
//        arithmetic_gmw_share_exponent_less_than_neg_l);

//   // mantissa * 2^p
//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa_left_shift =
//       Pow2<FLType>(floating_point_arithmetic_gmw_share_exponent) *
//       floating_point_arithmetic_gmw_share_mantissa;

//   // mantissa / 2^(-p)
//   ShareWrapper floating_point_arithmetic_gmw_share_mantissa_truncate = ObliviousTrunc<FLType>(
//       floating_point_arithmetic_gmw_share_mantissa,
//       (constant_arithmetic_gmw_share_zero_FLType - floating_point_arithmetic_gmw_share_exponent),
//       l);

//   // the integer result in FLType field
//   ShareWrapper unsigned_integer_arithemtic_gmw_share_FLType =
//       (arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l_and_less_than_zero *
//            floating_point_arithmetic_gmw_share_mantissa_truncate +
//        arithmetic_gmw_share_exponent_less_than_neg_l * constant_arithmetic_gmw_share_zero_FLType
//        + arithmetic_gmw_share_exponent_greater_than_or_equal_zero *
//            floating_point_arithmetic_gmw_share_mantissa_left_shift);

//   // each party locally convert share from FLType field into IntType field
//   ShareWrapper signed_integer_arithemtic_gmw_share_sign =
//       ArithmeticValueFieldConversion<FLType, IntType>(floating_point_arithmetic_gmw_share_sign);
//   ShareWrapper signed_integer_arithemtic_gmw_share_zero =
//       ArithmeticValueFieldConversion<FLType, IntType>(floating_point_arithmetic_gmw_share_zero);
//   //   ShareWrapper unsigned_integer_arithemtic_gmw_share_mantissa_left_shift =
//   //       ArithmeticValueFieldConversion<FLType, IntType>(
//   //           floating_point_arithmetic_gmw_share_mantissa_left_shift);
//   //   ShareWrapper unsigned_integer_arithemtic_gmw_share_mantissa_truncate =
//   //       ArithmeticValueFieldConversion<FLType, IntType>(
//   //           floating_point_arithmetic_gmw_share_mantissa_truncate);

//   ShareWrapper unsigned_integer_arithemtic_gmw_share_IntType =
//       ArithmeticValueFieldConversion<FLType,
//       IntType>(unsigned_integer_arithemtic_gmw_share_FLType);

//   ShareWrapper signed_integer_arithemtic_gmw_share_IntType =
//       (constant_arithmetic_gmw_share_one_IntType -
//        constant_arithmetic_gmw_share_two_IntType * signed_integer_arithemtic_gmw_share_sign) *
//       (constant_arithmetic_gmw_share_one_IntType - signed_integer_arithemtic_gmw_share_zero) *
//       unsigned_integer_arithemtic_gmw_share_IntType;

//   std::vector<ShareWrapper> result_vector;
//   result_vector.reserve(1);
//   result_vector.emplace_back(signed_integer_arithemtic_gmw_share_IntType);

//   //   // only for debugging
//   //   result_vector.emplace_back(
//   //       arithmetic_gmw_share_exponent_greater_than_or_equal_neg_l_and_less_than_zero);     //
//   1
//   //   result_vector.emplace_back(arithmetic_gmw_share_exponent_less_than_neg_l);             //
//   2
//   //   result_vector.emplace_back(arithmetic_gmw_share_exponent_greater_than_or_equal_zero);  //
//   3
//   //   result_vector.emplace_back(unsigned_integer_arithemtic_gmw_share_FLType);              //
//   4
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa_left_shift);   //
//   5
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa_truncate);     //
//   6
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_mantissa);              //
//   7
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_exponent);              //
//   8
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_zero);                  //
//   9
//   //   result_vector.emplace_back(floating_point_arithmetic_gmw_share_sign);                  //
//   10

//   return result_vector;
// }

// template std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS<__uint128_t, std::uint8_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k);
// template std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS<__uint128_t, std::uint16_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k);
// template std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS<__uint128_t, std::uint32_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k);
// template std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS<__uint128_t, std::uint64_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k);
// template std::vector<ShareWrapper> ShareWrapper::FL2Int_ABZS<__uint128_t, __uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k);

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLSqrt_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                     const ShareWrapper& arithmetic_gmw_share_p1,
//                                                     const ShareWrapper& arithmetic_gmw_share_z1,
//                                                     const ShareWrapper& arithmetic_gmw_share_s1,
//                                                     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   double constant_double_alpha = -0.8099868542;
//   double constant_double_beta = 1.787727479;
//   double constant_double_sqrt2 = sqrt(2);

//   std::vector<ShareWrapper> constant_arithmetic_gmw_share_alpha =
//       CreateConstantFloatingPointShareVector<T>(constant_double_alpha, l, k, num_of_simd);
//   std::vector<ShareWrapper> constant_arithmetic_gmw_share_beta =
//       CreateConstantFloatingPointShareVector<T>(constant_double_beta, l, k, num_of_simd);
//   std::vector<ShareWrapper> constant_arithmetic_gmw_share_sqrt2 =
//       CreateConstantFloatingPointShareVector<T>(constant_double_sqrt2, l, k, num_of_simd);

//   //   std::vector<T> constant_zero{T(0)};
//   //  const  ShareWrapper constant_arithmetic_gmw_share_zero =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_zero);
//   ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput<T>(T(0), num_of_simd);

//   //   std::vector<T> constant_one{T(1)};
//   //  const  ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);

//   //   std::vector<T> constant_l_div_2_floor{T(floor(double(l) / 2))};
//   //   ShareWrapper constant_arithmetic_gmw_share_l_div_2_floor =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l_div_2_floor);
//   ShareWrapper constant_arithmetic_gmw_share_l_div_2_floor =
//       CreateConstantArithmeticGmwInput<T>(T(floor(double(l) / 2)), num_of_simd);

//   //   std::vector<T> constant_minus_l{T(-T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_minus_l);
//   ShareWrapper constant_arithmetic_gmw_share_minus_l =
//       CreateConstantArithmeticGmwInput<T>(T(-T(l)), num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(l), num_of_simd);

//   //   std::vector<T> constant_l_minus_1{T(T(l) - T(1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(T(l) - T(1)), num_of_simd);

//   //   std::vector<T> constant_1_minus_l{T(T(1) - T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_1_minus_l);
//   ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//       CreateConstantArithmeticGmwInput<T>(T(T(1) - T(l)), num_of_simd);

//   //   std::vector<T> constant_3_mul_pow2_l_minus_2{T(3) * (T(1) << (T(l) - 2))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_3_mul_pow2_l_minus_2 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_3_mul_pow2_l_minus_2);
//   ShareWrapper constant_arithmetic_gmw_share_3_mul_pow2_l_minus_2 =
//       CreateConstantArithmeticGmwInput<T>(T(3) * (T(1) << (T(l) - 2)), num_of_simd);

//   //   std::vector<T> constant_pow2_l_minus_1{(T(1) << (T(l) - 1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_minus_1);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//       CreateConstantArithmeticGmwInput<T>((T(1) << (T(l) - 1)), num_of_simd);

//   // x
//   std::vector<ShareWrapper> arithmetic_gmw_share_x = CreateFloatingPointShareVector(
//       arithmetic_gmw_share_v1, constant_arithmetic_gmw_share_minus_l,
//       constant_arithmetic_gmw_share_zero, constant_arithmetic_gmw_share_zero, l, k);

//   // ============================================================

//   //   // extract the least significant bit of <p1>^A
//   //   ShareWrapper boolean_value_p1 =
//   //   ArithmeticValueBitDecomposition<T>(arithmetic_gmw_share_p1); std::vector<ShareWrapper>
//   //   boolean_value_p1_vector = boolean_value_p1.Split(); ShareWrapper boolean_gmw_share_b =
//   //   boolean_value_p1_vector.front(); ShareWrapper arithmetic_gmw_share_b =
//   //   BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b);
//   //   // extract the least significant bit of l
//   //   bool l0 = l & 1;
//   //   ShareWrapper constant_boolean_gmw_share_l0 =
//   //   share_->GetBackend().ConstantBooleanGmwInput(l0);
//   //   // <c>^B = <b>^B ^ l0
//   //   ShareWrapper boolean_gmw_share_c = boolean_gmw_share_b ^ constant_boolean_gmw_share_l0;
//   //   ShareWrapper arithmetic_gmw_share_c =
//   //   BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_c);

//   //   // paper (Secure Computation on Floating Point Numbers) may contain error,
//   //   // <b>^B | l0 is not necessary,
//   //   // <b>^B | l0
//   //   //   std::cout << "<b>^B | l0" << std::endl;
//   //   //   ShareWrapper boolean_gmw_share_b_or_l0 = boolean_gmw_share_b |
//   //   //   constant_boolean_gmw_share_l0; ShareWrapper arithmetic_gmw_share_b_or_l0 =
//   //   //       BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b_or_l0);

//   //   // (<p1>^A - <b>^A) / 2
//   //   // std::cout << "(<p1>^A - <b>^A) / 2" << std::endl;
//   //   ShareWrapper arithmetic_gmw_share_p1_minus_b_div_2 =
//   //       ArithmeticRightShift<T>(arithmetic_gmw_share_p1 - arithmetic_gmw_share_b, 1);

//   //   // paper (Secure Computation on Floating Point Numbers) may contain error,
//   //   // <b>^B | l0 is not necessary,
//   //   //   ShareWrapper arithmetic_gmw_share_p = arithmetic_gmw_share_p1_minus_b_div_2 +
//   //   //                                         constant_arithmetic_gmw_share_l_div_2_floor +
//   //   //                                         arithmetic_gmw_share_b_or_l0;

//   //   ShareWrapper arithmetic_gmw_share_p =
//   //       arithmetic_gmw_share_p1_minus_b_div_2 + constant_arithmetic_gmw_share_l_div_2_floor;

//   // paper (Secure Computation on Floating Point Numbers) may contain error, line 1-2)
//   // we correct it as following:

//   ShareWrapper arithmetic_gmw_share_p1_plus_l =
//       arithmetic_gmw_share_p1 + constant_arithmetic_gmw_share_l;

//   // <p1>A = floor((<p>^A + l) / 2)
//   ShareWrapper arithmetic_gmw_share_p = ArithmeticRightShift<T>(arithmetic_gmw_share_p1_plus_l,
//   1);

//   // <c>A = lsb(<p1>A)
//   ShareWrapper boolean_gmw_share_c =
//       ArithmeticValueBitDecomposition<T>(arithmetic_gmw_share_p1_plus_l).Split()[0];
//   ShareWrapper arithmetic_gmw_share_c = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_c);

//   // alpha * x
//   // std::cout << "alpha * x" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_alpha_mul_x =
//       FLMul_ABZS<T>(arithmetic_gmw_share_x, constant_arithmetic_gmw_share_alpha, l, k);

//   // y0 = alpha * x + beta
//   // std::cout << "y0 = alpha * x + beta" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_y0 =
//       FLAdd_ABZS<T>(arithmetic_gmw_share_alpha_mul_x, constant_arithmetic_gmw_share_beta, l, k);

//   // g0 = x * y0
//   // std::cout << "g0 = x * y0" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_g0 =
//       FLMul_ABZS<T>(arithmetic_gmw_share_x, arithmetic_gmw_share_y0, l, k);

//   // h0 = y0 / 2
//   std::vector<ShareWrapper> arithmetic_gmw_share_h0 = CreateFloatingPointShareVector(
//       arithmetic_gmw_share_y0[0], arithmetic_gmw_share_y0[1] - constant_arithmetic_gmw_share_one,
//       arithmetic_gmw_share_y0[2], arithmetic_gmw_share_y0[3], l, k);

//   // 1.5 = 3 / 2
//   std::vector<ShareWrapper> constant_arithmetic_gmw_share_3_div_2 =
//       CreateConstantFloatingPointShareVector<T>(double(1.5), l, k, num_of_simd);

//   std::vector<ShareWrapper> arithmetic_gmw_share_gi = arithmetic_gmw_share_g0;
//   std::vector<ShareWrapper> arithmetic_gmw_share_hi = arithmetic_gmw_share_h0;
//   for (std::size_t i = 1; i < ceil(log2(double(l) / 5.4)); i++) {
//     // gi * hi
//     std::vector<ShareWrapper> arithmetic_gmw_share_gi_mul_hi =
//         FLMul_ABZS<T>(arithmetic_gmw_share_gi, arithmetic_gmw_share_hi, l, k);

//     // 1.5 - gi * hi
//     std::vector<ShareWrapper> arithmetic_gmw_share_3_div_2_minus_gi_mul_hi =
//         FLSub_ABZS<T>(constant_arithmetic_gmw_share_3_div_2, arithmetic_gmw_share_gi_mul_hi, l,
//         k);

//     // g_(i+1) = gi * (1.5 - gi * hi)
//     arithmetic_gmw_share_gi =
//         FLMul_ABZS<T>(arithmetic_gmw_share_gi, arithmetic_gmw_share_3_div_2_minus_gi_mul_hi, l,
//         k);

//     // h_(i+1) = hi * (1.5 - gi * hi)
//     arithmetic_gmw_share_hi =
//         FLMul_ABZS<T>(arithmetic_gmw_share_hi, arithmetic_gmw_share_3_div_2_minus_gi_mul_hi, l,
//         k);
//   }

//   // hi^2 = hi * hi
//   // std::cout << "hi^2 = hi * hi" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_hi_square =
//       FLMul_ABZS<T>(arithmetic_gmw_share_hi, arithmetic_gmw_share_hi, l, k);

//   // x * hi^2
//   // std::cout << "x * hi^2" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_x_mul_hi_square =
//       FLMul_ABZS<T>(arithmetic_gmw_share_x, arithmetic_gmw_share_hi_square, l, k);

//   // ki = 1.5 - 2 * x * hi^2
//   std::vector<ShareWrapper> arithmetic_gmw_share_ki = FLSub_ABZS<T>(
//       constant_arithmetic_gmw_share_3_div_2[0], constant_arithmetic_gmw_share_3_div_2[1],
//       constant_arithmetic_gmw_share_3_div_2[2], constant_arithmetic_gmw_share_3_div_2[3],
//       arithmetic_gmw_share_x_mul_hi_square[0],
//       arithmetic_gmw_share_x_mul_hi_square[1] + constant_arithmetic_gmw_share_one,
//       arithmetic_gmw_share_x_mul_hi_square[2], arithmetic_gmw_share_x_mul_hi_square[3], l, k);

//   // h_(i+1) = hi * ki = hi * (1.5 - 2 * x * hi^2)
//   arithmetic_gmw_share_hi = FLMul_ABZS<T>(arithmetic_gmw_share_hi, arithmetic_gmw_share_ki, l,
//   k);

//   // 2 * x * h_(i+1) -> sqrt(x)
//   std::vector<ShareWrapper> arithmetic_gmw_share_sqrt_x =
//       FLMul_ABZS<T>(arithmetic_gmw_share_x[0], arithmetic_gmw_share_x[1],
//       arithmetic_gmw_share_x[2],
//                     arithmetic_gmw_share_x[3], arithmetic_gmw_share_hi[0],
//                     arithmetic_gmw_share_hi[1] + constant_arithmetic_gmw_share_one,
//                     arithmetic_gmw_share_hi[2], arithmetic_gmw_share_hi[3], l, k);

//   std::vector<ShareWrapper> arithmetic_gmw_share_sqrt_a = CreateFloatingPointShareVector(
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c) *
//               constant_arithmetic_gmw_share_pow2_l_minus_1 +
//           arithmetic_gmw_share_c * constant_arithmetic_gmw_share_sqrt2[0],
//       (arithmetic_gmw_share_c - constant_arithmetic_gmw_share_one) *
//               constant_arithmetic_gmw_share_l_minus_1 +
//           arithmetic_gmw_share_c * constant_arithmetic_gmw_share_sqrt2[1],
//       constant_arithmetic_gmw_share_zero, constant_arithmetic_gmw_share_zero, l, k);

//   // sqrt(a * x)
//   std::vector<ShareWrapper> arithmetic_gmw_share_sqrt_a_mul_x =
//       FLMul_ABZS<T>(arithmetic_gmw_share_sqrt_x, arithmetic_gmw_share_sqrt_a, l, k);

//   ShareWrapper arithmetic_gmw_share_p_prime =
//       (arithmetic_gmw_share_sqrt_a_mul_x[1] + arithmetic_gmw_share_p) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1);

//   // only for debug
//   //   ShareWrapper arithmetic_gmw_share_p_prime =
//   //       (arithmetic_gmw_share_sqrt_a_mul_x[1] + arithmetic_gmw_share_p);

//   ShareWrapper arithmetic_gmw_share_v =
//       arithmetic_gmw_share_sqrt_a_mul_x[0] *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1);

//   ShareWrapper arithmetic_gmw_share_error = arithmetic_gmw_share_s1;

//   std::vector<ShareWrapper> floating_point_sqrt_result;
//   floating_point_sqrt_result.reserve(4);
//   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_v);        // 0
//   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_p_prime);  // 1
//   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_z1);       // 2
//   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_s1);       // 3
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_error);    // 4

//   //   // only for debug
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_v1);     // 5
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_h0[0]);  // 6
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_h0[1]);  // 7
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_h0[2]);  // 8
//   //   floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_h0[3]);  // 9
//   // floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_v1);                // 7
//   // floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_c);                // 8
//   // floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_p);                // 9
//   // floating_point_sqrt_result.emplace_back(arithmetic_gmw_share_sqrt_a_mul_x[1]);  // 10

//   return floating_point_sqrt_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLSqrt_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k) const;

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLExp2_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                     const ShareWrapper& arithmetic_gmw_share_p1,
//                                                     const ShareWrapper& arithmetic_gmw_share_z1,
//                                                     const ShareWrapper& arithmetic_gmw_share_s1,
//                                                     std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   //   std::vector<T> constant_zero{T(0)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_zero =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_zero);
//   const ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput(T(0), num_of_simd);

//   //   std::vector<T> constant_one{T(1)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   const ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   const ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   //   std::vector<T> constant_l{T(l)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l);
//   const ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput(T(l), num_of_simd);

//   //   std::vector<T> constant_l_div_2_floor{T(floor(double(l) / 2))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_l_div_2_floor =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l_div_2_floor);
//   const ShareWrapper constant_arithmetic_gmw_share_l_div_2_floor =
//       CreateConstantArithmeticGmwInput(T(floor(double(l) / 2)), num_of_simd);

//   //   std::vector<T> constant_minus_l{T(-T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_minus_l);
//   const ShareWrapper constant_arithmetic_gmw_share_minus_l =
//       CreateConstantArithmeticGmwInput(T(-T(l)), num_of_simd);

//   //   std::vector<T> constant_l_minus_1{T(T(l) - T(1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l_minus_1);
//   const ShareWrapper constant_arithmetic_gmw_share_l_minus_1 =
//       CreateConstantArithmeticGmwInput(T(T(l) - T(1)), num_of_simd);

//   //   std::vector<T> constant_1_minus_l{T(T(1) - T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_1_minus_l);
//   const ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//       CreateConstantArithmeticGmwInput(T(T(1) - T(l)), num_of_simd);

//   //   std::vector<T> constant_1_minus_2_mul_l{T(T(1) - 2 * T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_1_minus_2_mul_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_1_minus_2_mul_l);
//   const ShareWrapper constant_arithmetic_gmw_share_1_minus_2_mul_l =
//       CreateConstantArithmeticGmwInput(T(T(1) - 2 * T(l)), num_of_simd);

//   //   std::vector<T> constant_3_mul_pow2_l_minus_2{T(3) * (T(1) << (T(l) - 2))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_3_mul_pow2_l_minus_2 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_3_mul_pow2_l_minus_2);
//   const ShareWrapper constant_arithmetic_gmw_share_3_mul_pow2_l_minus_2 =
//       CreateConstantArithmeticGmwInput(T(3) * (T(1) << (T(l) - 2)), num_of_simd);

//   //   std::vector<T> constant_pow2_l_minus_1{(T(1) << (T(l) - 1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_minus_1);
//   const ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//       CreateConstantArithmeticGmwInput((T(1) << (T(l) - 1)), num_of_simd);

//   //   std::vector<T> constant_pow2_k_minus_1{(T(1) << (T(k) - 1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_1 =
//   //   share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_k_minus_1);
//   const ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_1 =
//       CreateConstantArithmeticGmwInput((T(1) << (T(k) - 1)), num_of_simd);

//   //   std::vector<T> constant_pow2_l{(T(1) << (T(l)))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//   //   share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l);
//   const ShareWrapper constant_arithmetic_gmw_share_pow2_l =
//       CreateConstantArithmeticGmwInput((T(1) << (T(l))), num_of_simd);

//   T max = int(ceil(log2(std::int64_t(T(1) << (k - 1)) - 1 + l) - std::int64_t(l) + 1));

//   //   std::vector<T> constant_max{T(max)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_max =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_max);
//   const ShareWrapper constant_arithmetic_gmw_share_max =
//       CreateConstantArithmeticGmwInput(T(max), num_of_simd);

//   //  <a>^A = <p1>^A < max
//   ShareWrapper arithmetic_gmw_share_a =
//       LT<T>(arithmetic_gmw_share_p1, constant_arithmetic_gmw_share_max);

//   // <b>^A = <p1>^A < (1-l)
//   ShareWrapper arithmetic_gmw_share_b =
//       LT<T>(arithmetic_gmw_share_p1, constant_arithmetic_gmw_share_1_minus_l);

//   // <c>^A = <p1>^A < (1 - 2l)
//   ShareWrapper arithmetic_gmw_share_c =
//       LT<T>(arithmetic_gmw_share_p1, constant_arithmetic_gmw_share_1_minus_2_mul_l);

//   // (1 - <c>^A) * <a>^A
//   ShareWrapper arithmetic_gmw_share_1_minus_c_mul_a =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_c) * arithmetic_gmw_share_a;

//   // <p2>^A = -(1 - <c>^A) * <a>^A * (<b>^A * l + <p1>^A)
//   ShareWrapper arithmetic_gmw_share_p2 =
//       (constant_arithmetic_gmw_share_zero - arithmetic_gmw_share_1_minus_c_mul_a) *
//       (arithmetic_gmw_share_b * constant_arithmetic_gmw_share_l + arithmetic_gmw_share_p1);

//   // we always have <p2>^A < l
//   ShareWrapper arithmetic_gmw_share_x =
//       ObliviousTrunc<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_p2, l);

//   // <2^p2>^A
//   ShareWrapper arithmetic_gmw_share_pow2_p2 = Pow2<T>(arithmetic_gmw_share_p2);

//   // <y>^A = <v1>^A - <x>^A * <2^p2>^A
//   ShareWrapper arithmetic_gmw_share_y =
//       arithmetic_gmw_share_v1 - arithmetic_gmw_share_x * arithmetic_gmw_share_pow2_p2;

//   // <d>^B = <y>^A == 0
//   ShareWrapper boolean_gmw_share_d = EQZ<T>(arithmetic_gmw_share_y);

//   // <d>^A
//   ShareWrapper arithmetic_gmw_share_d = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_d);

//   // <b>^A * <s1>^A
//   ShareWrapper arithmetic_gmw_share_b_mul_s1 = arithmetic_gmw_share_b * arithmetic_gmw_share_s1;

//   // (1 - <d>^A) * <s1>^A
//   ShareWrapper arithmetic_gmw_share_1_minus_d_mul_s1 =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_d) * arithmetic_gmw_share_s1;

//   // Note: original paper contain errors: x' = (1 - b * s1) * (x - (1 - d) * s1) + b * s1 * (2^l
//   -
//   // 1
//   // + d - x), it should be x' = (1 - b * s1) * (x + (1 - d) * s1) + b * s1 * (2^l - 1 + d - x).
//   // <x'>^A = (1 - <b>^A * <s1>^A) * (<x>^A + (1 - <d>^A) * <s1>^A) + <b>^A * <s1>^A * (2^l - 1 +
//   // <d>^A - <x>^A)
//   ShareWrapper arithmetic_gmw_share_x_prime =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b_mul_s1) *
//           (arithmetic_gmw_share_x + arithmetic_gmw_share_1_minus_d_mul_s1) +
//       arithmetic_gmw_share_b_mul_s1 *
//           (constant_arithmetic_gmw_share_pow2_l - constant_arithmetic_gmw_share_one +
//            arithmetic_gmw_share_d - arithmetic_gmw_share_x);

//   // <y'>^A = (1 - <d>^A) * <s1>^A * (<2^p2>^A - <y>^A) +(1 - <s1>^A) * <y>^A
//   ShareWrapper arithmetic_gmw_share_y_prime =
//       arithmetic_gmw_share_1_minus_d_mul_s1 *
//           (arithmetic_gmw_share_pow2_p2 - arithmetic_gmw_share_y) +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_s1) * arithmetic_gmw_share_y;

//   // <w>^A = ((1 - <c>^A) * <a>^A) * ((1 - <b>^A) * <x>^A + <b>^A * <s1>^A) * (1 - 2 * <s1>^A) -
//   // <c>^A * <s1>^A
//   ShareWrapper arithmetic_gmw_share_w =
//       arithmetic_gmw_share_1_minus_c_mul_a *
//           ((constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b) *
//                arithmetic_gmw_share_x_prime +
//            arithmetic_gmw_share_b_mul_s1) *
//           (constant_arithmetic_gmw_share_one -
//            constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1) -
//       arithmetic_gmw_share_c * arithmetic_gmw_share_s1;

//   // <2^(l-p2)>^A
//   ShareWrapper arithmetic_gmw_share_pow2_l_minus_p2 =
//       Pow2<T>(constant_arithmetic_gmw_share_l - arithmetic_gmw_share_p2);

//   // <u>^A = (1 - <c>^A) * <a>^A * (<b>^A * <x>^A + (1 - <b>^A) * <2^(l-p2)>^A * <y>^A) + (2^l
//   -1)
//   // * <c>^A * <s1>^A
//   ShareWrapper arithmetic_gmw_share_u =
//       arithmetic_gmw_share_1_minus_c_mul_a *
//           (arithmetic_gmw_share_b * arithmetic_gmw_share_x_prime +
//            (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_b) *
//                arithmetic_gmw_share_pow2_l_minus_p2 * arithmetic_gmw_share_y_prime) +
//       (constant_arithmetic_gmw_share_pow2_l - constant_arithmetic_gmw_share_one) *
//           arithmetic_gmw_share_c * arithmetic_gmw_share_s1;

//   // TODO:: trunc arithmetic gmw share for bit decompose

//   // <u_0>^B, ..., <u_(l-1)>^B = BitDec(<u>^A)
//   ShareWrapper boolean_gmw_share_u = arithmetic_gmw_share_u.Convert<MpcProtocol::kBooleanGmw>();
//   std::vector<ShareWrapper> boolean_gmw_share_u_vector = boolean_gmw_share_u.Split();

//   // <u_0>^A, ..., <u_(l-1)>^A
//   std::vector<ShareWrapper> arithmetic_gmw_share_u_vector;
//   arithmetic_gmw_share_u_vector.reserve(boolean_gmw_share_u_vector.size());
//   for (std::size_t i = 0; i < l; ++i) {
//     arithmetic_gmw_share_u_vector.emplace_back(
//         BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_u_vector[i]));
//   }

//   ShareWrapper cvi;
//   ShareWrapper cpi;

//   ShareWrapper ai;
//   ShareWrapper bi;

//   std::vector<FloatingPointShareStruct> floating_point_share_struct_ab_vector;
//   floating_point_share_struct_ab_vector.reserve(l);

//   // ! original paper contain error, it should be
//   // <a_i>^A = 2^(l-1) * (1 - <u_(l-i)>^A) + <cv_i>^A * <u_(l-i)>^A
//   // <b_i>^A = -(l - 1) * (1 - <u_(l-i)>^A) + <cp_i>^A * <u_(l-i)>^A
//   for (std::size_t i = 1; i <= l; ++i) {
//     double floating_point_c = pow(2, pow(2, -std::int64_t(i)));
//     std::vector<ShareWrapper> arithmetic_gmw_share_c_vector =
//         CreateConstantFloatingPointShareVector<T>(floating_point_c, l, k, num_of_simd);
//     cvi = arithmetic_gmw_share_c_vector[0];
//     cpi = arithmetic_gmw_share_c_vector[1];

//     ai = constant_arithmetic_gmw_share_pow2_l_minus_1 *
//              (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_u_vector[l - i]) +
//          cvi * arithmetic_gmw_share_u_vector[l - i];

//     bi = constant_arithmetic_gmw_share_1_minus_l *
//              (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_u_vector[l - i]) +
//          cpi * arithmetic_gmw_share_u_vector[l - i];

//     FloatingPointShareStruct floating_point_share_struct_ab = CreateFloatingPointShareStruct(
//         ai, bi, constant_arithmetic_gmw_share_zero, constant_arithmetic_gmw_share_zero, l, k);

//     floating_point_share_struct_ab_vector.emplace_back(floating_point_share_struct_ab);
//   }

//   std::size_t head = 0;
//   std::size_t tail = floating_point_share_struct_ab_vector.size() - 1;

//   // only for test
//   // tail = 4;

//   // ============================================================
//   // TODO:: FLProd takes too much memory, optimize
//   FloatingPointShareStruct floating_point_share_struct_u =
//       FLProd_ABZS<T>(floating_point_share_struct_ab_vector, head, tail, l, k);
//   // ============================================================
//   // use SIMD to parallelize FLProd_ABZS

//   // ============================================================

//   ShareWrapper arithmetic_gmw_share_vu = floating_point_share_struct_u.mantissa;
//   ShareWrapper arithmetic_gmw_share_pu = floating_point_share_struct_u.exponent;

//   // <p> = <a>^A * (<w>^A + <pu>^A) + 2^(k-1) * (1 - <a>^A) * (1 - 2 * <s1>^A)
//   ShareWrapper arithmetic_gmw_share_p =
//       arithmetic_gmw_share_a * (arithmetic_gmw_share_w + arithmetic_gmw_share_pu) +
//       constant_arithmetic_gmw_share_pow2_k_minus_1 *
//           (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_a) *
//           (constant_arithmetic_gmw_share_one -
//            constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s1);

//   // <v>^A = 2^(l-1) * <z1>^A + (1 - <z1>^A) * <vu>^A
//   ShareWrapper arithmetic_gmw_share_v =
//       constant_arithmetic_gmw_share_pow2_l_minus_1 * arithmetic_gmw_share_z1 +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1) * arithmetic_gmw_share_vu;

//   // <p'>^A = <z1>^A * (1 - l) + (1 - <z1>^A)* <p>^A
//   ShareWrapper arithmetic_gmw_share_p_prime =
//       arithmetic_gmw_share_z1 *
//           (constant_arithmetic_gmw_share_one - constant_arithmetic_gmw_share_l) +
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z1) * arithmetic_gmw_share_p;

//   std::vector<ShareWrapper> floating_point_exp2_result;
//   floating_point_exp2_result.reserve(4);
//   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_v);              // 0
//   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p_prime);        // 1
//   floating_point_exp2_result.emplace_back(constant_arithmetic_gmw_share_zero);  // 2
//   floating_point_exp2_result.emplace_back(constant_arithmetic_gmw_share_zero);  // 3

//   // // only for debug
//   //
//   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p1-constant_arithmetic_gmw_share_max);
//   //
//   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p1-constant_arithmetic_gmw_share_max);
//   // floating_point_exp2_result.emplace_back(arithmetic_gmw_share_a);
//   // floating_point_exp2_result.emplace_back(arithmetic_gmw_share_a);
//   // floating_point_exp2_result.emplace_back(arithmetic_gmw_share_a);

//   //   // only for debug
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_a);        // 4
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_b);        // 5
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_c);        // 6
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p2);       // 7
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_x);        // 8
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_pow2_p2);  // 9
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_y);        // 10
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_d);        // 11
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_x_prime);  // 12
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_y_prime);  // 13
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_w);        // 14
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_u);        // 15
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_vu);       // 16
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_pu);       // 17
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p);        // 18
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_v);        // 19
//   //   floating_point_exp2_result.emplace_back(arithmetic_gmw_share_p_prime);  // 20

//   return floating_point_exp2_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLExp2_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k) const;

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLExp_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                    const ShareWrapper& arithmetic_gmw_share_p1,
//                                                    const ShareWrapper& arithmetic_gmw_share_z1,
//                                                    const ShareWrapper& arithmetic_gmw_share_s1,
//                                                    std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();
//   std::vector<ShareWrapper> constant_floating_point_share_vector_log2_e =
//       CreateConstantFloatingPointShareVector<T>(double(M_LOG2E), l, k, num_of_simd);

//   std::vector<ShareWrapper> floating_point_share_vector_x_mul_log2e =
//       FLMul_ABZS<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_p1, arithmetic_gmw_share_z1,
//                     arithmetic_gmw_share_s1, constant_floating_point_share_vector_log2_e[0],
//                     constant_floating_point_share_vector_log2_e[1],
//                     constant_floating_point_share_vector_log2_e[2],
//                     constant_floating_point_share_vector_log2_e[3], l, k);

//   std::vector<ShareWrapper> floating_point_share_vector_pow_e_x_mul = FLExp2_ABZS<T>(
//       floating_point_share_vector_x_mul_log2e[0], floating_point_share_vector_x_mul_log2e[1],
//       floating_point_share_vector_x_mul_log2e[2], floating_point_share_vector_x_mul_log2e[3], l,
//       k);

//   return floating_point_share_vector_pow_e_x_mul;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLExp_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k) const;

// // TODO: very time/memory comsuing, optimize
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLLog2_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                     const ShareWrapper& arithmetic_gmw_share_p1,
//                                                     const ShareWrapper& arithmetic_gmw_share_z1,
//                                                     const ShareWrapper& arithmetic_gmw_share_s1,
//                                                     std::size_t l, std::size_t k) const {
//   //   std::cout << "ShareWrapper::FLLog2_ABZS" << std::endl;

//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();
//   //   std::cout << "num_of_simd: " << num_of_simd << std::endl;

//   //   std::vector<T> constant_zero{T(0)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_zero =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_zero);
//   const ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput(T(0), num_of_simd);

//   //   std::vector<T> constant_one{T(1)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_one =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_one);
//   const ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput(T(1), num_of_simd);

//   //   std::vector<T> constant_two{T(2)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_two =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_two);
//   const ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput(T(2), num_of_simd);

//   //   std::vector<T> constant_minus_l{-T(l)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_minus_l);
//   const ShareWrapper constant_arithmetic_gmw_share_minus_l =
//       CreateConstantArithmeticGmwInput(-T(l), num_of_simd);

//   //   std::vector<T> constant_l{T(l)};
//   //   const ShareWrapper constant_arithmetic_gmw_share_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_l);
//   const ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput(T(l), num_of_simd);

//   //   std::vector<T> constant_1_minus_l{T(T(1) - T(l))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_1_minus_l);
//   const ShareWrapper constant_arithmetic_gmw_share_1_minus_l =
//       CreateConstantArithmeticGmwInput(T(T(1) - T(l)), num_of_simd);

//   //   std::vector<T> constant_pow2_l_minus_1{(T(1) << (T(l) - 1))};
//   //   const ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//   //       share_->GetBackend().ConstantArithmeticGmwInput(constant_pow2_l_minus_1);
//   const ShareWrapper constant_arithmetic_gmw_share_pow2_l_minus_1 =
//       CreateConstantArithmeticGmwInput((T(1) << (T(l) - 1)), num_of_simd);

//   std::size_t M = ceil(double(l) / (2 * log2(3)) - 0.5);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_constant_one =
//       CreateConstantFloatingPointShareVector(T(1) << (T(l) - 1), T(1) - T(l), T(0), T(0), l, k,
//                                              num_of_simd);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_v_mul_2_minus_l =
//       CreateFloatingPointShareVector(arithmetic_gmw_share_v1,
//       constant_arithmetic_gmw_share_minus_l,
//                                      constant_arithmetic_gmw_share_zero,
//                                      constant_arithmetic_gmw_share_zero, l, k);

//   //   std::cout << "FLLog2_ABZS 000" << std::endl;

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l =
//       FLSub_ABZS<T>(arithmetic_gmw_share_floating_point_constant_one,
//                     arithmetic_gmw_share_floating_point_v_mul_2_minus_l, l, k);

//   //   // only for testing
//   //   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l =
//   //       FLAdd_ABZS<T>(arithmetic_gmw_share_floating_point_v_mul_2_minus_l,
//   //                     arithmetic_gmw_share_floating_point_v_mul_2_minus_l, l, k);

//   //   std::cout << "FLLog2_ABZS 111" << std::endl;
//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_1_plus_v_mul_2_minus_l =
//       FLAdd_ABZS<T>(arithmetic_gmw_share_floating_point_constant_one,
//                     arithmetic_gmw_share_floating_point_v_mul_2_minus_l, l, k);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_y =
//       FLDiv_ABZS<T>(arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l,
//                     arithmetic_gmw_share_floating_point_1_plus_v_mul_2_minus_l);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_y_square = FLMul_ABZS<T>(
//       arithmetic_gmw_share_floating_point_y, arithmetic_gmw_share_floating_point_y, l, k);
//   double c0 = 2 * log2(std::numbers::e);
//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_c0 =
//       CreateConstantFloatingPointShareVector<T>(c0, l, k, num_of_simd);
//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_y_mul_c0 = FLMul_ABZS<T>(
//       arithmetic_gmw_share_floating_point_y, arithmetic_gmw_share_floating_point_c0, l, k);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_sum_y_2i_plus_1_mul_ci =
//       arithmetic_gmw_share_floating_point_y_mul_c0;
//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_y_2i_plus_1 =
//       arithmetic_gmw_share_floating_point_y;

//   // ============================================================
//   // very time comsuming
//   for (std::size_t i = 1; i <= M; i++) {
//     arithmetic_gmw_share_floating_point_y_2i_plus_1 =
//         FLMul_ABZS<T>(arithmetic_gmw_share_floating_point_y_2i_plus_1,
//                       arithmetic_gmw_share_floating_point_y_square, l, k);

//     double ci = 2 * log2(std::numbers::e) / (2 * i + 1);
//     std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_c =
//         CreateConstantFloatingPointShareVector<T>(ci, l, k, num_of_simd);

//     std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_y_2i_plus_1_mul_c =
//         FLMul_ABZS<T>(arithmetic_gmw_share_floating_point_y_2i_plus_1,
//                       arithmetic_gmw_share_floating_point_c, l, k);

//     arithmetic_gmw_share_floating_point_sum_y_2i_plus_1_mul_ci =
//         FLAdd_ABZS<T>(arithmetic_gmw_share_floating_point_sum_y_2i_plus_1_mul_ci,
//                       arithmetic_gmw_share_floating_point_y_2i_plus_1_mul_c, l, k);
//   }
//   // ============================================================
//   // TODO: use SIMD to parallelize

//   // ============================================================

//   ShareWrapper arithmetic_gmw_share_p1_plus_l =
//       arithmetic_gmw_share_p1 + constant_arithmetic_gmw_share_l;

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_l_plus_p_vector =
//       Int2FL_ABZS<T>(arithmetic_gmw_share_p1_plus_l);

//   std::vector<ShareWrapper> arithmetic_gmw_share_floating_point_log_x =
//       FLSub_ABZS<T>(arithmetic_gmw_share_floating_point_l_plus_p_vector,
//                     arithmetic_gmw_share_floating_point_sum_y_2i_plus_1_mul_ci, l, k);

//   //   std::cout << "FLLog2_ABZS 222" << std::endl;

//   ShareWrapper boolean_gmw_share_a =
//       EQ<T>(arithmetic_gmw_share_p1, constant_arithmetic_gmw_share_1_minus_l);
//   ShareWrapper boolean_gmw_share_b =
//       EQ<T>(arithmetic_gmw_share_v1, constant_arithmetic_gmw_share_pow2_l_minus_1);

//   //   std::cout << "FLLog2_ABZS 333" << std::endl;
//   ShareWrapper arithmetic_gmw_share_a = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_a);
//   ShareWrapper arithmetic_gmw_share_b = BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b);

//   //   std::cout << "FLLog2_ABZS 444" << std::endl;
//   ShareWrapper arithmetic_gmw_share_z = arithmetic_gmw_share_a * arithmetic_gmw_share_b;

//   ShareWrapper arithmetic_gmw_share_v_prime_prime =
//       arithmetic_gmw_share_floating_point_log_x[0] *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);
//   ShareWrapper arithmetic_gmw_share_p_prime_prime =
//       arithmetic_gmw_share_floating_point_log_x[1] *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   std::vector<ShareWrapper> floating_point_log2_result;
//   floating_point_log2_result.reserve(4);
//   floating_point_log2_result.emplace_back(arithmetic_gmw_share_v_prime_prime);
//   floating_point_log2_result.emplace_back(arithmetic_gmw_share_p_prime_prime);
//   floating_point_log2_result.emplace_back(arithmetic_gmw_share_z);
//   floating_point_log2_result.emplace_back(arithmetic_gmw_share_s1);

//   // only for debug
//   floating_point_log2_result.emplace_back(arithmetic_gmw_share_p1_plus_l);

//   floating_point_log2_result.emplace_back(
//       arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l[0]);  // 5
//   floating_point_log2_result.emplace_back(
//       arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l[1]);  // 6
//   floating_point_log2_result.emplace_back(
//       arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l[2]);  // 7
//   floating_point_log2_result.emplace_back(
//       arithmetic_gmw_share_floating_point_1_minus_v_mul_2_minus_l[3]);  // 8

//   return floating_point_log2_result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLLog2_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k) const;

// // added by Liang Zhao
// // compute ln(<x>^A)
// // based on paper (Secure Computation on Floating Point Numbers (may contain errors), SCALE-MAMBA
// // v1.14: Documentation)
// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLLn_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
//                                                   const ShareWrapper& arithmetic_gmw_share_p1,
//                                                   const ShareWrapper& arithmetic_gmw_share_z1,
//                                                   const ShareWrapper& arithmetic_gmw_share_s1,
//                                                   std::size_t l, std::size_t k) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_v1->GetNumberOfSimdValues();

//   std::vector<ShareWrapper> floating_point_share_vector_ln_x =
//       FLLog2_ABZS<T>(arithmetic_gmw_share_v1, arithmetic_gmw_share_p1, arithmetic_gmw_share_z1,
//                      arithmetic_gmw_share_s1, l, k);

//   std::vector<ShareWrapper> constant_floating_point_share_vector_ln_2 =
//       CreateConstantFloatingPointShareVector<T>(double(M_LN2), l, k, num_of_simd);

//   std::vector<ShareWrapper> floating_point_share_vector_ln_x_mul_ln_2 =
//       FLMul_ABZS<T>(floating_point_share_vector_ln_x, constant_floating_point_share_vector_ln_2);

//   return floating_point_share_vector_ln_x_mul_ln_2;
// }

// template std::vector<ShareWrapper> ShareWrapper::FLLn_ABZS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
//     const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
//     std::size_t l, std::size_t k) const;

// // ------------------------------------------------------------

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLAdd_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_2, std::size_t l, std::size_t k) const
//     {
//   std::vector<ShareWrapper> result =
//       FLAdd_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                     arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                     arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                     arithmetic_gmw_share_2[3], l, k);

//   return result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLSub_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_2, std::size_t l, std::size_t k) const
//     {
//   std::vector<ShareWrapper> result =
//       FLSub_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                     arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                     arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                     arithmetic_gmw_share_2[3], l, k);

//   return result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLDiv_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_2, std::size_t l, std::size_t k) const
//     {
//   std::vector<ShareWrapper> result =
//       FLDiv_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                     arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                     arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                     arithmetic_gmw_share_2[3], l, k);
//   return result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLMul_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_2, std::size_t l, std::size_t k) const
//     {
//   std::vector<ShareWrapper> result =
//       FLMul_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                     arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                     arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                     arithmetic_gmw_share_2[3], l, k);
//   return result;
// }

// template <typename T>
// ShareWrapper ShareWrapper::FLLT_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//                                      const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
//                                      std::size_t l, std::size_t k) const {
//   ShareWrapper result =
//       FLLT_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                    arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                    arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                    arithmetic_gmw_share_2[3], l, k);
//   return result;
// }

// template <typename T>
// ShareWrapper ShareWrapper::FLEQ_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
//                                      const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
//                                      std::size_t l, std::size_t k) const {
//   ShareWrapper result =
//       FLEQ_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//       arithmetic_gmw_share_1[2],
//                    arithmetic_gmw_share_1[3], arithmetic_gmw_share_2[0],
//                    arithmetic_gmw_share_2[1], arithmetic_gmw_share_2[2],
//                    arithmetic_gmw_share_2[3], l, k);
//   return result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLRound_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1, std::size_t mode, std::size_t l,
//     std::size_t k) const {
//   std::vector<ShareWrapper> result =
//       FLRound_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//                       arithmetic_gmw_share_1[2], arithmetic_gmw_share_1[3], mode, l, k);
//   return result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FLSqrt_ABZS(
//     const std::vector<ShareWrapper>& arithmetic_gmw_share_1, std::size_t l, std::size_t k) const
//     {
//   std::vector<ShareWrapper> result =
//       FLSqrt_ABZS<T>(arithmetic_gmw_share_1[0], arithmetic_gmw_share_1[1],
//                      arithmetic_gmw_share_1[2], arithmetic_gmw_share_1[3], l, k);
//   return result;
// }

// // ------------------------------------------------------------
// // TODO:: wrap all method with floating-point struct
// template <typename T>
// FloatingPointShareStruct ShareWrapper::FLMul_ABZS(
//     const FloatingPointShareStruct& arithmetic_gmw_share_1,
//     const FloatingPointShareStruct& arithmetic_gmw_share_2, std::size_t l, std::size_t k) const {
//   std::vector<ShareWrapper> result_vector = FLMul_ABZS<T>(
//       arithmetic_gmw_share_1.mantissa, arithmetic_gmw_share_1.exponent,
//       arithmetic_gmw_share_1.zero, arithmetic_gmw_share_1.sign, arithmetic_gmw_share_2.mantissa,
//       arithmetic_gmw_share_2.exponent, arithmetic_gmw_share_2.zero, arithmetic_gmw_share_2.sign,
//       l, k);

//   FloatingPointShareStruct result_struct;
//   result_struct.mantissa = result_vector[0];
//   result_struct.exponent = result_vector[1];
//   result_struct.zero = result_vector[2];
//   result_struct.sign = result_vector[3];

//   return result_struct;
// }

// // added by Liang Zhao
// // floating-point numbers product with log(n) multiplications
// // a0 * a1 * ... * a_(n-1)
// template <typename T>
// FloatingPointShareStruct ShareWrapper::FLProd_ABZS(
//     const std::vector<FloatingPointShareStruct>& floating_point_struct_vector, std::size_t head,
//     std::size_t tail, std::size_t l, std::size_t k) const {
//   //   std::cout << "head: " << head << ", ";
//   //   std::cout << "tail: " << tail << std::endl;

//   if (tail - head == 0) {
//     //        std::cout << "floating_point_vector[0]: " <<
//     //        FloatingPointToDouble<T>(floating_point_vector[head], l, k) << std::endl;
//     return floating_point_struct_vector[head];
//   } else {
//     std::size_t mid = int(head + (tail - head) / 2);

//     // std::cout << "mid: " << mid << std::endl;

//     FloatingPointShareStruct result_left =
//         FLProd_ABZS<T>(floating_point_struct_vector, head, mid, l, k);

//     FloatingPointShareStruct result_right =
//         FLProd_ABZS<T>(floating_point_struct_vector, mid + 1, tail, l, k);

//     // TODO: cause high memory usage
//     FloatingPointShareStruct product_result = FLMul_ABZS<T>(result_left, result_right, l, k);
//     return product_result;

//     // std::cout << "compute mul" << std::endl;

//     // only for debug
//     // return result_left;
//   }
// }

// FixedPointShareStruct ShareWrapper::CreateFixedPointShareStruct(
//     const ShareWrapper& arithmetic_gmw_share_v, std::size_t k, std::size_t f) const {
//   FixedPointShareStruct fixed_point_share_struct;
//   fixed_point_share_struct.v = arithmetic_gmw_share_v;
//   fixed_point_share_struct.k = k;
//   fixed_point_share_struct.f = f;

//   return fixed_point_share_struct;
// }

// // added by Liang Zhao
// template <typename T>
// FixedPointShareStruct ShareWrapper::CreateFixedPointShareStruct(T v, std::size_t k, std::size_t
// f,
//                                                                 std::size_t num_of_simd) const {
//   ShareWrapper constant_arithmetic_gmw_share_v =
//       CreateConstantArithmeticGmwInput<T>(v, num_of_simd);

//   FixedPointShareStruct fixed_point_share_struct;
//   fixed_point_share_struct.v = constant_arithmetic_gmw_share_v;
//   fixed_point_share_struct.k = k;
//   fixed_point_share_struct.f = f;

//   return fixed_point_share_struct;
// }

// // added by Liang Zhao
// template <typename T>
// FixedPointShareStruct ShareWrapper::CreateFixedPointShareStruct(double fixed_point_number,
//                                                                 std::size_t k, std::size_t f,
//                                                                 std::size_t num_of_simd) const {
//   //   FixedPointStruct<T> fixed_point_struct = CreateFixedPointStruct<T>(fixed_point_number, k,
//   f); FixedPointVectorStruct<T> fixed_point_vector_struct =
//       CreateFixedPointVectorStruct<T>(fixed_point_number, k, f, num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_v =
//       CreateConstantArithmeticGmwInput<T>(fixed_point_vector_struct.v_vector);

//   FixedPointShareStruct fixed_point_share_struct;
//   fixed_point_share_struct.v = constant_arithmetic_gmw_share_v;
//   fixed_point_share_struct.k = k;
//   fixed_point_share_struct.f = f;

//   return fixed_point_share_struct;
// }

// template FixedPointShareStruct ShareWrapper::CreateFixedPointShareStruct<__uint128_t>(
//     double fixed_point_number, std::size_t k, std::size_t f, std::size_t num_of_simd) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxAdd_CS(const FixedPointShareStruct& fixed_point_a,
//                                              const FixedPointShareStruct& fixed_point_b) const {
//   FixedPointShareStruct fixed_point_addition_result;
//   fixed_point_addition_result.v = fixed_point_a.v + fixed_point_b.v;
//   fixed_point_addition_result.k = fixed_point_a.k;
//   fixed_point_addition_result.f = fixed_point_a.f;

//   return fixed_point_addition_result;
// }

// template FixedPointShareStruct ShareWrapper::FxAdd_CS<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, const FixedPointShareStruct& fixed_point_b)
//     const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxSub_CS(const FixedPointShareStruct& fixed_point_a,
//                                              const FixedPointShareStruct& fixed_point_b) const {
//   FixedPointShareStruct fixed_point_subtraction_result;
//   fixed_point_subtraction_result.v = fixed_point_a.v - fixed_point_b.v;
//   fixed_point_subtraction_result.k = fixed_point_a.k;
//   fixed_point_subtraction_result.f = fixed_point_a.f;

//   return fixed_point_subtraction_result;
// }

// template FixedPointShareStruct ShareWrapper::FxSub_CS<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, const FixedPointShareStruct& fixed_point_b)
//     const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxMul_CS(const FixedPointShareStruct& fixed_point_a,
//                                              const FixedPointShareStruct& fixed_point_b) const {
//   FixedPointShareStruct fixed_point_multiplication_result;

//   //        ShareWrapper arithmetic_gmw_share_multiplication = fixed_point_a.v * fixed_point_b.v;
//   // TODO: use TruncPr, improve performance?
//   fixed_point_multiplication_result.v =
//       ArithmeticRightShift<T>(fixed_point_a.v * fixed_point_b.v, fixed_point_a.f);
//   fixed_point_multiplication_result.k = fixed_point_a.k;
//   fixed_point_multiplication_result.f = fixed_point_a.f;

//   return fixed_point_multiplication_result;
// }

// template FixedPointShareStruct ShareWrapper::FxMul_CS<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, const FixedPointShareStruct& fixed_point_b)
//     const;

// template <typename T, typename T_int>
// FixedPointShareStruct ShareWrapper::FxDivSimple_CS(const FixedPointShareStruct& fixed_point_a,
//                                                    const T fixed_point_b) const {
//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   double fixed_point_b_double =
//       FixedPointToDouble<T, T_int>(fixed_point_b, fixed_point_a.k, fixed_point_a.f);
//   std::cout << "fixed_point_b_double: " << fixed_point_b_double << std::endl;

//   double inverse_b = 1.0 / fixed_point_b_double;

//   std::cout << "inverse_b: " << inverse_b << std::endl;

//   FixedPointShareStruct fixed_point_inverse_b =
//       CreateFixedPointShareStruct<T>(inverse_b, fixed_point_a.k, fixed_point_a.f, num_of_simd);

//   FixedPointShareStruct fixed_point_division_simple_result;

//   // TODO: use TruncPr, improve performance?
//   fixed_point_division_simple_result.v =
//       ArithmeticRightShift<T>(fixed_point_a.v * fixed_point_inverse_b.v, fixed_point_a.f);
//   fixed_point_division_simple_result.k = fixed_point_a.k;
//   fixed_point_division_simple_result.f = fixed_point_a.f;

//   // only for debug
//   //   fixed_point_division_simple_result.v = fixed_point_a.v * fixed_point_inverse_b.v;
//   // fixed_point_division_simple_result.v = fixed_point_inverse_b.v ;

//   return fixed_point_division_simple_result;
// }

// template FixedPointShareStruct ShareWrapper::FxDivSimple_CS<__uint128_t, __int128_t>(
//     const FixedPointShareStruct& fixed_point_a, const __uint128_t fixed_point_b) const;

// // TODO: test different truncation protocols
// template <typename T>
// FixedPointShareStruct ShareWrapper::FxDiv_CS(const FixedPointShareStruct& fixed_point_a,
//                                              const FixedPointShareStruct& fixed_point_b) const {
//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   std::size_t k = fixed_point_a.k;
//   std::size_t f = fixed_point_a.f;
//   std::size_t theta = ceil(log2(double(k) / 3.5));

//   T alpha = T(pow(2, 2 * f));
//   ShareWrapper arithmetic_gmw_share_b = fixed_point_b.v;
//   ShareWrapper arithmetic_gmw_share_w = FxAppRcr_CS<T>(arithmetic_gmw_share_b, k, f);

//   ShareWrapper constant_arithmetic_gmw_share_alpha =
//       CreateConstantArithmeticGmwInput<T>(alpha, num_of_simd);

//   ShareWrapper arithmetic_gmw_share_x =
//       constant_arithmetic_gmw_share_alpha - arithmetic_gmw_share_b * arithmetic_gmw_share_w;

//   ShareWrapper arithmetic_gmw_share_a = fixed_point_a.v;
//   ShareWrapper arithmetic_gmw_share_y = arithmetic_gmw_share_a * arithmetic_gmw_share_w;

//   ShareWrapper arithmetic_gmw_share_y_prime = ArithmeticRightShift<T>(arithmetic_gmw_share_y, f);

//   ShareWrapper arithmetic_gmw_share_x_prime = arithmetic_gmw_share_x;

//   for (std::size_t i = 1; i < theta; i++) {
//     arithmetic_gmw_share_y_prime =
//         arithmetic_gmw_share_y_prime *
//         (constant_arithmetic_gmw_share_alpha + arithmetic_gmw_share_x_prime);
//     arithmetic_gmw_share_x_prime = arithmetic_gmw_share_x_prime * arithmetic_gmw_share_x_prime;
//     arithmetic_gmw_share_y_prime = ArithmeticRightShift<T>(arithmetic_gmw_share_y_prime, (2 *
//     f)); arithmetic_gmw_share_x_prime = ArithmeticRightShift<T>(arithmetic_gmw_share_x_prime, (2
//     * f));
//   }

//   ShareWrapper arithmetic_gmw_share_y_prime_prime =
//       arithmetic_gmw_share_y_prime *
//       (constant_arithmetic_gmw_share_alpha + arithmetic_gmw_share_x_prime);

//   ShareWrapper arithmetic_gmw_share_y_prime_prime_prime =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_y_prime_prime, 2 * f);

//   FixedPointShareStruct fixed_point_division_result;
//   fixed_point_division_result.v = arithmetic_gmw_share_y_prime_prime_prime;
//   fixed_point_division_result.k = k;
//   fixed_point_division_result.f = f;

//   return fixed_point_division_result;
// }

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FxNorm_CS(const ShareWrapper& arithmetic_gmw_share_b,
//                                                   std::size_t k, std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_b->GetNumberOfSimdValues();

//   ShareWrapper arithmetic_gmw_share_b_less_than_zero = LTZ<T>(arithmetic_gmw_share_b);
//   //   ShareWrapper arithmetic_gmw_share_b_less_than_zero =
//   //       BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_b_less_than_zero);

//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);
//   ShareWrapper arithmetic_gmw_share_s =
//       constant_arithmetic_gmw_share_one -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_b_less_than_zero;

//   // x = abs(b)
//   //    std::cout << "x = abs(b)" << std::endl;
//   ShareWrapper arithmetic_gmw_share_x = arithmetic_gmw_share_s * arithmetic_gmw_share_b;

//   // TODO: truncate x to a smaller field before bit decompose to improve performance
//   ShareWrapper boolean_gmw_share_x = arithmetic_gmw_share_x.Convert<MpcProtocol::kBooleanGmw>();

//   std::vector<ShareWrapper> boolean_gmw_share_x_vector = boolean_gmw_share_x.Split();

//   std::vector<ShareWrapper> boolean_gmw_share_y_vector(k);
//   boolean_gmw_share_y_vector[k - 1] = boolean_gmw_share_x_vector[k - 1];
//   for (std::size_t i = 1; i < k; i++) {
//     boolean_gmw_share_y_vector[k - 1 - i] =
//         boolean_gmw_share_y_vector[k - i] | boolean_gmw_share_x_vector[k - 1 - i];
//   }

//   std::vector<ShareWrapper> boolean_gmw_share_z_vector(k);
//   for (std::size_t i = 0; i <= k - 2; i++) {
//     boolean_gmw_share_z_vector[i] =
//         boolean_gmw_share_y_vector[i] ^ boolean_gmw_share_y_vector[i + 1];
//   }
//   boolean_gmw_share_z_vector[k - 1] = boolean_gmw_share_y_vector[k - 1];

//   ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << T(k - 1), num_of_simd);
//   ShareWrapper arithmetic_gmw_share_z_0 =
//       boolean_gmw_share_z_vector[0].BooleanGmwBitsToArithmeticGmw<T>();
//   ShareWrapper arithmetic_gmw_share_v =
//       constant_arithmetic_gmw_share_pow2_k_minus_1 * arithmetic_gmw_share_z_0;

//   // TODO: optimize for multiple addition
//   for (std::size_t i = 1; i < k; i++) {
//     ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_i_minus_1 =
//         CreateConstantArithmeticGmwInput<T>(T(1) << T(k - i - 1), num_of_simd);

//     ShareWrapper arithmetic_gmw_share_z_i =
//         boolean_gmw_share_z_vector[i].BooleanGmwBitsToArithmeticGmw<T>();
//     arithmetic_gmw_share_v =
//         arithmetic_gmw_share_v +
//         constant_arithmetic_gmw_share_pow2_k_minus_i_minus_1 * arithmetic_gmw_share_z_i;
//   }

//   ShareWrapper arithmetic_gmw_share_c = arithmetic_gmw_share_x * arithmetic_gmw_share_v;
//   ShareWrapper arithmetic_gmw_share_v_prime = arithmetic_gmw_share_s * arithmetic_gmw_share_v;

//   std::vector<ShareWrapper> result;
//   result.emplace_back(arithmetic_gmw_share_c);
//   result.emplace_back(arithmetic_gmw_share_v_prime);

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FxNorm_CS<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_b, std::size_t k, std::size_t f) const;

// template <typename T>
// ShareWrapper ShareWrapper::FxAppRcr_CS(const ShareWrapper& arithmetic_gmw_share_b, std::size_t k,
//                                        std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_b->GetNumberOfSimdValues();

//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);

//   double alpha = 2.9142;
//   T alpha_T = T(alpha * (pow(2, k)));

//   ShareWrapper constant_arithmetic_gmw_share_alpha =
//       CreateConstantArithmeticGmwInput<T>(alpha_T, num_of_simd);

//   std::vector<ShareWrapper> arithmetic_gmw_share_c_v_vector =
//       FxNorm_CS<T>(arithmetic_gmw_share_b, k, f);
//   ShareWrapper arithmetic_gmw_share_c = arithmetic_gmw_share_c_v_vector[0];
//   ShareWrapper arithmetic_gmw_share_v = arithmetic_gmw_share_c_v_vector[1];

//   ShareWrapper arithmetic_gmw_share_d = constant_arithmetic_gmw_share_alpha -
//                                         constant_arithmetic_gmw_share_two *
//                                         arithmetic_gmw_share_c;

//   ShareWrapper arithmetic_gmw_share_w = arithmetic_gmw_share_d * arithmetic_gmw_share_v;

//   ShareWrapper arithmetic_gmw_share_w_prime =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_w, 2 * (k - f));

//   return arithmetic_gmw_share_w_prime;
// }

// template <typename T>
// ShareWrapper ShareWrapper::FxLT_CS(const FixedPointShareStruct& fixed_point_a,
//                                    const FixedPointShareStruct& fixed_point_b) const {
//   assert(fixed_point_a.k == fixed_point_b.k);
//   assert(fixed_point_a.f == fixed_point_b.f);

//   return LT<T>(fixed_point_a.v, fixed_point_b.v);
// }

// template ShareWrapper ShareWrapper::FxLT_CS<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, const FixedPointShareStruct& fixed_point_b)
//     const;

// template <typename T>
// ShareWrapper ShareWrapper::FxEQ_CS(const FixedPointShareStruct& fixed_point_a,
//                                    const FixedPointShareStruct& fixed_point_b) const {
//   assert(fixed_point_a.k == fixed_point_b.k);
//   assert(fixed_point_a.f == fixed_point_b.f);

//   ShareWrapper boolean_gmw_share_a_equal_b =
//       EQ<T>(fixed_point_a.v, fixed_point_b.v, fixed_point_a.k);
//   ShareWrapper arithmetic_gmw_share_a_equal_b =
//       BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_a_equal_b);

//   return arithmetic_gmw_share_a_equal_b;
// }

// template ShareWrapper ShareWrapper::FxEQ_CS<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, const FixedPointShareStruct& fixed_point_b)
//     const;

// template <typename T, typename T_int>
// ShareWrapper ShareWrapper::FxLinAppSQ(const ShareWrapper& arithmetic_gmw_share_b, std::size_t k,
//                                       std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_b->GetNumberOfSimdValues();

//   double constant_alpha = -0.8099868542;
//   double constant_beta = 1.787727479;

//   ShareWrapper constant_arithmetic_gmw_share_alpha =
//       CreateConstantArithmeticGmwInput<T>(-T(-constant_alpha * (pow(2, k))), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_beta =
//       CreateConstantArithmeticGmwInput<T>(T(constant_beta * (pow(2, 2 * k))), num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);

//   std::vector<ShareWrapper> norm_SQ_result = FxNormSQ<T>(arithmetic_gmw_share_b, k, f);
//   ShareWrapper arithmetic_gmw_share_c = norm_SQ_result[0];
//   ShareWrapper arithmetic_gmw_share_v = norm_SQ_result[1];
//   ShareWrapper arithmetic_gmw_share_m = norm_SQ_result[2];
//   ShareWrapper arithmetic_gmw_share_W = norm_SQ_result[3];

//   ShareWrapper arithmetic_gmw_share_w =
//       constant_arithmetic_gmw_share_alpha * arithmetic_gmw_share_c +
//       constant_arithmetic_gmw_share_beta;

//   ShareWrapper arithmetic_gmw_share_m_prime =
//       ArithmeticGmwToBooleanGmwBit<T, T>(arithmetic_gmw_share_m);

//   ShareWrapper arithmetic_gmw_share_w_mul_v = arithmetic_gmw_share_w * arithmetic_gmw_share_v;

//   ShareWrapper arithmetic_gmw_share_w_prime_trunc =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_w_mul_v, (3 * k - 2 * f));

//   ShareWrapper arithmetic_gmw_share_w_prime_trunc_mul_W =
//       arithmetic_gmw_share_w_prime_trunc * arithmetic_gmw_share_W;

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_w_prime_trunc_mul_W =
//       CreateFixedPointShareStruct(arithmetic_gmw_share_w_prime_trunc_mul_W, k, f);

//   //   FixedPointStruct fixed_point_constant_1_div_2_high_f_div_2 =
//   //       CreateFixedPointStruct<T>((pow(2, (f / 2.0))), k, f);
//   T fixed_point_constant_1_div_2_high_f_div_2 = T(pow(2.0, (f / 2.0 + f)));

//   print_u128_u("fixed_point_constant_1_div_2_high_f_div_2: ",
//                fixed_point_constant_1_div_2_high_f_div_2);

//   // ============================================================
//   //   FixedPointShareStruct fixed_point_arithmetic_gmw_share_w =
//   //       FxDivSimple_CS<T, T_int>(fixed_point_arithmetic_gmw_share_w_prime_trunc_mul_W,
//   //                                 fixed_point_constant_1_div_2_high_f_div_2);
//   // ============================================================
//   // TODO: use arithmetic shift, performance difference?
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_w =
//       fixed_point_arithmetic_gmw_share_w_prime_trunc_mul_W;
//   fixed_point_arithmetic_gmw_share_w.v =
//       ArithmeticRightShift<T>(fixed_point_arithmetic_gmw_share_w_prime_trunc_mul_W.v, f / 2.0);

//   // ============================================================

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_sqrt_2 =
//       CreateFixedPointShareStruct<T>(pow(2, 0.5), k, f, num_of_simd);

//   ShareWrapper arithmetic_gmw_share_sqrt_2_mul_w =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_sqrt_2, fixed_point_arithmetic_gmw_share_w).v;

//   ShareWrapper arithmetic_gmw_share_result =
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_m_prime) *
//           fixed_point_arithmetic_gmw_share_w.v +
//       arithmetic_gmw_share_m_prime * arithmetic_gmw_share_sqrt_2_mul_w;

//   return arithmetic_gmw_share_result;

//   // only for debug
//   // return arithmetic_gmw_share_m_prime;
//   //   return fixed_point_arithmetic_gmw_share_w.v;
// }

// template ShareWrapper ShareWrapper::FxLinAppSQ<__uint128_t, __int128_t>(
//     const ShareWrapper& arithmetic_gmw_share_b, std::size_t k, std::size_t f) const;

// template <typename T>
// std::vector<ShareWrapper> ShareWrapper::FxNormSQ(const ShareWrapper& arithmetic_gmw_share_b,
//                                                  std::size_t k, std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_b->GetNumberOfSimdValues();

//   ShareWrapper constant_boolean_gmw_share_0 = CreateConstantBooleanGmwInput(T(0), num_of_simd);

//   // TODO: truncate before bit decompose to improve performance
//   ShareWrapper boolean_gmw_share_x = arithmetic_gmw_share_b.Convert<MpcProtocol::kBooleanGmw>();

//   std::vector<ShareWrapper> boolean_gmw_share_x_vector = boolean_gmw_share_x.Split();
//   std::vector<ShareWrapper> boolean_gmw_share_y_vector(k);
//   boolean_gmw_share_y_vector[k - 1] = boolean_gmw_share_x_vector[k - 1];
//   for (std::size_t i = 1; i < k; i++) {
//     boolean_gmw_share_y_vector[k - 1 - i] =
//         boolean_gmw_share_y_vector[k - i] | boolean_gmw_share_x_vector[k - 1 - i];
//   }

//   std::size_t w_array_size = ceil(double(k) / 2) + 1;
//   //   std::cout << "w_array_size: " << w_array_size << std::endl;
//   std::vector<ShareWrapper> boolean_gmw_share_z_vector(2 * (w_array_size - 1) + 1);
//   for (std::size_t i = 0; i < (2 * (w_array_size - 1) + 1); i++) {
//     boolean_gmw_share_z_vector[i] = constant_boolean_gmw_share_0;
//   }

//   //   std::vector<ShareWrapper> boolean_gmw_share_z_vector(k);
//   for (std::size_t i = 0; i <= k - 2; i++) {
//     boolean_gmw_share_z_vector[i] =
//         boolean_gmw_share_y_vector[i] ^ boolean_gmw_share_y_vector[i + 1];
//   }
//   boolean_gmw_share_z_vector[k - 1] = boolean_gmw_share_y_vector[k - 1];

//   std::vector<ShareWrapper> arithmetic_gmw_share_z_vector(k);
//   ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T(1) << T(k - 1), num_of_simd);
//   arithmetic_gmw_share_z_vector[0] =
//       boolean_gmw_share_z_vector[0].BooleanGmwBitsToArithmeticGmw<T>();
//   ShareWrapper arithmetic_gmw_share_v =
//       constant_arithmetic_gmw_share_pow2_k_minus_1 * arithmetic_gmw_share_z_vector[0];

//   for (std::size_t i = 1; i < k; i++) {
//     ShareWrapper constant_arithmetic_gmw_share_pow2_k_minus_i_minus_1 =
//         CreateConstantArithmeticGmwInput<T>(T(1) << T(k - i - 1), num_of_simd);
//     arithmetic_gmw_share_z_vector[i] =
//         boolean_gmw_share_z_vector[i].BooleanGmwBitsToArithmeticGmw<T>();
//     arithmetic_gmw_share_v =
//         arithmetic_gmw_share_v +
//         constant_arithmetic_gmw_share_pow2_k_minus_i_minus_1 * arithmetic_gmw_share_z_vector[i];
//   }

//   ShareWrapper arithmetic_gmw_share_c = arithmetic_gmw_share_b * arithmetic_gmw_share_v;

//   ShareWrapper arithmetic_gmw_share_m = arithmetic_gmw_share_z_vector[0];
//   for (std::size_t i = 1; i < k; i++) {
//     ShareWrapper constant_arithmetic_gmw_share_i_plus_1 =
//         CreateConstantArithmeticGmwInput<T>(T(i + 1), num_of_simd);
//     arithmetic_gmw_share_m = arithmetic_gmw_share_m + constant_arithmetic_gmw_share_i_plus_1 *
//                                                           arithmetic_gmw_share_z_vector[i];
//   }

//   //   std::size_t w_array_size = ceil(double(k) / 2) + 1;
//   //   std::cout << "w_array_size: " << w_array_size << std::endl;

//   std::vector<ShareWrapper> boolean_gmw_share_w_array(w_array_size);
//   boolean_gmw_share_w_array[0] = constant_boolean_gmw_share_0;

//   //   std::cout << "111" << std::endl;
//   for (std::size_t i = 1; i < w_array_size; i++) {
//     //     std::cout << "z[2 * i]: " << z[2 * i];
//     //     std::cout << std::endl;

//     boolean_gmw_share_w_array[i] =
//         boolean_gmw_share_z_vector[2 * i - 1] ^ boolean_gmw_share_z_vector[2 * i];
//   }

//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_w_array_1 =
//       boolean_gmw_share_w_array[1].BooleanGmwBitsToArithmeticGmw<T>();
//   ShareWrapper arithmetic_gmw_share_w =
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_w_array_1;

//   for (std::size_t i = 2; i < w_array_size; i++) {
//     ShareWrapper constant_arithmetic_gmw_share_pow2_i =
//         CreateConstantArithmeticGmwInput<T>(T((1) << i), num_of_simd);
//     ShareWrapper arithmetic_gmw_share_w_array_i =
//         BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_w_array[i]);

//     arithmetic_gmw_share_w = arithmetic_gmw_share_w +
//                              constant_arithmetic_gmw_share_pow2_i *
//                              arithmetic_gmw_share_w_array_i;
//   }

//   std::vector<ShareWrapper> result;
//   result.emplace_back(arithmetic_gmw_share_c);
//   result.emplace_back(arithmetic_gmw_share_v);
//   result.emplace_back(arithmetic_gmw_share_m);
//   result.emplace_back(arithmetic_gmw_share_w);

//   // only for debug
//   result.emplace_back(boolean_gmw_share_w_array[17]);
//   result.emplace_back(boolean_gmw_share_w_array[18]);
//   result.emplace_back(boolean_gmw_share_w_array[19]);
//   result.emplace_back(boolean_gmw_share_w_array[20]);
//   //   result.emplace_back(boolean_gmw_share_w_array[21]);
//   //   result.emplace_back(boolean_gmw_share_w_array[21].BooleanGmwBitsToArithmeticGmw<T>());

//   return result;
// }

// template std::vector<ShareWrapper> ShareWrapper::FxNormSQ<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t k, std::size_t f) const;

// template <typename T, typename T_int>
// FixedPointShareStruct ShareWrapper::FxParamFxSqrt_CS(const ShareWrapper& arithmetic_gmw_share_x,
//                                                      std::size_t k, std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_x->GetNumberOfSimdValues();

//   std::size_t theta = ceil(log2(k / 5.4));

//   ShareWrapper arithemtic_gmw_share_y0 = FxLinAppSQ<T, T_int>(arithmetic_gmw_share_x, k, f);
//   double scale_factor = 1.0 / (pow(2.0, f));

//   T fixed_point_constant_two = 2.0 * pow(2.0, f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_x0 =
//       CreateFixedPointShareStruct(arithmetic_gmw_share_x, k, f);
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_y0 =
//       CreateFixedPointShareStruct(arithemtic_gmw_share_y0, k, f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_g0 =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_x0, fixed_point_arithmetic_gmw_share_y0);
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_h0 =
//       FxDivSimple_CS<T, T_int>(fixed_point_arithmetic_gmw_share_y0, fixed_point_constant_two);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_g0h0 =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_g0, fixed_point_arithmetic_gmw_share_h0);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_g = fixed_point_arithmetic_gmw_share_g0;
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_h = fixed_point_arithmetic_gmw_share_h0;
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_gh =
//   fixed_point_arithmetic_gmw_share_g0h0;

//   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_3_div_2 =
//       CreateFixedPointShareStruct<T>(1.5, k, f, num_of_simd);
//   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_3 =
//       CreateFixedPointShareStruct<T>(3, k, f, num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_4 =
//       CreateConstantArithmeticGmwInput<T>(T(4), num_of_simd);

//   for (std::size_t i = 1; i < theta - 2; i++) {
//     FixedPointShareStruct fixed_point_arithmetic_gmw_share_r = FxSub_CS<T>(
//         fixed_point_constant_arithmetic_gmw_share_3_div_2, fixed_point_arithmetic_gmw_share_gh);
//     fixed_point_arithmetic_gmw_share_g =
//         FxMul_CS<T>(fixed_point_arithmetic_gmw_share_g, fixed_point_arithmetic_gmw_share_r);
//     fixed_point_arithmetic_gmw_share_h =
//         FxMul_CS<T>(fixed_point_arithmetic_gmw_share_h, fixed_point_arithmetic_gmw_share_r);
//     fixed_point_arithmetic_gmw_share_gh =
//         FxMul_CS<T>(fixed_point_arithmetic_gmw_share_g, fixed_point_arithmetic_gmw_share_h);
//   }

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_r = FxSub_CS<T>(
//       fixed_point_constant_arithmetic_gmw_share_3_div_2, fixed_point_arithmetic_gmw_share_gh);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_h_mul_r =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_h, fixed_point_arithmetic_gmw_share_r);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_h_square = FxMul_CS<T>(
//       fixed_point_arithmetic_gmw_share_h_mul_r, fixed_point_arithmetic_gmw_share_h_mul_r);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_H =
//       fixed_point_arithmetic_gmw_share_h_square;
//   fixed_point_arithmetic_gmw_share_H.v =
//       fixed_point_arithmetic_gmw_share_H.v * constant_arithmetic_gmw_share_4;

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_H_prime =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_H, fixed_point_arithmetic_gmw_share_x0);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_H_prime_prime = FxSub_CS<T>(
//       fixed_point_constant_arithmetic_gmw_share_3, fixed_point_arithmetic_gmw_share_H_prime);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_H_prime_prime_prime = FxMul_CS<T>(
//       fixed_point_arithmetic_gmw_share_h_mul_r, fixed_point_arithmetic_gmw_share_H_prime_prime);

//   fixed_point_arithmetic_gmw_share_g = FxMul_CS<T>(
//       fixed_point_arithmetic_gmw_share_H_prime_prime_prime, fixed_point_arithmetic_gmw_share_x0);

//   return fixed_point_arithmetic_gmw_share_g;
// }

// template FixedPointShareStruct ShareWrapper::FxParamFxSqrt_CS<__uint128_t, __int128_t>(
//     const ShareWrapper& arithmetic_gmw_share_x, std::size_t k, std::size_t f) const;

// template <typename T, typename T_int>
// FixedPointShareStruct ShareWrapper::FxSqrt(const FixedPointShareStruct& fixed_point_a) const {
//   std::size_t k = fixed_point_a.k;
//   std::size_t f = fixed_point_a.f;

//   FixedPointShareStruct result;

//   // TODO: implement other protocols cover this value range
//   if (3 * k - 2 * f >= f) {
//     // ???
//   }

//   else {
//     FixedPointShareStruct result =
//         FxParamFxSqrt_CS<T, T_int>(fixed_point_a.v, fixed_point_a.k, fixed_point_a.f);
//   }

//   // TODO
//   // other sqrt algorithms, ....

//   return result;
// }

// template FixedPointShareStruct ShareWrapper::FxSqrt<__uint128_t, __int128_t>(
//     const FixedPointShareStruct& fixed_point_a) const;

// template <typename T>
// FloatingPointShareStruct ShareWrapper::Fx2FL(const FixedPointShareStruct& fixed_point_a,
//                                              std::size_t gamma, std::size_t f, std::size_t l,
//                                              std::size_t k) const {
//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   std::vector<ShareWrapper> floating_point_arithmetic_gmw_share_vector =
//       Int2FL_ABZS<T, T>(fixed_point_a.v, gamma, l, k);

//   ShareWrapper arithmetic_gmw_share_v = floating_point_arithmetic_gmw_share_vector[0];
//   ShareWrapper arithmetic_gmw_share_p = floating_point_arithmetic_gmw_share_vector[1];
//   ShareWrapper arithmetic_gmw_share_z = floating_point_arithmetic_gmw_share_vector[2];
//   ShareWrapper arithmetic_gmw_share_s = floating_point_arithmetic_gmw_share_vector[3];

//   ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput<T>(T(0), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_f =
//       CreateConstantArithmeticGmwInput<T>(T(f), num_of_simd);

//   ShareWrapper arithmetic_gmw_share_p_prime =
//       (arithmetic_gmw_share_p - constant_arithmetic_gmw_share_f) *
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_z);

//   FloatingPointShareStruct floating_point_result;
//   floating_point_result.mantissa = arithmetic_gmw_share_v;

//   floating_point_result.exponent = arithmetic_gmw_share_p_prime;

//   // only for debug
//   //   floating_point_result.exponent = arithmetic_gmw_share_p;

//   floating_point_result.zero = arithmetic_gmw_share_z;
//   floating_point_result.sign = arithmetic_gmw_share_s;
//   floating_point_result.error = constant_arithmetic_gmw_share_zero;
//   floating_point_result.l = l;
//   floating_point_result.k = k;

//   return floating_point_result;
// }

// template FloatingPointShareStruct ShareWrapper::Fx2FL<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a, std::size_t gamma, std::size_t f, std::size_t l,
//     std::size_t k) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::Int2Fx(const ShareWrapper& arithmetic_gmw_share_a,
//                                            std::size_t k, std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_a->GetNumberOfSimdValues();

//   FixedPointShareStruct fixed_point = CreateFixedPointShareStruct(
//       arithmetic_gmw_share_a * CreateConstantArithmeticGmwInput<T>(T(1) << f, num_of_simd), k,
//       f);

//   return fixed_point;
// }

// template FixedPointShareStruct ShareWrapper::Int2Fx<__uint128_t>(
//     const ShareWrapper& arithmetic_gmw_share_a, std::size_t k, std::size_t f) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxPolyEval(const FixedPointShareStruct& fixed_point_x,
//                                                const double coefficient[],
//                                                std::size_t array_size) const {
//   std::size_t k = fixed_point_x.k;
//   std::size_t f = fixed_point_x.f;

//   std::size_t num_of_simd = fixed_point_x.v->GetNumberOfSimdValues();

//   FixedPointShareStruct fixed_point_x_premult = fixed_point_x;

//   FixedPointShareStruct fixed_point_coefficient =
//       CreateFixedPointShareStruct<T>(coefficient[0], k, f, num_of_simd);

//   FixedPointShareStruct local_aggregation = fixed_point_coefficient;

//   for (std::size_t i = 1; i < array_size; i++) {
//     fixed_point_coefficient = CreateFixedPointShareStruct<T>(coefficient[i], k, f, num_of_simd);

//     FixedPointShareStruct fixed_point_coefficient_mul_x =
//         FxMul_CS<T>(fixed_point_coefficient, fixed_point_x_premult);

//     local_aggregation = FxAdd_CS<T>(local_aggregation, fixed_point_coefficient_mul_x);

//     // save one multiplication
//     if (i != array_size - 1) {
//       fixed_point_x_premult = FxMul_CS<T>(fixed_point_x_premult, fixed_point_x);
//     }
//   }

//   return local_aggregation;
// }

// template FixedPointShareStruct ShareWrapper::FxPolyEval<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_x, const double coefficient[],
//     std::size_t array_size) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxSqrt_P0132(const FixedPointShareStruct& fixed_point_a)
// const {
//   std::size_t k = fixed_point_a.k;
//   std::size_t f = fixed_point_a.f;

//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   std::size_t gamma = FLOATINGPOINT_BITS;
//   std::size_t l_floating_point = FLOATINGPOINT_MANTISSA_BITS + 1;
//   std::size_t k_floating_point = FLOATINGPOINT_EXPONENT_BITS;

//   FloatingPointShareStruct floating_point_arithmetic_gmw_share_a =
//       Fx2FL<T>(fixed_point_a, gamma, f, l_floating_point, k_floating_point);

//   std::size_t shift_bits = l_floating_point - f;

//   // norm_v in [0.5,1]
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_norm_v = CreateFixedPointShareStruct(
//       ArithmeticRightShift<T>(floating_point_arithmetic_gmw_share_a.mantissa,
//                               (l_floating_point - f)),
//       k, f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_poly_P = FxPolyEval<T>(
//       fixed_point_arithmetic_gmw_share_norm_v, p_0132, sizeof(p_0132) / sizeof(p_0132[0]));

//   // (2^k)^0.5 = 2^(floor(k/2)) + 2^0.5 if k is odd
//   // (2^k)^0.5 = 2^(floor(k/2)) if k is even
//   ShareWrapper arithmetic_gmw_share_shift_bits_plus_f_plus_p =
//       CreateConstantArithmeticGmwInput<T>(T(shift_bits) + T(f), num_of_simd) +
//       floating_point_arithmetic_gmw_share_a.exponent;
//   ShareWrapper arithmetic_gmw_share_shift_bits_plus_f_plus_p_div_2 =
//       ArithmeticRightShift<T>(arithmetic_gmw_share_shift_bits_plus_f_plus_p, 1);

//   ShareWrapper arithmetic_gmw_share_shift_bits_plus_f_plus_p_is_odd =
//       ArithmeticGmwToBooleanGmwBit<T, T>(arithmetic_gmw_share_shift_bits_plus_f_plus_p);

//   ShareWrapper arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2 =
//       Pow2<T>(arithmetic_gmw_share_shift_bits_plus_f_plus_p_div_2);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2 =
//       CreateFixedPointShareStruct(
//           ArithmeticLeftShift<T>(arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2, f), k,
//           f);
//   FixedPointShareStruct
//   fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2_final =
//       fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2;

//   ShareWrapper constant_arithmetic_gmw_share_pow2_f =
//       CreateConstantArithmeticGmwInput<T>(T(1) << f, num_of_simd);

//   ShareWrapper constant_arithmetic_gmw_share_1_div_sqrt2_minus_1 =
//       CreateConstantArithmeticGmwInput<T>(T((M_SQRT2 - double(1)) * pow(2, f)), num_of_simd);

//   fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2_final.v =
//       ArithmeticRightShift<T>(
//           fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2_final.v *
//               (constant_arithmetic_gmw_share_pow2_f +
//                arithmetic_gmw_share_shift_bits_plus_f_plus_p_is_odd *
//                    constant_arithmetic_gmw_share_1_div_sqrt2_minus_1),
//           f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_sqrt_result =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_poly_P,
//                   fixed_point_arithmetic_gmw_share_pow2_shift_bits_plus_f_plus_p_div_2_final);

//   //   return fixed_point_arithmetic_gmw_share_norm_v;
//   return fixed_point_arithmetic_gmw_share_sqrt_result;
// }

// template FixedPointShareStruct ShareWrapper::FxSqrt_P0132<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxExp2_P1045(const FixedPointShareStruct& fixed_point_a)
// const {
//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   std::size_t k = fixed_point_a.k;
//   std::size_t f = fixed_point_a.f;

//   ShareWrapper arithmetic_gmw_share_a = fixed_point_a.v;
//   ShareWrapper arithmetic_gmw_share_s = LTZ<T>(arithmetic_gmw_share_a);

//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);

//   // abs(a)
//   ShareWrapper arithmetic_gmw_share_a_prime =
//       (constant_arithmetic_gmw_share_one -
//        constant_arithmetic_gmw_share_two * arithmetic_gmw_share_s) *
//       arithmetic_gmw_share_a;

//   // integer part of abs(a)
//   ShareWrapper arithmetic_gmw_share_b = ArithmeticRightShift<T>(arithmetic_gmw_share_a_prime, f);

//   FixedPointShareStruct fixed_point_a_arithmetic_gmw_share_a_prime = fixed_point_a;
//   fixed_point_a_arithmetic_gmw_share_a_prime.v = arithmetic_gmw_share_a_prime;

//   ShareWrapper arithmetic_gmw_share_c =
//       arithmetic_gmw_share_a_prime -
//       arithmetic_gmw_share_b * CreateConstantArithmeticGmwInput<T>(T(1) << f, num_of_simd);
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_c =
//       CreateFixedPointShareStruct(arithmetic_gmw_share_c, k, f);

//   ShareWrapper arithmetic_gmw_share_pow2_b = Pow2<T>(arithmetic_gmw_share_b);
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_d =
//       Int2Fx<T>(arithmetic_gmw_share_pow2_b, k, f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_e =
//       FxPolyEval<T>(fixed_point_arithmetic_gmw_share_c, p_1045, sizeof(p_1045) /
//       sizeof(p_1045[0]));
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_g =
//       FxMul_CS<T>(fixed_point_arithmetic_gmw_share_d, fixed_point_arithmetic_gmw_share_e);

//   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_one =
//       CreateFixedPointShareStruct<T>(double(1.0), k, f, num_of_simd);

//   // TODO: use pow2_neg to improve performance instead of division
//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_g_inverse = FxDiv_CS<T>(
//       fixed_point_constant_arithmetic_gmw_share_one, fixed_point_arithmetic_gmw_share_g);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_exp2_a = CreateFixedPointShareStruct(
//       (constant_arithmetic_gmw_share_one - arithmetic_gmw_share_s) *
//               fixed_point_arithmetic_gmw_share_g.v +
//           arithmetic_gmw_share_s * fixed_point_arithmetic_gmw_share_g_inverse.v,
//       k, f);

//   return fixed_point_arithmetic_gmw_share_exp2_a;
// }

// template FixedPointShareStruct ShareWrapper::FxExp2_P1045<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxLog2_P2508(const FixedPointShareStruct& fixed_point_a)
// const {
//   std::size_t num_of_simd = fixed_point_a.v->GetNumberOfSimdValues();

//   std::size_t k = fixed_point_a.k;
//   std::size_t f = fixed_point_a.f;

//   std::size_t gamma = FLOATINGPOINT_BITS;
//   std::size_t l_floating_point = FLOATINGPOINT_MANTISSA_BITS + 1;
//   std::size_t k_floating_point = FLOATINGPOINT_EXPONENT_BITS;

//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_l =
//       CreateConstantArithmeticGmwInput<T>(T(l_floating_point), num_of_simd);

//   FloatingPointShareStruct floating_point_arithmetic_gmw_share_a =
//       Fx2FL<T>(fixed_point_a, gamma, f, l_floating_point, k_floating_point);

//   std::size_t shift_bits = l_floating_point - f;

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_norm_v = CreateFixedPointShareStruct(
//       ArithmeticRightShift<T>(floating_point_arithmetic_gmw_share_a.mantissa, (shift_bits)), k,
//       f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_poly_P = FxPolyEval<T>(
//       fixed_point_arithmetic_gmw_share_norm_v, p_2508, sizeof(p_2508) / sizeof(p_2508[0]));

//   ShareWrapper arithmetic_gmw_share_p_plus_l =
//       floating_point_arithmetic_gmw_share_a.exponent + constant_arithmetic_gmw_share_l;

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_p_plus_l =
//       CreateFixedPointShareStruct(ArithmeticLeftShift<T>(arithmetic_gmw_share_p_plus_l, f), k,
//       f);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_log2_result = FxAdd_CS<T>(
//       fixed_point_arithmetic_gmw_share_poly_P, fixed_point_arithmetic_gmw_share_p_plus_l);

//   return fixed_point_arithmetic_gmw_share_log2_result;
// }

// template FixedPointShareStruct ShareWrapper::FxLog2_P2508<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_a) const;
// // ------------------------------------------------------------

// template <typename T>
// ShareWrapper ShareWrapper::Fx2IntWithRoundTowardsZero_CS(const ShareWrapper& v1, std::size_t k,
//                                                          std::size_t f) const {
//   ShareWrapper result = ArithmeticRightShift<T>(v1, f);
//   return result;
// }

// template ShareWrapper ShareWrapper::Fx2IntWithRoundTowardsZero_CS<__uint128_t>(
//     const ShareWrapper& v1, std::size_t k, std::size_t f) const;

// // not correct
// // template <typename T>
// // ShareWrapper ShareWrapper::FxCeil_CS(const ShareWrapper& v1, std::size_t k, std::size_t f)
// // const
// // {
// //   FixedPointShareStruct fixed_point_x = CreateFixedPointShareStruct(v1, k, f);

// //   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_1_div_2 =
// //       CreateFixedPointShareStruct(T(1) << (f - 1), k, f);

// //   // x + 0.5
// //   FixedPointShareStruct fixed_point_arithmetic_gmw_share_x_plus_1_div_2 =
// //       FxAdd_CS<T>(fixed_point_x, fixed_point_constant_arithmetic_gmw_share_1_div_2);

// //   ShareWrapper result =
// //       ArithmeticRightShift<T>(fixed_point_arithmetic_gmw_share_x_plus_1_div_2.v, f);
// //   return result;
// // }

// // template ShareWrapper ShareWrapper::FxCeil_CS<__uint128_t>(const ShareWrapper& v1, std::size_t
// // k,
// //                                                            std::size_t f) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxNeg_CS(const ShareWrapper& v1, std::size_t k,
//                                              std::size_t f) const {
//   std::size_t num_of_simd = v1->GetNumberOfSimdValues();

//   FixedPointShareStruct fixed_point_x = CreateFixedPointShareStruct(v1, k, f);
//   FixedPointShareStruct fixed_point_neg_x;
//   // ============================================================
//   //   // constant arithemtic share -1
//   //   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_neg_1 =
//   //       CreateFixedPointShareStruct(T(-1) << (f), k, f, num_of_simd);

//   //   fixed_point_neg_x = FxMul_CS<T>(fixed_point_x,
//   //   fixed_point_constant_arithmetic_gmw_share_neg_1);
//   // ============================================================
//   // TODO: directly negation the fixed_point_x as arithmetic integer,
//   // all computation is locally, more efficient
//   ShareWrapper constant_arithmetic_gmw_share_zero =
//       CreateConstantArithmeticGmwInput<T>(T(0), num_of_simd);
//   ShareWrapper arithmetic_gmw_share_neg_v1 = constant_arithmetic_gmw_share_zero - v1;
//   fixed_point_neg_x = CreateFixedPointShareStruct(arithmetic_gmw_share_neg_v1, k, f);

//   // ============================================================

//   return fixed_point_neg_x;
// }

// template FixedPointShareStruct ShareWrapper::FxNeg_CS<__uint128_t>(const ShareWrapper& v1,
//                                                                    std::size_t k,
//                                                                    std::size_t f) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxAbs_CS(const ShareWrapper& arithmetic_gmw_share_x,
//                                              std::size_t k, std::size_t f) const {
//   std::size_t num_of_simd = arithmetic_gmw_share_x->GetNumberOfSimdValues();

//   ShareWrapper arithmetic_gmw_share_x_less_than_zero = LTZ<T>(arithmetic_gmw_share_x);

//   ShareWrapper constant_arithmetic_gmw_share_one =
//       CreateConstantArithmeticGmwInput<T>(T(1), num_of_simd);
//   ShareWrapper constant_arithmetic_gmw_share_two =
//       CreateConstantArithmeticGmwInput<T>(T(2), num_of_simd);
//   ShareWrapper arithmetic_gmw_share_s =
//       constant_arithmetic_gmw_share_one -
//       constant_arithmetic_gmw_share_two * arithmetic_gmw_share_x_less_than_zero;

//   // abs(x)
//   ShareWrapper arithmetic_gmw_share_abs_x = arithmetic_gmw_share_s * arithmetic_gmw_share_x;

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_x =
//       CreateFixedPointShareStruct(arithmetic_gmw_share_abs_x, k, f);
//   return fixed_point_arithmetic_gmw_share_x;
// }

// template FixedPointShareStruct ShareWrapper::FxAbs_CS<__uint128_t>(const ShareWrapper& x,
//                                                                    std::size_t k,
//                                                                    std::size_t f) const;

// template <typename T>
// ShareWrapper ShareWrapper::FxLTZ_CS(const ShareWrapper& x, std::size_t k, std::size_t f) const {
//   ShareWrapper arithmetic_gmw_share_x_less_than_zero = LTZ<T>(x);

//   return arithmetic_gmw_share_x_less_than_zero;
// }

// template ShareWrapper ShareWrapper::FxLTZ_CS<__uint128_t>(const ShareWrapper& x, std::size_t k,
//                                                           std::size_t f) const;

// template <typename T>
// ShareWrapper ShareWrapper::FxEQZ_CS(const ShareWrapper& x, std::size_t k, std::size_t f) const {
//   ShareWrapper boolean_gmw_share_x_equal_zero = EQZ<T>(x);

//   ShareWrapper arithmetic_gmw_share_x_equal_zero =
//       BooleanGmwBitsToArithmeticGmw<T>(boolean_gmw_share_x_equal_zero);

//   return arithmetic_gmw_share_x_equal_zero;
// }

// template ShareWrapper ShareWrapper::FxEQZ_CS<__uint128_t>(const ShareWrapper& v1, std::size_t k,
//                                                           std::size_t f) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxExp(const FixedPointShareStruct& fixed_point_x) const {
//   //   FixedPointShareStruct fixed_point_x = CreateFixedPointShareStruct(v1, k, f);
//   std::size_t k = fixed_point_x.k;
//   std::size_t f = fixed_point_x.f;

//   std::size_t num_of_simd = fixed_point_x.v->GetNumberOfSimdValues();

//   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_log2e =
//       CreateFixedPointShareStruct<T>(double(M_LOG2E), k, f, num_of_simd);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_x_mul_log2_e =
//       FxMul_CS<T>(fixed_point_x, fixed_point_constant_arithmetic_gmw_share_log2e);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_x_mul_exp_x =
//       FxExp2_P1045<T>(fixed_point_arithmetic_gmw_share_x_mul_log2_e);

//   return fixed_point_arithmetic_gmw_share_x_mul_exp_x;
// }

// template FixedPointShareStruct ShareWrapper::FxExp<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_x) const;

// template <typename T>
// FixedPointShareStruct ShareWrapper::FxLn(const FixedPointShareStruct& fixed_point_x) const {
//   std::size_t k = fixed_point_x.k;
//   std::size_t f = fixed_point_x.f;

//   std::size_t num_of_simd = fixed_point_x.v->GetNumberOfSimdValues();

//   FixedPointShareStruct fixed_point_log2_x = FxLog2_P2508<T>(fixed_point_x);

//   FixedPointShareStruct fixed_point_constant_arithmetic_gmw_share_ln_2 =
//       CreateFixedPointShareStruct<T>(double(M_LN2), k, f, num_of_simd);

//   FixedPointShareStruct fixed_point_arithmetic_gmw_share_ln_x =
//       FxMul_CS<T>(fixed_point_log2_x, fixed_point_constant_arithmetic_gmw_share_ln_2);

//   return fixed_point_arithmetic_gmw_share_ln_x;
// }

// template FixedPointShareStruct ShareWrapper::FxLn<__uint128_t>(
//     const FixedPointShareStruct& fixed_point_x) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput(T constant_value,
                                                            std::size_t num_of_simd) const {
  //   share_->GetRegister()->SetAsPrecomputationMode();
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_arithmetic_gmw_share =
      share_->GetBackend().ConstantArithmeticGmwInput<T>(constant_value_vector);
  //   share_->GetRegister()->UnsetPrecomputationMode();

  return constant_arithmetic_gmw_share;
}

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename A>
ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput(
    std::vector<T, A> constant_value_vector) const {
  //   share_->GetRegister()->SetAsPrecomputationMode();
  //   std::vector<T> constant_value_vector{constant_value};
  ShareWrapper constant_arithmetic_gmw_share =
      share_->GetBackend().ConstantArithmeticGmwInput<T>(constant_value_vector);
  //   share_->GetRegister()->UnsetPrecomputationMode();

  return constant_arithmetic_gmw_share;
}

template ShareWrapper
ShareWrapper::CreateConstantArithmeticGmwInput<std::uint8_t, std::allocator<std::uint8_t>>(
    std::vector<std::uint8_t> constant_value_vector) const;

template ShareWrapper
ShareWrapper::CreateConstantArithmeticGmwInput<std::uint16_t, std::allocator<std::uint16_t>>(
    std::vector<std::uint16_t> constant_value_vector) const;

template ShareWrapper
ShareWrapper::CreateConstantArithmeticGmwInput<std::uint32_t, std::allocator<std::uint32_t>>(
    std::vector<std::uint32_t> constant_value_vector) const;

template ShareWrapper
ShareWrapper::CreateConstantArithmeticGmwInput<std::uint64_t, std::allocator<std::uint64_t>>(
    std::vector<std::uint64_t> constant_value_vector) const;

template ShareWrapper ShareWrapper::CreateConstantArithmeticGmwInput<
    __uint128_t, std::allocator<__uint128_t>>(std::vector<__uint128_t> constant_value_vector) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(T constant_value,
                                                           std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput<T>(constant_value, num_of_simd);
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint8_t>(
    std::uint8_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint16_t>(
    std::uint16_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint32_t>(
    std::uint32_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<std::uint64_t>(
    std::uint64_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(bool constant_value,
                                                           std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBooleanGmwInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(float constant_value,
                                                           std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBooleanGmwInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(double constant_value,
                                                           std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBooleanGmwInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput(constant_value, num_of_simd);
}

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBmrInput(T constant_value,
                                                    std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBmrInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBmrInput<T>(constant_value, num_of_simd);
}

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint8_t>(
    std::uint8_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint16_t>(
    std::uint16_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint32_t>(
    std::uint32_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<std::uint64_t>(
    std::uint64_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBmrInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ShareWrapper::CreateConstantAsBmrInput(bool constant_value,
                                                    std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBmrInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return share_->GetBackend().ConstantAsBmrInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsBmrInput(float constant_value,
                                                    std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBmrInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBmrInput(constant_value, num_of_simd);
}
ShareWrapper ShareWrapper::CreateConstantAsBmrInput(double constant_value,
                                                    std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBmrInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput(num_of_simd, constant_value);
}

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsGCInput(T constant_value,
                                                   std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsGCInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsGCInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsGCInput<T>(constant_value, num_of_simd);
}

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint8_t>(
    std::uint8_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint16_t>(
    std::uint16_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint32_t>(
    std::uint32_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<std::uint64_t>(
    std::uint64_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsGCInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ShareWrapper::CreateConstantAsGCInput(bool constant_value,
                                                   std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsGCInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsGCInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return share_->GetBackend().ConstantAsGCInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsGCInput(float constant_value,
                                                   std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsGCInput(ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsGCInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsGCInput(constant_value, num_of_simd);
}
ShareWrapper ShareWrapper::CreateConstantAsGCInput(double constant_value,
                                                   std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsGCInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ShareWrapper::CreateConstantAsGCInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInput(num_of_simd, constant_value);
}

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(T constant_value,
                                                                std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_bmr_gc_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsGCInput(ToInput<T>(constant_value_vector));
  } else {
    throw std::runtime_error(
        "CreateConstantAsBooleanGmwBmrGCInput operations are supported only for Boolean Gmw and "
        "BMR");
  }
  return constant_boolean_gmw_bmr_gc_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwBmrGCInput<T>(constant_value, num_of_simd);
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint8_t>(
    std::uint8_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint16_t>(
    std::uint16_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint32_t>(
    std::uint32_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<std::uint64_t>(
    std::uint64_t constant_value) const;

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(bool constant_value,
                                                                std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_bmr_gc_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(BitVector<>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    constant_boolean_gmw_bmr_gc_share =
        share_->GetBackend().ConstantAsGCInput(BitVector<>(constant_value_vector));
  } else {
    throw std::runtime_error(
        "CreateConstantAsBooleanGmwBmrGCInput operations are supported only for Boolean Gmw and "
        "BMR");
  }
  return constant_boolean_gmw_bmr_gc_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwBmrGCInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(float constant_value,
                                                                std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_bmr_gc_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<float, std::true_type>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<float, std::true_type>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsGCInput(
        ToInput<float, std::true_type>(constant_value_vector));
  } else {
    throw std::runtime_error(
        "CreateConstantAsBooleanGmwBmrGCInput operations are supported only for Boolean Gmw and "
        "BMR");
  }
  return constant_boolean_gmw_bmr_gc_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwBmrGCInput(constant_value, num_of_simd);
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(double constant_value,
                                                                std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_bmr_gc_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<double, std::true_type>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<double, std::true_type>(constant_value_vector));
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsGCInput(
        ToInput<double, std::true_type>(constant_value_vector));
  } else {
    throw std::runtime_error(
        "CreateConstantAsBooleanGmwBmrGCInput operations are supported only for Boolean Gmw and "
        "BMR");
  }
  return constant_boolean_gmw_bmr_gc_share;
}

ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwBmrGCInput(constant_value, num_of_simd);
}

template <typename T>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBooleanGmwInput(
      FixedPointToInput<T>(constant_value_vector, fixed_point_fraction_bit_size));
  return constant_boolean_gmw_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint8_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint16_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint32_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint64_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<__uint128_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;

template <typename T>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwInputFromFixedPoint<T>(constant_value, num_of_simd,
                                                          fixed_point_fraction_bit_size);
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint8_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint16_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint32_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<std::uint64_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwInputFromFixedPoint<__uint128_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;

template <typename T>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_bmr_gc_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        FixedPointToInput<T>(constant_value_vector, fixed_point_fraction_bit_size));
  } else if (share_->GetProtocol() == MpcProtocol::kBmr) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsBmrInput(
        FixedPointToInput<T>(constant_value_vector, fixed_point_fraction_bit_size));
  } else if (share_->GetProtocol() == MpcProtocol::kGarbledCircuit) {
    constant_boolean_gmw_bmr_gc_share = share_->GetBackend().ConstantAsGCInput(
        FixedPointToInput<T>(constant_value_vector, fixed_point_fraction_bit_size));
  } else {
    throw std::runtime_error(
        "CreateConstantAsBooleanGmwBmrGCInput operations are supported only for Boolean Gmw and "
        "BMR");
  }
  return constant_boolean_gmw_bmr_gc_share;
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint8_t>(double constant_value, std::size_t num_of_simd,
                  std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint16_t>(double constant_value, std::size_t num_of_simd,
                   std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint32_t>(double constant_value, std::size_t num_of_simd,
                   std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint64_t>(double constant_value, std::size_t num_of_simd,
                   std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<__uint128_t>(
    double constant_value, std::size_t num_of_simd,
    std::size_t fixed_point_fraction_bit_size) const;

template <typename T>
ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  return CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<T>(constant_value, num_of_simd,
                                                               fixed_point_fraction_bit_size);
}

template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint8_t>(double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint16_t>(double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint32_t>(double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<
    std::uint64_t>(double constant_value, std::size_t fixed_point_fraction_bit_size) const;
template ShareWrapper ShareWrapper::CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint<__uint128_t>(
    double constant_value, std::size_t fixed_point_fraction_bit_size) const;
}  // namespace encrypto::motion
