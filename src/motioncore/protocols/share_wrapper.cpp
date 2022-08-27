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
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra) {
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
  } else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator-(const ShareWrapper& other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetCircuitType() == other->GetCircuitType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra) {
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
  } else {
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
      } else {
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
  if (share_->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      other->GetProtocol() != MpcProtocol::kArithmeticGmw &&
      share_->GetProtocol() != MpcProtocol::kAstra && other->GetProtocol() != MpcProtocol::kAstra) {
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
  } else {
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

  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
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
  } else {
    throw std::bad_cast();
  }
}

template <MpcProtocol P>
ShareWrapper ShareWrapper::Convert() const {
  constexpr auto kArithmeticGmw = MpcProtocol::kArithmeticGmw;
  constexpr auto kBooleanGmw = MpcProtocol::kBooleanGmw;
  constexpr auto kBmr = MpcProtocol::kBmr;
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
    } else {  // kBmr -> kBooleanGmw
      return BmrToBooleanGmw();
    }
  } else if constexpr (P == kBmr) {
    if (share_->GetProtocol() == kArithmeticGmw) {  // kArithmeticGmw -> kBmr
      return ArithmeticGmwToBmr();
    } else {  // kBooleanGmw -> kBmr
      return BooleanGmwToBmr();
    }
  } else {
    throw std::runtime_error("Unknown MpcProtocol");
  }
}

// explicit specialization of function templates
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kArithmeticGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBooleanGmw>() const;
template ShareWrapper ShareWrapper::Convert<MpcProtocol::kBmr>() const;

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

template std::vector<std::uint8_t> ShareWrapper::As() const;
template std::vector<std::uint16_t> ShareWrapper::As() const;
template std::vector<std::uint32_t> ShareWrapper::As() const;
template std::vector<std::uint64_t> ShareWrapper::As() const;

template <typename T>
ShareWrapper ShareWrapper::Add(SharePointer share, SharePointer other) const {
  assert(share->GetProtocol() == other->GetProtocol() ||
         (share->GetCircuitType() == other->GetCircuitType() &&
          share->IsConstant() != other->IsConstant()));
  switch (share->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
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
      } else {
        assert(!(share->IsConstant() && other->IsConstant()));
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

template <typename T>
ShareWrapper ShareWrapper::Sub(SharePointer share, SharePointer other) const {
  assert(share->GetProtocol() == other->GetProtocol());
  switch (share->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      auto this_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(share);
      assert(this_a);
      auto this_wire_a = this_a->GetArithmeticWire();

      auto other_a = std::dynamic_pointer_cast<proto::arithmetic_gmw::Share<T>>(other);
      assert(other_a);
      auto other_wire_a = other_a->GetArithmeticWire();

      auto subtraction_gate =
          share_->GetRegister()->EmplaceGate<proto::arithmetic_gmw::SubtractionGate<T>>(
              this_wire_a, other_wire_a);
      auto result = std::static_pointer_cast<Share>(subtraction_gate->GetOutputAsArithmeticShare());
      return ShareWrapper(result);
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

template <typename T>
ShareWrapper ShareWrapper::Mul(SharePointer share, SharePointer other) const {
  assert(share->GetProtocol() == other->GetProtocol() ||
         (share->GetCircuitType() == other->GetCircuitType() &&
          share->IsConstant() != other->IsConstant()));
  switch (share->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
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
      } else {
        assert(!(share->IsConstant() && other->IsConstant()));
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

template ShareWrapper ShareWrapper::HybridMul<std::uint8_t>(SharePointer share,
                                                            SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint16_t>(SharePointer share,
                                                             SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint32_t>(SharePointer share,
                                                             SharePointer other) const;
template ShareWrapper ShareWrapper::HybridMul<std::uint64_t>(SharePointer share,
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

}  // namespace encrypto::motion
