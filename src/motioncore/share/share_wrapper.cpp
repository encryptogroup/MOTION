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

#include "algorithm/algorithm_description.h"
#include "algorithm/tree.h"
#include "arithmetic_gmw_share.h"
#include "base/backend.h"
#include "bmr_share.h"
#include "boolean_gmw_share.h"
#include "gate/arithmetic_gmw_gate.h"
#include "gate/b2a_gate.h"
#include "gate/bmr_gate.h"
#include "gate/boolean_gmw_gate.h"
#include "gate/conversion_gate.h"
#include "secure_type/secure_unsigned_integer.h"
#include "share/arithmetic_gmw_share.h"
#include "share/boolean_gmw_share.h"

namespace MOTION::Shares {
using SharePtr = std::shared_ptr<Share>;

ShareWrapper ShareWrapper::operator~() const {
  assert(share_);
  if (share_->GetProtocol() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MPCProtocol::BooleanGMW) {
    auto gmw_share = std::dynamic_pointer_cast<GMWShare>(share_);
    assert(gmw_share);
    auto inv_gate = std::make_shared<Gates::GMW::GMWINVGate>(gmw_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  } else {
    auto bmr_share = std::dynamic_pointer_cast<BMRShare>(share_);
    assert(bmr_share);
    auto inv_gate = std::make_shared<Gates::BMR::BMRINVGate>(bmr_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator^(const ShareWrapper &other) const {
  assert(share_);
  assert(*other);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MPCProtocol::BooleanGMW) {
    auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
    auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

    assert(this_b);
    assert(other_b);

    auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<BMRShare>(share_);
    auto other_b = std::dynamic_pointer_cast<BMRShare>(*other);

    auto xor_gate = std::make_shared<Gates::BMR::BMRXORGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator&(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetProtocol() == MPCProtocol::BooleanGMW) {
    auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
    auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

    auto and_gate = std::make_shared<Gates::GMW::GMWANDGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<BMRShare>(share_);
    auto other_b = std::dynamic_pointer_cast<BMRShare>(*other);

    auto and_gate = std::make_shared<Gates::BMR::BMRANDGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator|(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetProtocol() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  // OR operatinos is equal to NOT ( ( NOT a ) AND ( NOT b ) )
  return ~((~*this) & ~other);
}

ShareWrapper ShareWrapper::operator+(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetProtocol() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
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

ShareWrapper ShareWrapper::operator-(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetProtocol() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
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

ShareWrapper ShareWrapper::operator*(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetProtocol() == other->GetProtocol());
  assert(share_->GetBitLength() == other->GetBitLength());
  assert(share_->GetNumOfSIMDValues() == other->GetNumOfSIMDValues());
  if (share_->GetProtocol() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
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

ShareWrapper ShareWrapper::operator==(const ShareWrapper &other) const {
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
  const auto bitlen = result->GetBitLength();

  if (bitlen == 1) {
    return result;
  } else if (Helpers::IsPowerOfTwo(bitlen)) {
    return ENCRYPTO::Algorithm::FullANDTree(result);
  } else {  // bitlen is not a power of 2
    while (result->GetBitLength() != 1) {
      std::queue<Shares::ShareWrapper> q;
      std::vector<Shares::ShareWrapper> out;
      std::size_t offset{0};
      const auto inner_bitlen{result->GetBitLength()};
      const auto split = result.Split();
      for (auto i = 1ull; i <= inner_bitlen; i *= 2) {
        if ((inner_bitlen & i) == i) {
          const auto _begin = split.begin() + offset;
          const auto _end = split.begin() + offset + i;
          q.push(Shares::ShareWrapper::Join(_begin, _end));
          offset += i;
        }
      }
      while (!q.empty()) {
        out.emplace_back(ENCRYPTO::Algorithm::FullANDTree(q.front()));
        q.pop();
      }
      result = Shares::ShareWrapper::Join(out);
    }
    return result;
  }
}

ShareWrapper ShareWrapper::MUX(const ShareWrapper &a, const ShareWrapper &b) const {
  assert(*a);
  assert(*b);
  assert(share_);
  assert(share_->GetProtocol() == a->GetProtocol());
  assert(share_->GetProtocol() == b->GetProtocol());
  assert(a->GetBitLength() == b->GetBitLength());
  assert(share_->GetBitLength() == 1);

  if (share_->GetProtocol() == MPCProtocol::ArithmeticGMW) {
    // TODO implement
    throw std::runtime_error("C-OT-based MUX for Arithmetic GMW shares is not implemented yet");
  }

  if (share_->GetProtocol() == MPCProtocol::BooleanGMW) {
    auto this_gmw = std::dynamic_pointer_cast<GMWShare>(share_);
    auto a_gmw = std::dynamic_pointer_cast<GMWShare>(*a);
    auto b_gmw = std::dynamic_pointer_cast<GMWShare>(*b);

    assert(this_gmw);
    assert(a_gmw);
    assert(b_gmw);

    auto mux_gate = std::make_shared<Gates::GMW::GMWMUXGate>(a_gmw, b_gmw, this_gmw);
    share_->GetRegister()->RegisterNextGate(mux_gate);
    return ShareWrapper(mux_gate->GetOutputAsShare());
  } else {
    // s ? a : b
    // result <- b ^ (s * (a ^ b))

    auto a_xor_b = a ^ b;

    auto mask = ShareWrapper::Join(std::vector<ShareWrapper>(a_xor_b->GetBitLength(), *this));
    mask &= a_xor_b;
    return b ^ mask;
  }
}

template <typename MOTION::MPCProtocol p>
ShareWrapper ShareWrapper::Convert() const {
  constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
  constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
  constexpr auto BMR = MOTION::MPCProtocol::BMR;
  if (share_->GetProtocol() == p) {
    throw std::runtime_error("Trying to convert share to MPCProtocol it is already in");
  }

  assert(share_->GetProtocol() < MOTION::MPCProtocol::InvalidProtocol);

  if constexpr (p == AGMW) {
    if (share_->GetProtocol() == BGMW) {  // BGMW -> AGMW
      return BooleanGMWToArithmeticGMW();
    } else {  // BMR --(over BGMW)--> AGMW
      return this->Convert<BGMW>().Convert<AGMW>();
    }
  } else if constexpr (p == BGMW) {
    if (share_->GetProtocol() == AGMW) {  // AGMW --(over BMR)--> BGMW
      return this->Convert<BMR>().Convert<BGMW>();
    } else {  // BMR -> BGMW
      return BMRToBooleanGMW();
    }
  } else if constexpr (p == BMR) {
    if (share_->GetProtocol() == AGMW) {  // AGMW -> BMR
      return ArithmeticGMWToBMR();
    } else {  // BGMW -> BMR
      return BooleanGMWToBMR();
    }
  } else {
    throw std::runtime_error("Unkown MPCProtocol");
  }
}

// explicit specialization of function templates
template ShareWrapper ShareWrapper::Convert<MOTION::MPCProtocol::ArithmeticGMW>() const;
template ShareWrapper ShareWrapper::Convert<MOTION::MPCProtocol::BooleanGMW>() const;
template ShareWrapper ShareWrapper::Convert<MOTION::MPCProtocol::BMR>() const;

ShareWrapper ShareWrapper::ArithmeticGMWToBMR() const {
  const auto bitlen{share_->GetBitLength()};
  auto wire{share_->GetWires().at(0)};
  auto &backend = share_->GetBackend();
  std::vector<ENCRYPTO::BitVector<>> my_input;
  switch (bitlen) {
    case 8u: {
      auto agmw_wire{std::dynamic_pointer_cast<Wires::ArithmeticWire<std::uint8_t>>(wire)};
      assert(agmw_wire);
      my_input = ENCRYPTO::ToInput(agmw_wire->GetValues());
      break;
    }
    case 16u: {
      auto agmw_wire{std::dynamic_pointer_cast<Wires::ArithmeticWire<std::uint16_t>>(wire)};
      assert(agmw_wire);
      my_input = ENCRYPTO::ToInput(agmw_wire->GetValues());
      break;
    }
    case 32u: {
      auto agmw_wire{std::dynamic_pointer_cast<Wires::ArithmeticWire<std::uint32_t>>(wire)};
      assert(agmw_wire);
      my_input = ENCRYPTO::ToInput(agmw_wire->GetValues());
      break;
    }
    case 64u: {
      auto agmw_wire{std::dynamic_pointer_cast<Wires::ArithmeticWire<std::uint64_t>>(wire)};
      assert(agmw_wire);
      my_input = ENCRYPTO::ToInput(agmw_wire->GetValues());
      break;
    }
    default:
      throw std::runtime_error(fmt::format("Invalid bitlength {}", bitlen));
  }
  std::vector<ENCRYPTO::BitVector<>> dummy_input(my_input.size(),
                                                 ENCRYPTO::BitVector<>(my_input.at(0).GetSize()));

  std::vector<SecureUnsignedInteger> shares;
  for (auto party_id = 0ull; party_id < backend.GetConfig()->GetNumOfParties(); ++party_id) {
    if (party_id == backend.GetConfig()->GetMyId())
      shares.emplace_back(backend.BMRInput(party_id, my_input));
    else
      shares.emplace_back(backend.BMRInput(party_id, dummy_input));
  }

  auto result{shares.at(0)};
  for (auto share_i = 0ull; share_i < shares.size(); ++share_i) result += shares.at(share_i);

  return result.Get();
}

ShareWrapper ShareWrapper::BooleanGMWToArithmeticGMW() const {
  const auto bitlen = share_->GetBitLength();
  switch (bitlen) {
    case 8u: {
      auto bgmw_to_agmw_gate =
          std::make_shared<Gates::Conversions::GMWToArithmeticGate<std::uint8_t>>(share_);
      share_->GetRegister()->RegisterNextGate(bgmw_to_agmw_gate);
      return ShareWrapper(bgmw_to_agmw_gate->GetOutputAsShare());
    }
    case 16u: {
      auto bgmw_to_agmw_gate{
          std::make_shared<Gates::Conversions::GMWToArithmeticGate<std::uint16_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(bgmw_to_agmw_gate);
      return ShareWrapper(bgmw_to_agmw_gate->GetOutputAsShare());
    }
    case 32u: {
      auto bgmw_to_agmw_gate{
          std::make_shared<Gates::Conversions::GMWToArithmeticGate<std::uint32_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(bgmw_to_agmw_gate);
      return ShareWrapper(bgmw_to_agmw_gate->GetOutputAsShare());
    }
    case 64u: {
      auto bgmw_to_agmw_gate{
          std::make_shared<Gates::Conversions::GMWToArithmeticGate<std::uint64_t>>(share_)};
      share_->GetRegister()->RegisterNextGate(bgmw_to_agmw_gate);
      return ShareWrapper(bgmw_to_agmw_gate->GetOutputAsShare());
    }
    default:
      throw std::runtime_error(fmt::format("Invalid bitlength {}", bitlen));
  }
}

ShareWrapper ShareWrapper::BooleanGMWToBMR() const {
  auto gmw_share = std::dynamic_pointer_cast<Shares::GMWShare>(share_);
  assert(gmw_share);
  auto gmw_to_bmr_gate{std::make_shared<Gates::Conversion::GMWToBMRGate>(gmw_share)};
  share_->GetRegister()->RegisterNextGate(gmw_to_bmr_gate);
  return ShareWrapper(gmw_to_bmr_gate->GetOutputAsShare());
}

ShareWrapper ShareWrapper::BMRToBooleanGMW() const {
  auto bmr_share = std::dynamic_pointer_cast<Shares::BMRShare>(share_);
  assert(bmr_share);
  auto bmr_to_gmw_gate = std::make_shared<Gates::Conversion::BMRToGMWGate>(bmr_share);
  share_->GetRegister()->RegisterNextGate(bmr_to_gmw_gate);
  return ShareWrapper(bmr_to_gmw_gate->GetOutputAsShare());
}

const SharePtr ShareWrapper::Out(std::size_t output_owner) const {
  assert(share_);
  auto &backend = share_->GetBackend();
  switch (share_->GetProtocol()) {
    case MPCProtocol::ArithmeticGMW: {
      switch (share_->GetBitLength()) {
        case 8u: {
          return backend.ArithmeticGMWOutput<std::uint8_t>(share_, output_owner);
        }
        case 16u: {
          return backend.ArithmeticGMWOutput<std::uint16_t>(share_, output_owner);
        }
        case 32u: {
          return backend.ArithmeticGMWOutput<std::uint32_t>(share_, output_owner);
        }
        case 64u: {
          return backend.ArithmeticGMWOutput<std::uint64_t>(share_, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength())));
        }
      }
    }
    case MPCProtocol::BooleanGMW: {
      return backend.BooleanGMWOutput(share_, output_owner);
    }
    case MPCProtocol::BMR: {
      return backend.BMROutput(share_, output_owner);
    }
    default: {
      throw(std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<uint>(share_->GetProtocol()))));
    }
  }
}

std::vector<ShareWrapper> ShareWrapper::Split() const {
  std::vector<ShareWrapper> result;
  result.reserve(share_->GetWires().size());
  const auto split = share_->Split();
  for (const auto &s : split) result.emplace_back(s);
  return result;
}

ShareWrapper ShareWrapper::Join(const std::vector<ShareWrapper> &v) {
  if (v.empty()) throw std::runtime_error("ShareWrapper cannot be empty");
  {
    const auto p = v.at(0)->GetProtocol();
    for (auto i = 1ull; i < v.size(); ++i) {
      if (v.at(i)->GetProtocol() != p) {
        throw std::runtime_error("Trying to join shares of different types");
      }
    }
  }
  std::vector<Shares::SharePtr> raw_v;
  raw_v.reserve(v.size());
  for (const auto &s : v) raw_v.emplace_back(*s);

  std::vector<Wires::WirePtr> wires;
  wires.reserve(v.size());
  for (const auto &s : v)
    for (const auto &w : s->GetWires()) wires.emplace_back(w);
  switch (v.at(0)->GetProtocol()) {
    case MPCProtocol::ArithmeticGMW: {
      switch (wires.at(0)->GetBitLength()) {
        case 8: {
          return ShareWrapper(std::make_shared<Shares::ArithmeticShare<std::uint8_t>>(wires));
        }
        case 16: {
          return ShareWrapper(std::make_shared<Shares::ArithmeticShare<std::uint16_t>>(wires));
        }
        case 32: {
          return ShareWrapper(std::make_shared<Shares::ArithmeticShare<std::uint32_t>>(wires));
        }
        case 64: {
          return ShareWrapper(std::make_shared<Shares::ArithmeticShare<std::uint64_t>>(wires));
        }
        default:
          throw std::runtime_error(fmt::format(
              "Incorrect bit length of arithmetic shares: {}, allowed are 8, 16, 32, 64",
              wires.at(0)->GetBitLength()));
      }
    }
    case MPCProtocol::BooleanGMW: {
      return ShareWrapper(std::make_shared<Shares::GMWShare>(wires));
    }
    case MPCProtocol::BMR: {
      return ShareWrapper(std::make_shared<Shares::BMRShare>(wires));
    }
    default: {
      throw std::runtime_error("Unknown MPC protocol");
    }
  }
}

ShareWrapper ShareWrapper::Evaluate(const ENCRYPTO::AlgorithmDescription &algo) const {
  std::size_t n_input_wires = algo.n_input_wires_parent_a_;
  if (algo.n_input_wires_parent_b_) n_input_wires += *algo.n_input_wires_parent_b_;

  if (n_input_wires != share_->GetBitLength()) {
    share_->GetRegister()->GetLogger()->LogError(fmt::format(
        "ShareWrapper::Evaluate: expected a share of bit length {}, got a share of bit length {}",
        n_input_wires, share_->GetBitLength()));
  }

  auto wires_tmp{Split()};
  std::vector<std::shared_ptr<ShareWrapper>> wires;
  for (const auto &w : wires_tmp) wires.emplace_back(std::make_shared<ShareWrapper>(w.Get()));

  wires.resize(algo.n_wires_, nullptr);

  assert((algo.n_gates_ + n_input_wires) == wires.size());

  for (std::size_t wire_i = n_input_wires, gate_i = 0; wire_i < algo.n_wires_; ++wire_i, ++gate_i) {
    const auto &gate = algo.gates_.at(gate_i);
    const auto type = gate.type_;
    switch (type) {
      case ENCRYPTO::PrimitiveOperationType::XOR: {
        assert(gate.parent_b_);
        wires.at(gate.output_wire_) = std::make_shared<Shares::ShareWrapper>(
            *wires.at(gate.parent_a_) ^ *wires.at(*gate.parent_b_));
        break;
      }
      case ENCRYPTO::PrimitiveOperationType::AND: {
        assert(gate.parent_b_);
        wires.at(gate.output_wire_) = std::make_shared<Shares::ShareWrapper>(
            *wires.at(gate.parent_a_) & *wires.at(*gate.parent_b_));
        break;
      }
      case ENCRYPTO::PrimitiveOperationType::OR: {
        assert(gate.parent_b_);
        wires.at(gate.output_wire_) = std::make_shared<Shares::ShareWrapper>(
            *wires.at(gate.parent_a_) | *wires.at(*gate.parent_b_));
        break;
      }
      case ENCRYPTO::PrimitiveOperationType::INV: {
        wires.at(gate.output_wire_) =
            std::make_shared<Shares::ShareWrapper>(~*wires.at(gate.parent_a_));
        break;
      }
      default:
        throw std::runtime_error("Invalid PrimitiveOperationType");
    }
  }

  std::vector<ShareWrapper> out;
  for (auto i = wires.size() - algo.n_output_wires_; i < wires.size(); i++) {
    out.emplace_back(*wires.at(i));
  }

  return ShareWrapper::Join(out);
}

template <typename T>
ShareWrapper ShareWrapper::Add(SharePtr share, SharePtr other) const {
  auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto other_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(other);
  assert(other_a);
  auto other_wire_a = other_a->GetArithmeticWire();

  auto addition_gate =
      std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(this_wire_a, other_wire_a);
  auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
  share_->GetRegister()->RegisterNextGate(addition_gate_cast);
  auto res = std::static_pointer_cast<Shares::Share>(addition_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(res);
}

template ShareWrapper ShareWrapper::Add<std::uint8_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Add<std::uint16_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Add<std::uint32_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Add<std::uint64_t>(SharePtr share, SharePtr other) const;

template <typename T>
ShareWrapper ShareWrapper::Sub(SharePtr share, SharePtr other) const {
  auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto other_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(other);
  assert(other_a);
  auto other_wire_a = other_a->GetArithmeticWire();

  auto subtraction_gate =
      std::make_shared<Gates::Arithmetic::ArithmeticSubtractionGate<T>>(this_wire_a, other_wire_a);
  auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(subtraction_gate);
  share_->GetRegister()->RegisterNextGate(addition_gate_cast);
  auto res =
      std::static_pointer_cast<Shares::Share>(subtraction_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(res);
}

template ShareWrapper ShareWrapper::Sub<std::uint8_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Sub<std::uint16_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Sub<std::uint32_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Sub<std::uint64_t>(SharePtr share, SharePtr other) const;

template <typename T>
ShareWrapper ShareWrapper::Mul(SharePtr share, SharePtr other) const {
  auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto other_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(other);
  assert(other_a);
  auto other_wire_a = other_a->GetArithmeticWire();

  auto multiplication_gate = std::make_shared<Gates::Arithmetic::ArithmeticMultiplicationGate<T>>(
      this_wire_a, other_wire_a);
  auto multiplication_gate_cast =
      std::static_pointer_cast<Gates::Interfaces::Gate>(multiplication_gate);
  share_->GetRegister()->RegisterNextGate(multiplication_gate_cast);
  auto res =
      std::static_pointer_cast<Shares::Share>(multiplication_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(res);
}

template <typename T>
ShareWrapper ShareWrapper::Square(SharePtr share) const {
  auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
  assert(this_a);
  auto this_wire_a = this_a->GetArithmeticWire();

  auto square_gate = std::make_shared<Gates::Arithmetic::ArithmeticSquareGate<T>>(this_wire_a);
  auto square_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(square_gate);
  share_->GetRegister()->RegisterNextGate(square_gate_cast);
  auto res = std::static_pointer_cast<Shares::Share>(square_gate->GetOutputAsArithmeticShare());

  return ShareWrapper(res);
}

template ShareWrapper ShareWrapper::Mul<std::uint8_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Mul<std::uint16_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Mul<std::uint32_t>(SharePtr share, SharePtr other) const;
template ShareWrapper ShareWrapper::Mul<std::uint64_t>(SharePtr share, SharePtr other) const;

}  // namespace MOTION::Shares
