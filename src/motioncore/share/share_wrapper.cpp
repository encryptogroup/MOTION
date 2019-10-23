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
#include "arithmetic_gmw_share.h"
#include "base/backend.h"
#include "bmr_share.h"
#include "boolean_gmw_share.h"
#include "gate/bmr_gate.h"

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

const SharePtr ShareWrapper::Out(std::size_t output_owner) {
  assert(share_);
  auto backend = share_->GetBackend().lock();
  assert(backend);
  switch (share_->GetProtocol()) {
    case MPCProtocol::ArithmeticGMW: {
      switch (share_->GetBitLength()) {
        case 8u: {
          return backend->ArithmeticGMWOutput<std::uint8_t>(share_, output_owner);
        }
        case 16u: {
          return backend->ArithmeticGMWOutput<std::uint16_t>(share_, output_owner);
        }
        case 32u: {
          return backend->ArithmeticGMWOutput<std::uint32_t>(share_, output_owner);
        }
        case 64u: {
          return backend->ArithmeticGMWOutput<std::uint64_t>(share_, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength())));
        }
      }
    }
    case MPCProtocol::BooleanGMW: {
      return backend->BooleanGMWOutput(share_, output_owner);
    }
    case MPCProtocol::BMR: {
      return backend->BMROutput(share_, output_owner);
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

ShareWrapper ShareWrapper::Evaluate(
    const std::shared_ptr<const ENCRYPTO::AlgorithmDescription> &algo) const {
  std::size_t n_input_wires = algo->n_input_wires_parent_a_;
  if (algo->n_input_wires_parent_b_) n_input_wires += *algo->n_input_wires_parent_b_;

  if (n_input_wires != share_->GetBitLength()) {
    share_->GetRegister()->GetLogger()->LogError(fmt::format(
        "ShareWrapper::Evaluate: expected a share of bit length {}, got a share of bit length {}",
        n_input_wires, share_->GetBitLength()));
  }

  auto wires_tmp{Split()};
  std::vector<std::shared_ptr<ShareWrapper>> wires;
  for (const auto &w : wires_tmp) wires.emplace_back(std::make_shared<ShareWrapper>(w.Get()));

  wires.resize(algo->n_wires_, nullptr);

  assert((algo->n_gates_ + algo->n_output_wires_ + n_input_wires) == wires.size());

  for (std::size_t wire_i = n_input_wires, gate_i = 0; wire_i < algo->n_wires_; ++wire_i) {
    const auto &gate = algo->gates_.at(gate_i);
    const auto type = gate.type_;
    switch (type) {
      case ENCRYPTO::PrimitiveOperationType::XOR: {
        assert(gate.parent_b_);
        *wires.at(gate.output_wire_) = *wires.at(gate.parent_a_) ^ *wires.at(*gate.parent_b_);
        break;
      }
      case ENCRYPTO::PrimitiveOperationType::AND: {
        assert(gate.parent_b_);
        *wires.at(gate.output_wire_) = *wires.at(gate.parent_a_) & *wires.at(*gate.parent_b_);
        break;
      }
      case ENCRYPTO::PrimitiveOperationType::INV: {
        *wires.at(gate.output_wire_) = ~*wires.at(gate.parent_a_);
        break;
      }
      default:
        throw std::runtime_error("Invalid PrimitiveOperationType");
    }
  }

  std::vector<ShareWrapper> out;
  for (auto i = n_input_wires + algo->n_gates_; i < wires.size(); i++) {
    out.emplace_back(*wires.at(i));
  }

  return ShareWrapper::Join(out);
}
}